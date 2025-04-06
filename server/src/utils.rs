use crate::errors::ServerError;
use common::{GetPreKeyBundleRequest, RegisterRequest, RequestWrapper, ResponseCode, ResponseWrapper, SendMessageRequest, ServerResponse, CONFIG};
use log::{debug, error, info};
use protocol::utils::{DecryptionKey, PreKeyBundle, PrivateKey, SessionKeys};
use std::collections::HashMap;
use std::sync::Arc;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};

use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};
use tokio_tungstenite::{accept_async, WebSocketStream};
use protocol::x3dh::process_prekey_bundle;

pub(crate) type Tx = mpsc::UnboundedSender<Message>;
pub(crate) type Rx = mpsc::UnboundedReceiver<Message>;
pub(crate) type PeerMap = Arc<RwLock<HashMap<String, Peer>>>;

pub(crate) type Session = Arc<RwLock<SessionKeys>>;

type SharedSink = Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>;

#[derive(Debug, Clone)]
pub(crate) struct Peer {
    pub(crate) sender: Tx,
    pub(crate) pb: PreKeyBundle,
}

impl Peer {
    pub(crate) fn new(sender: Tx, pb: PreKeyBundle) -> Self {
        Self { sender, pb }
    }

    pub(crate) fn get_bundle(&mut self) -> PreKeyBundle {
        let mut old_bundle = self.pb.clone();

        // We need at least one key in 'otpk' to split
        let last_key = old_bundle.otpk.pop();

        // Build a new PreKeyBundle that just contains the last key in its 'otpk'
        let new_bundle_with_last = PreKeyBundle {
            verifying_key: old_bundle.verifying_key.clone(),
            ik: old_bundle.ik.clone(),
            spk: old_bundle.spk.clone(),
            sig: old_bundle.sig.clone(),
            otpk: if last_key.is_some() {
                vec![last_key.unwrap()]
            } else {
                vec![]
            },
        };

        // Now update the *peer's* bundle (remove last key from its 'otpk').
        // old_bundle no longer has the last key, because we popped it above.
        self.pb = old_bundle;
        new_bundle_with_last
    }
}

pub(crate) struct Server {
    pub(crate) addr: String,
    pub(crate) port: String,
    pub(crate) peers: PeerMap,
    pub(crate) connections: Vec<JoinHandle<()>>,
}

impl Server {
    pub(crate) fn new(addr: String, port: String) -> Self {
        Self {
            addr,
            port,
            peers: Arc::new(RwLock::new(HashMap::new())),
            connections: Vec::new(),
        }
    }

    pub(crate) async fn listen(&mut self) {
        let listener = TcpListener::bind(format!("{}:{}", &self.addr, &self.port)).await.unwrap();
        while let Ok((stream, _)) = listener.accept().await {
            let peers = self.peers.clone();
            let addr = match stream.peer_addr() {
                Ok(addr) => addr.to_string(),
                Err(_) => "Unknown".to_string(),
            };

            info!("Incoming WebSocket connection: {}", &addr);

            let ws_stream = match accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    error!("Websocket handshake failed with {}: {}", addr, e);
                    return;
                }
            };
            let mut new_connection = Connection::new(
                peers,
                addr
            );

            self.connections.push(tokio::spawn(async move {
                        new_connection.run(ws_stream).await;
                    }
                )
            );
        }
    }





}

pub(crate) struct Receiver{
    session: Session,
    peers: PeerMap,
    reader: SplitStream<WebSocketStream<TcpStream>>,
    writer: SharedSink,
    tx: Tx,
    user: Option<String>,
}

impl Receiver {


    async fn receive(&mut self){
        while let Some(Ok(msg_result)) = StreamExt::next(&mut self.reader).await {
            match msg_result {
                Message::Text(msg) => {
                    debug!("Received message: {}", msg);
                    let dk = self.session.read().await.get_decryption_key();
                    if dk.is_some() {
                        let dk = dk.unwrap();
                        match decrypt_client_request(&msg.to_string(), &dk) {
                            Ok((request, id)) => {
                                match request {
                                    RequestType::Register(register_request) => {
                                        match self.handle_registration(register_request, id).await {
                                            Ok(_) => {
                                                debug!("Registration successful");
                                            }
                                            Err(e) => {
                                                error!("Failed to register: {}", e);
                                            }
                                        }
                                    }
                                    RequestType::SendMessage(send_message_request) => {
                                        match self.handle_send_message(send_message_request, id).await {
                                            Ok(_) => {
                                                debug!("Message sent successfully");
                                            }
                                            Err(e) => {
                                                error!("Failed to send message: {}", e);
                                            }
                                        }
                                    }
                                    RequestType::GetPrekeyBundle(request) => {
                                        // Handle prekey bundle request
                                        match self.handle_get_prekey_bundle(request, id).await {
                                            Ok(_) => {
                                                debug!("Prekey bundle sent successfully");
                                            }
                                            Err(e) => {
                                                error!("Failed to send prekey bundle: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to decrypt request: {}", e);
                            }
                        }
                    } else {
                        if let Ok(request) = serde_json::from_str::<EstablishConnectionRequest>(&msg.to_string()){
                            if request.request_type == "establish_connection" {
                                if let Err(e) = self.handle_establish_connection(request).await {
                                    error!("Failed to establish connection: {}", e);
                                }
                            } else {
                                error!("Invalid request type");
                            }
                        } else {
                            error!("Failed to parse request");
                        }
                    }
                }
                Message::Binary(_) => {}
                Message::Ping(_) => {}
                Message::Pong(_) => {}
                Message::Close(_) => {}
                Message::Frame(_) => {}
            }
        }
    }

    async fn handle_establish_connection(
        &mut self,
        request: EstablishConnectionRequest,
    ) -> Result<(), ServerError> {
        if let Ok(bundle) = PreKeyBundle::try_from(request.bundle) {
            debug!("Key bundle parsed correctly");
            match process_prekey_bundle(PrivateKey::from_base64(CONFIG.get_private_key_server())?, bundle) {
                Ok((im, ek, dk)) => {
                    debug!("Key bundle processed successfully");
                    self.session.write().await.set_encryption_key(ek);
                    self.session.write().await.set_decryption_key(dk);
                    self.session.write().await.set_associated_data(im.get_associated_data());

                    let response = ServerResponse::new(ResponseCode::Ok, im.to_base64());
                    self.send_response(response, None).await?;
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to process prekey bundle: {}", e);
                    self.send_response(
                        ServerResponse::new(
                            ResponseCode::BadRequest,
                            "Failed to process prekey bundle".to_string()
                        ),
                        None
                    ).await?;
                    return Err(ServerError::InvalidRequest);
                }
            }
        } else {
            error!("Failed to parse prekey bundle");
            self.send_response(
                ServerResponse::new(
                    ResponseCode::BadRequest,
                    "Failed to parse prekey bundle".to_string()
                ),
                None
            ).await?;
            return Err(ServerError::InvalidRequest);
        }
    }

    async fn send_response(&self, response: ServerResponse, id: Option<String>)-> Result<(), ServerError> {
        debug!("response: {}", response.to_string());
        if let Some(req_id) = id {
            if let Some(ek) = self.session.read().await.get_encryption_key() {
                let aad = self.session.read().await.get_associated_data().unwrap();
                let response = ResponseWrapper {
                    request_id: req_id,
                    body: serde_json::from_str(&response.to_string()).unwrap(),
                };
                let response = serde_json::to_string(&response).unwrap();
                return match ek.encrypt(&response.as_bytes(), &aad) {
                    Ok(enc) => {
                        self.writer.lock().await.send(Message::Text(Utf8Bytes::from(enc))).await?;
                        Ok(())
                    }
                    Err(e) => {
                        error!("Failed to encrypt response: {}", e);
                        Err(ServerError::X3DHError(e))
                    }
                }
            }
        }
        self.writer.lock().await.send(Message::Text(Utf8Bytes::from(response.to_string()))).await?;
        Ok(())
    }

    async fn handle_registration(
        &mut self,
        request: RegisterRequest,
        id: String,
    ) -> Result<(), ServerError> {
        let is_alphanumeric = !request.username.is_empty() &&
            request.username.chars().all(char::is_alphanumeric);
        if is_alphanumeric && !self.peers.read().await.contains_key(&request.username) {
            if let Ok(bundle) = PreKeyBundle::try_from(request.bundle) {
                debug!("Key bundle parsed correctly");
                let peer = Peer::new(self.tx.clone(), bundle);
                let username = request.username.clone();
                self.peers.write().await.insert(request.username, peer);
                let response = ServerResponse::new(ResponseCode::Ok, "User registered successfully!".to_string());
                self.send_response(response, Some(id)).await?;
                self.user = Some(username.clone());
                Ok(())
            } else {
                error!("Failed to parse prekey bundle");
                self.send_response(
                    ServerResponse::new(
                        ResponseCode::BadRequest,
                        "Failed to parse prekey bundle".to_string()
                    ),
                    None
                ).await?;
                Err(ServerError::InvalidRequest)
            }
        } else if is_alphanumeric {
            let response = ServerResponse::new(ResponseCode::Conflict, "Username already exists".to_string());
            self.send_response(response, Some(id)).await?;
            Err(ServerError::InvalidRequest)
        }
        else {
            let response = ServerResponse::new(ResponseCode::BadRequest, "Invalid username".to_string());
            self.send_response(response, Some(id)).await?;
            Err(ServerError::InvalidRequest)
        }
    }

    async fn handle_send_message(
        &mut self,
        request: SendMessageRequest,
        id: String,
    ) -> Result<(), ServerError> {
        match self.peers.read().await.get(&request.to) {
            Some(peer) => {
                let serialized = serde_json::to_string(&request).unwrap();
                peer.sender.send(Message::Text(Utf8Bytes::from(serialized))).map_err(|_| {
                    error!("Failed to send message to peer");
                    ServerError::SendError("Failed to send message to peer".to_string())
                })?;
                Ok(())
            }
            None => {
                debug!("Peer not found: {}", request.to);
                debug!("User {} not found", request.to);
                self.send_response(
                    ServerResponse::new(
                        ResponseCode::NotFound,
                        "User not found".to_string()
                    ),
                    Some(id)
                ).await?;

                return Err(ServerError::UserNotFoundError);
            }
        }
    }

    async fn handle_get_prekey_bundle(
        &mut self,
        request: GetPreKeyBundleRequest,
        id: String,
    ) -> Result<(), ServerError> {
        if self.user != Some(request.who.clone()) {
            match self.peers.write().await.get_mut(&request.who) {
                Some(peer) => {
                    let bundle = peer.get_bundle();
                    let response = ServerResponse::new(ResponseCode::Ok, bundle.to_base64());
                    self.send_response(response, Some(id)).await?;
                    Ok(())
                }
                None => {
                    debug!("User {} not found", request.who);
                    self.send_response(
                        ServerResponse::new(
                            ResponseCode::NotFound,
                            "User not found".to_string()
                        ),
                        Some(id)
                    ).await?;
                    return Err(ServerError::UserNotFoundError);
                }
            }
        } else {
            debug!("User {} is asking for its own bundle", request.who);
            self.send_response(
                ServerResponse::new(
                    ResponseCode::BadRequest,
                    "User cannot ask for its own bundle".to_string()
                ),
                Some(id)
            ).await?;
            Err(ServerError::InvalidRequest)
        }

    }


}

pub(crate) struct Sender {
    session: Session,
    peers: PeerMap,
    rx: Rx,
    writer: SharedSink
}
impl Sender {
    async fn send(mut self) {
        loop {
            if let Some(msg_result) = self.rx.recv().await {
                if let Some(ek) = self.session.read().await.get_encryption_key() {
                    let aad = self.session.read().await.get_associated_data().unwrap();
                    match ek.encrypt(&msg_result.to_string().into_bytes(), &aad) {
                        Ok(enc) => {
                            if self.writer.lock().await.send(Message::Text(Utf8Bytes::from(enc))).await.is_err() {
                                error!("Failed to send message.");
                            } else {
                                debug!("Message sent: {}", msg_result.to_string());
                            }
                        },
                        _ => {}
                    }
                } else {
                    debug!("Session encryption key not found");
                }
            }
        }
    }
}

pub(crate) struct Connection {
    pub(crate) session: Session,
    pub(crate) peers: PeerMap,
    pub(crate) addr: String,

}

impl Connection {
    pub(crate) fn new(
        peers: PeerMap,
        addr: String,

    ) -> Self {

        let session =  Arc::new(RwLock::new(SessionKeys::new()));
        Self {
            session,
            peers: peers.clone() ,
            addr
        }
    }

    async fn run(&mut self, stream: WebSocketStream<TcpStream>,) {
        let (tx, rx) = mpsc::unbounded_channel::<Message>();
        let (writer, reader) = stream.split();
        let writer = Arc::new(Mutex::new(writer));
        let sender = Sender {
            session: self.session.clone(),
            peers: self.peers.clone(),
            rx,
            writer: writer.clone()
        };

        let mut receiver =  Receiver {
            session: self.session.clone(),
            peers: self.peers.clone(),
            tx,
            writer: writer.clone(),
            reader,
            user: None,
        };

        let task_receive = tokio::spawn(async move {
            receiver.receive().await;
        });

        let task_send = tokio::spawn(async move {
            sender.send().await;
        });

        tokio::select! {
            _ = task_receive => (),
            _ = task_send => (),
        }
    }

}



#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EstablishConnectionRequest{
    request_type: String,
    bundle: String,
}


pub(crate) fn decrypt_client_request(
    req: &str,
    dk: &DecryptionKey,
) -> Result<(RequestType, String), ServerError> {
    let decrypted = match common::decrypt_request(req, dk) {
        Ok((dec, _ )) => dec,
        Err(_) => return Err(ServerError::InvalidRequest),
    };
    if let Ok(message) = serde_json::from_str::<SendMessageRequest>(&decrypted.to_string()) {
        Ok((RequestType::SendMessage(message), "".to_string()))
    } else if let Ok(req) = serde_json::from_str::<RequestWrapper>(&decrypted.to_string()) {
        let id = req.request_id;
        let body = req.body;
        debug!("Decrypted request: {}", body.to_string());
        if let Ok(registration) = serde_json::from_str::<RegisterRequest>(&body.to_string()) {
            Ok((RequestType::Register(registration), id))
        }  else if let Ok(who) = serde_json::from_str::<GetPreKeyBundleRequest>(&body.to_string()) {
            Ok((RequestType::GetPrekeyBundle(who), id))
        } else {
            Err(ServerError::InvalidRequest)
        }
    } else  {
        error!("Failed to decrypt request");
        Err(ServerError::InvalidRequest)
    }
}

pub(crate) enum RequestType {
    Register(RegisterRequest),
    SendMessage(SendMessageRequest),
    GetPrekeyBundle(GetPreKeyBundleRequest),
}
