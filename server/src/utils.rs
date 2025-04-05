use crate::errors::ServerError;
use common::{RegisterRequest, RequestWrapper, ResponseCode, SendMessageRequest, ServerResponse, CONFIG};
use log::{debug, error, info};
use protocol::utils::{DecryptionKey, EncryptionKey, InitialMessage, PreKeyBundle, PrivateKey, SessionKeys};
use std::collections::HashMap;
use std::sync::Arc;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, Mutex, RwLock};

use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};
use tokio_tungstenite::{accept_async, WebSocketStream};
use protocol::errors::X3DHError;
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
        let listener = TcpListener::bind(format!("{}:{}", self.addr, self.port)).await.unwrap();
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
            let new_connection = Connection::new(
                peers,
                addr,
                ws_stream
            );

            self.connections.push(tokio::spawn(self.handle_connection(new_connection)));
        }
    }

    pub(crate) async fn handle_connection(&mut self, mut connection: Connection) {
        let (tx, rx) = mpsc::unbounded_channel();
        connection.sender.set_rx(rx);
        connection.receiver.set_tx(tx);
        let task_receive = tokio::task::spawn(connection.receiver.receive());
        let task_send =  tokio::task::spawn(connection.sender.send());
        tokio::select! {
            _ = task_receive => (),
            _ = task_send => (),
        }
    }

}

pub(crate) struct Receiver{
    session: Session,
    peers: PeerMap,
    reader: SplitStream<WebSocketStream<TcpStream>>,
    writer: SharedSink,
    tx: Option<Tx>
}

impl Receiver {
    fn set_tx(&mut self, tx: Tx) {
        self.tx = Some(tx);
    }

    async fn receive(&mut self){
        while let Some(Ok(msg_result)) = StreamExt::next(&mut self.reader).await {
            match msg_result {
                Message::Text(msg) => {
                    debug!("Received message: {}", msg);
                    if let Some(dk) = self.session.read().await.get_decryption_key() {
                        match decrypt_client_request(&msg.to_string(), &dk) {
                            Ok((action, id)) => {
                                match action {
                                    Action::Register(request) => {
                                        if let Err(e) = self.handle_register(request).await {
                                            error!("Failed to register: {}", e);
                                        }
                                    }
                                    Action::SendMessage(request) => {
                                        if let Err(e) = self.handle_send_message(request).await {
                                            error!("Failed to send message: {}", e);
                                        }
                                    }
                                    Action::GetPrekeyBundle(user) => {
                                        if let Err(e) = self.handle_get_prekey_bundle(user).await {
                                            error!("Failed to get prekey bundle: {}", e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to decrypt request: {}", e);
                            }
                        }
                    } else {
                        if let Some(request) = serde_json::from_str::<EstablishConnectionRequest>(&msg.to_string()){
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
            match process_prekey_bundle(PrivateKey::from_base64(CONFIG.get_private_key_server())?, bundle)? {
                Ok((im, ek, dk)) => {
                    debug!("Key bundle processed successfully");
                    self.session = SessionKeys::new_with_keys(ek, dk, Some(im.associated_data.clone()));
                    let response = ServerResponse::new(ResponseCode::Ok, im.to_base64()).to_string();
                    self.send_response(response).await?;
                }
                Err(e) => {
                    error!("Failed to process prekey bundle: {}", e);
                    self.send_response(ServerResponse::new(ResponseCode::BadRequest, "Failed to process prekey bundle".to_string())).await?;
                    return Err(ServerError::InvalidRequest);
                }
            }
        } else {
            error!("Failed to parse prekey bundle");
            self.send_response(ServerResponse::new(ResponseCode::BadRequest, "Failed to parse prekey bundle".to_string())).await?;
            return Err(ServerError::InvalidRequest);
        }
    }

    async fn send_response(&mut self, response: ServerResponse)-> anyhow::Result<()>{
        self.writer.lock().await.send(Message::Text(Utf8Bytes::from(response.to_string()))).await?;
        Ok(())
    }

}

pub(crate) struct Sender {
    session: Session,
    peers: PeerMap,
    rx: Option<Rx>,
    writer: SharedSink
}

impl Sender {
    fn set_rx(&mut self, rx: Rx) {
        self.rx = Some(rx);
    }

    async fn send(mut self) {
        if let Some(mut rx) = self.rx.take() {
            loop {
                if let Some(msg_result) = rx.recv().await {
                    if let Some(ek) = self.session.read().await.get_encryption_key() {
                        let aad = self.session.read().await.get_associated_data().unwrap();
                        let nonce = self.session.write().await.get_nonce();
                        match ek.encrypt(nonce, &msg_result.to_string().into_bytes(), &aad) {
                            Ok(enc) => {
                                if self.writer.lock().await.send(Message::Text(Utf8Bytes::from(enc))).await.is_err() {
                                    error!("Failed to send message.");
                                } else {
                                    debug!("Message sent: {}", msg_result.to_string());
                                }
                            },
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

pub(crate) struct Connection {
    pub(crate) session: Session,
    pub(crate) peers: PeerMap,
    pub(crate) addr: String,
    pub(crate) sender: Sender,
    pub(crate) receiver: Receiver,
}

impl Connection {
    pub(crate) fn new(
        peers: PeerMap,
        addr: String,
        mut stream: WebSocketStream<TcpStream>,
    ) -> Self {

        let (writer, reader) = stream.split();
        let writer = Arc::new(Mutex::new(writer));
        let session =  Arc::new(RwLock::new(SessionKeys::new()));
        Self {
            session: session.clone(),
            peers: peers.clone() ,
            addr,
            sender: Sender {
                session: session.clone(),
                peers: peers.clone(),
                rx: None,
                writer: writer.clone()
            },

            receiver: Receiver {
                session: session.clone(),
                peers: peers.clone(),
                tx: None,
                writer: writer.clone(),
                reader,
            },
        }
    }

}



#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EstablishConnectionRequest<'a> {
    request_type: &'a str,
    bundle: &'a str,
}


pub(crate) fn decrypt_client_request(
    req: &str,
    dk: &DecryptionKey,
) -> Result<(Action, String), ServerError> {
    let decrypted = match common::decrypt_request(req, dk) {
        Ok((dec, _ )) => dec,
        Err(_) => return Err(ServerError::InvalidRequest),
    };


    if let Ok(req) = serde_json::from_str::<RequestWrapper>(&decrypted.to_string()) {
        let id = req.request_id;
        let body = req.body;
        match Action::from_json(&body) {
            Some(action) => Ok((action, id.to_string())),
            None => {
                error!("Failed to parse request");
                Err(ServerError::InvalidRequest)
            }
        }
    } else  {
        match Action::from_json(&decrypted) {
            None => Err(ServerError::InvalidRequest),
            Some(action) => {
                Ok((action, String::new()))
            }
        }
    }


}

pub(crate) enum Action {
    Register(RegisterRequest),
    SendMessage(SendMessageRequest),
    GetPrekeyBundle(String),
}

impl Action {
    pub(crate) fn from_json(request: &serde_json::Value) -> Option<Self> {
        let action = request.get("action")?.as_str()?;
        match action {
            "register" => Some(Self::Register(RegisterRequest {
                username: request.get("username")?.as_str()?.to_string(),
                bundle: request.get("bundle")?.as_str()?.to_string(),
            })),

            "send_message" => {
                let timestamp = request
                    .get("timestamp")?
                    .as_str()?
                    .to_string();
                Some(Self::SendMessage(SendMessageRequest {
                    msg_type: request.get("msg_type")?.as_str()?.to_string(),
                    from: request.get("from")?.as_str()?.to_string(),
                    to: request.get("to")?.as_str()?.to_string(),
                    text: request.get("text")?.as_str()?.to_string(),
                    timestamp,
                }))
            }
            "get_prekey_bundle" => {
                let user = request.get("who")?.as_str()?.to_string();
                Some(Self::GetPrekeyBundle(user))
            }

            _ => None,
        }
    }
}
