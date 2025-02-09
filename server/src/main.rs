mod utils;

mod errors;
mod tests;

use std::clone::Clone;
use crate::utils::{Peer, PeerMap};
use common::{CONFIG, RegisterRequest, ResponseCode, ServerResponse};
use futures::stream::SplitSink;
use futures_util::stream::SplitStream;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use protocol::utils::{AssociatedData, EncryptionKey, PreKeyBundle, PrivateKey, SessionKeys};
use protocol::x3dh::process_prekey_bundle;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use tokio::io::join;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Utf8Bytes;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use utils::{decrypt_client_request, Action, EstablishConnection, Tx};

type SharedSink = Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>;
type SharedSession = Arc<RwLock<SessionKeys>>;

#[tokio::main]
async fn main() {


    env::set_var("RUST_LOG", CONFIG.get_log_level());
    env_logger::init();

    let peers: PeerMap = Arc::new(RwLock::new(HashMap::new()));
    let addr = format!("{}:{}", CONFIG.get_server_ip(), CONFIG.get_server_port());

    let listener = TcpListener::bind(&addr).await.unwrap();
    info!("WebSocket server started listening on port {}", CONFIG.get_server_port());

    let mut connections = vec![];

    while let Ok((stream, _)) = listener.accept().await {
        let peers = peers.clone();
        connections.push(tokio::spawn(handle_connection(stream, peers)));
    }

    // Handle the results of each thread
    for (i, handle) in connections.into_iter().enumerate() {
        match handle.await {
            Ok(result) => warn!("Thread {} returned: {:?}", i, result),
            Err(e) => warn!("Thread {} panicked: {:?}", i, e),
        }
    }
}

async fn handle_connection(stream: TcpStream, peers: PeerMap) {
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

    info!("WebSocket connection established: {}", &addr);

    let session = Arc::new(RwLock::new(SessionKeys::new()));
    let (sender, receiver) = ws_stream.split();
    let (tx, rx) = mpsc::unbounded_channel();
    let sender = Arc::new(Mutex::new(sender));
    let task_receiver = tokio::spawn(task_receiver(
        sender.clone(),
        receiver,
        tx,
        peers.clone(),
        addr.to_string(),
        session.clone(),
    ));

    let task_sender = tokio::spawn(task_sender(session.clone(), sender.clone(), rx));

    tokio::select! {
        _ = task_receiver => (),
        _ = task_sender => (),
    }
}

async fn send_message(sink: SharedSink, msg: String) -> anyhow::Result<()> {
    let mut sink_lock = sink.lock().await;
    sink_lock.send(Message::text(Utf8Bytes::from(msg))).await?;
    Ok(())
}

fn establish_connection(bundle: String) -> Result<(String, SessionKeys), String> {
    if let Ok(bundle) = PreKeyBundle::try_from(bundle) {
        debug!("Key bundle parsed correctly");
        match process_prekey_bundle(
            PrivateKey::from_base64(CONFIG.clone().get_private_key_server()).unwrap(),
            bundle,
        ) {
            Ok((im, ek, dk)) => {
                debug!("Key bundle processed successfully");
                let session = SessionKeys::new_with_keys(ek, dk, Some(im.associated_data.clone()));
                let msg = ServerResponse::new(ResponseCode::Ok, im.to_base64()).to_string();
                Ok((msg, session))
            }
            Err(_) => {
                error!("Cannot process key bundle");
                Err(ServerResponse::new(
                    ResponseCode::BadRequest,
                    "Can't process bundle".to_string(),
                ).to_string())
            },
        }
    } else {
        error!("Cannot parse key bundle.");
        Err(ServerResponse::new(
            ResponseCode::BadRequest,
            "Prekey Bundle is malformed".to_string(),
        )
        .to_string())
    }
}

async fn handle_registration(
    request: RegisterRequest,
    peers: PeerMap,
    sender: SharedSink,
    tx: Tx,
    ek: EncryptionKey,
    aad: AssociatedData,
    request_id: String,
) -> Result<String, ()> {

    let mut response = String::new();
    let mut ret = Err(());
    let is_alphanumeric = !request.username.is_empty() &&
        request.username.chars().all(char::is_alphanumeric);

    if !peers.read().await.contains_key(&request.username) && is_alphanumeric {
        match PreKeyBundle::try_from(request.bundle) {
            Ok(pb) => {
                debug!("Key bundle parsed successfully");
                let peer = Peer::new(tx, pb);
                let user = request.username.clone();
                peers.write().await.insert(request.username, peer);
                response = ServerResponse::new(
                    ResponseCode::Ok,
                    "User registered successfully.".to_string(),
                ).to_string();

                debug!("User \"{}\" registered successfully", &user);
                ret = Ok(user);

            }
            Err(_) => {

                response =
                    ServerResponse::new(ResponseCode::BadRequest, "Bad request".to_string())
                        .to_string();
                error!("Cannot parse key bundle. Registration failed.");
                ret = Err(());

            }
        }
    } else if is_alphanumeric {
        response =
            ServerResponse::new(ResponseCode::Conflict, "User already exists".to_string())
                .to_string();
        debug!("UserAlready Exist");
        ret = Err(());
    } else {
        response = ServerResponse::new(ResponseCode::BadRequest, "The username must be alphanumeric.".to_string())
            .to_string();
        debug!("Username bust be alphanumeric.");
        ret = Err(());
    }

    let wrapper = common::ResponseWrapper {
        request_id,
        body: serde_json::from_str(response.as_str()).unwrap(),
    };
    let serialized = serde_json::to_string(&wrapper)
        .map_err(|_| ())?;

    match ek.encrypt(&serialized.into_bytes(), &aad) {
        Ok(enc) => {
            send_message(sender, enc)
                .await
                .expect("Failed to send message.");

        }
        Err(_) => ret = Err(()),
    }
    ret
}

async fn task_receiver(
    sender: SharedSink,
    mut receiver: SplitStream<WebSocketStream<TcpStream>>,
    tx: Tx,
    peers: PeerMap,
    addr: String,
    session: SharedSession,
) {

    let mut user = String::new();
    while let Some(Ok(msg_result)) = StreamExt::next(&mut receiver).await {
        match msg_result {
            Message::Text(text) => {
                debug!("Received message: \"{}\", from: {}", &text, &addr);
                if session.read().await.get_decryption_key().is_none() {
                    if let Some(request) = EstablishConnection::from_json(
                        &serde_json::from_str::<Value>(text.as_str()).unwrap_or(Value::Null),
                    ) {
                        match establish_connection(request.0.to_string()) {
                            Ok((msg, s)) => {
                                session
                                    .write()
                                    .await
                                    .set_encryption_key(s.get_encryption_key().unwrap());
                                session
                                    .write()
                                    .await
                                    .set_decryption_key(s.get_decryption_key().unwrap());
                                session
                                    .write()
                                    .await
                                    .set_associated_data(s.get_associated_data().unwrap());

                                debug!("Sending confirmation message: {}, to {}", &msg, &addr);

                                send_message(sender.clone(), msg)
                                    .await
                                    .expect("Failed to send message.");

                                info!("Connection established with: {}", &addr);
                            }

                            Err(e) => {
                                send_message(sender.clone(), e)
                                    .await
                                    .expect("Failed to send message.");
                            }
                        }
                    }
                } else if let Some(dk) = session.read().await.get_decryption_key() {
                    match decrypt_client_request(&text.to_string(), &dk) {
                        Ok((action, request_id)) => {
                            match action {
                                Action::Register(register_request) => {
                                    debug!("Received registration request");
                                    if let Some(ek) = session.read().await.get_encryption_key() {
                                        let aad = session.read().await.get_associated_data().unwrap();
                                        if let Ok(u) = handle_registration(
                                            register_request,
                                            peers.clone(),
                                            sender.clone(),
                                            tx.to_owned(),
                                            ek,
                                            aad,
                                            request_id,
                                        )
                                        .await
                                        {
                                            user = u;
                                        }
                                    }
                                }
                                Action::SendMessage(send_message_request) => {
                                    debug!("Received send message request");
                                    match peers.read().await.get(&send_message_request.to) {
                                        None => {
                                            debug!("User {} not found", &send_message_request.to);
                                            if let Some(ek) =
                                                session.read().await.get_encryption_key()
                                            {
                                                let aad = session.read().await.get_associated_data().unwrap();
                                                let response = ServerResponse::new(
                                                    ResponseCode::NotFound,
                                                    "User not found".to_string(),
                                                )
                                                .to_string();
                                                let wrapper = common::ResponseWrapper {
                                                    request_id,
                                                    body: serde_json::from_str(response.as_str()).unwrap(),
                                                };
                                                let serialized = serde_json::to_string(&wrapper)
                                                    .map_err(|_| ())
                                                    .expect("Failed to serialize response");
                                                if let Ok(enc) =
                                                    ek.encrypt(serialized.as_bytes(), &aad)
                                                {
                                                    send_message(sender.clone(), enc)
                                                        .await
                                                        .expect("Failed to send message.")
                                                }
                                            }
                                        }

                                        Some(peer) => {
                                            // send message to the thread that handles the recipient
                                            // connection

                                            peer.sender
                                                .send(Message::from(send_message_request.to_json()))
                                                .expect("Failed to send message");
                                        }
                                    }
                                }
                                Action::GetPrekeyBundle(user_asked) => {
                                    debug!("Received get user prekey bundle request");
                                    if user != user_asked {

                                        handle_get_bundle_request(
                                            peers.clone(),
                                            user_asked,
                                            &session,
                                            sender.clone(),
                                            request_id,
                                            &addr,
                                        )
                                            .await;
                                    } else {
                                        let r = ServerResponse::new(
                                            ResponseCode::BadRequest,
                                            "You can't ask for your own bundle".to_string(),
                                        ).to_string();
                                        send_message(sender.clone(), r)
                                            .await
                                            .expect("Failed to send message.");
                                    }
                                }
                            }
                        }

                        Err(_e) => {
                            error!("Failed to decrypt request: {}", text.to_string())
                        }
                    }
                }
            }

            Message::Close(_) => {
                peers.write().await.remove(&user);
                info!("Connection closed with {}", &addr);
                return;
            }
            _ => {}
        }
    }
}

async fn handle_get_bundle_request(
    peers: PeerMap,
    user: String,
    session: &SharedSession,
    sender: SharedSink,
    request_id: String,
    addr: &str,
) {
    let aad = session.read().await.get_associated_data().unwrap();
    let ek = session.read().await.get_encryption_key().unwrap();
    match peers.write().await.get_mut(&user) {
        None => {
            debug!("User {} not found.", &user);
            let response = ServerResponse::new(ResponseCode::NotFound, "User not found".to_string()).to_string();
            let wrapper = common::ResponseWrapper {
                request_id,
                body: serde_json::from_str(response.as_str()).unwrap(),
            };
            let serialized = serde_json::to_string(&wrapper)
                .map_err(|_| ())
                .expect("Failed to serialize response");
            match ek.encrypt(serialized.as_bytes(), &aad) {
                Ok(enc) => {
                    send_message(sender.clone(), enc)
                        .await
                        .expect("Failed to send message.");
                }
                Err(_) => {
                    error!("Failed to encrypt response");
                }
            }
        },

        Some(peer) => {
            let bundle = peer.get_bundle();

            let response =
                ServerResponse::new(ResponseCode::Ok, bundle.to_base64()).to_string();
            let wrapper = common::ResponseWrapper {
                request_id,
                body: serde_json::from_str(response.as_str()).unwrap(),
            };
            let serialized = serde_json::to_string(&wrapper)
                .map_err(|_| ())
                .expect("Failed to serialize response");
            match ek.encrypt(serialized.as_bytes(), &aad) {
                Ok(enc) => {
                    send_message(sender.clone(), enc)
                        .await
                        .expect("Failed to send message.");
                    debug!("Sent prekey bundle of {} to {}", &user, addr);
                }
                Err(_) => {
                    error!("Failed to encrypt response");
                }
            }
        }
    }
}

async fn task_sender(
    session: SharedSession,
    sender: SharedSink,
    mut receiver: mpsc::UnboundedReceiver<Message>,
) {
    loop {
        if let Some(msg_result) = receiver.recv().await {
            if let Some(ek) = session.read().await.get_encryption_key() {
                let aad = session.read().await.get_associated_data().unwrap();
                match ek.encrypt(&msg_result.to_string().into_bytes(), &aad) {
                    Ok(enc) => {
                        send_message(sender.clone(), enc)
                            .await
                            .expect("Failed to send message.");
                        debug!("Message forwarded: {}", msg_result.to_string());
                    }
                    Err(_) => error!("Failed to encrypt: {}", msg_result.to_string()),
                }
            }
        } else {
            return;
        }
    }
}
