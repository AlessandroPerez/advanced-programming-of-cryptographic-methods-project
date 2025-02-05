mod utils;

mod errors;
mod tests;

use crate::utils::{Peer, PeerMap};
use common::{RegisterRequest, ResponseCode, ServerResponse};
use futures::stream::SplitSink;
use futures_util::stream::SplitStream;
use futures_util::{SinkExt, StreamExt};
use log::{error, info};
use protocol::utils::{AssociatedData, EncryptionKey, PreKeyBundle, PrivateKey, PublicKey, SessionKeys};
use protocol::x3dh::process_prekey_bundle;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::ops::Deref;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Utf8Bytes;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use utils::{decrypt_client_request, Action, EstablishConnection, Tx};

// Keys for testing
const PRIVATE_KEY: &str = "QPdkjPrBYWzwTq70jdeVbr4f4kdS140HeuOXi88hgPc=";


// server address
const IP: &str = "127.0.0.1";
const PORT: &str = "3333";

type SharedSink = Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>;
type SharedSession = Arc<RwLock<SessionKeys>>;

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    env_logger::init();

    let peers: PeerMap = Arc::new(RwLock::new(HashMap::new()));
    let addr = format!("{}:{}", IP, PORT);

    let listener = TcpListener::bind(&addr).await.unwrap();
    info!("WebSocket server started listening on port {}", PORT);

    while let Ok((stream, _)) = listener.accept().await {
        let peers = peers.clone();
        tokio::spawn(handle_connection(stream, peers));
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
        match process_prekey_bundle(
            PrivateKey::from_base64(PRIVATE_KEY.to_string()).unwrap(),
            bundle,
        ) {
            Ok((im, ek, dk)) => {
                let session = SessionKeys::new_with_keys(ek, dk, Some(im.associated_data.clone()));
                let msg = ServerResponse::new(ResponseCode::Ok, im.to_base64()).to_string();
                Ok((msg, session))
            }
            Err(_) => Err(ServerResponse::new(
                ResponseCode::BadRequest,
                "Can't process bundle".to_string(),
            )
            .to_string()),
        }
    } else {
        Err(ServerResponse::new(
            ResponseCode::BadRequest,
            "Prekey Bundle is malformed".to_string(),
        )
        .to_string())
    }
}

async fn handle_registration(
    mut request: RegisterRequest,
    peers: PeerMap,
    sender: SharedSink,
    tx: Tx,
    ek: EncryptionKey,
    aad: AssociatedData,
) -> Result<String, ()> {

    let mut response = String::new();
    let mut ret = Err(());
    let is_alphanumeric = !request.username.is_empty() &&
        request.username.chars().all(char::is_alphanumeric);

    if !peers.read().await.contains_key(&request.username) && is_alphanumeric {
        match PreKeyBundle::try_from(request.bundle) {
            Ok(pb) => {
                let peer = Peer::new(tx, pb);
                let user = request.username.clone();
                peers.write().await.insert(request.username, peer);
                response = ServerResponse::new(
                    ResponseCode::Ok,
                    "User registered successfully.".to_string(),
                ).to_string();

                ret = Ok(user);
            }
            Err(_) => {

                response =
                    ServerResponse::new(ResponseCode::BadRequest, "Bad request".to_string())
                        .to_string();
                error!("{}", response);
                ret = Err(());

            }
        }
    } else if is_alphanumeric {
        response =
            ServerResponse::new(ResponseCode::Conflict, "User already exists".to_string())
                .to_string();
        error!("{}", response);
        ret = Err(());
    } else {
        response = ServerResponse::new(ResponseCode::BadRequest, "The username must be alphanumeric.".to_string())
            .to_string();
        error!("{}", response);
        ret = Err(());
    }


    info!("Sending response: {}", response);
    match ek.encrypt(&response.into_bytes(), &aad) {
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
    // TODO: check if errors make the application vulnerable
    // example: Decryption Oracle attack
    let mut user = String::new();
    while let Some(Ok(msg_result)) = StreamExt::next(&mut receiver).await {
        match msg_result {
            Message::Text(text) => {
                info!("Received message: \"{}\", from: {}", &text, &addr);
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
                } else if let Some(dk) = session.read().await.get_decryption_key() {
                    match decrypt_client_request(&text.to_string(), &dk) {
                        Ok((action, aad)) => {
                            match action {
                                Action::Register(register_request) => {
                                    if let Some(ek) = session.read().await.get_encryption_key() {
                                        if let Ok(u) = handle_registration(
                                            register_request,
                                            peers.clone(),
                                            sender.clone(),
                                            tx.to_owned(),
                                            ek,
                                            aad,
                                        )
                                        .await
                                        {
                                            user = u;
                                        }
                                    }
                                }
                                Action::SendMessage(send_message_request) => {
                                    match peers.read().await.get(&send_message_request.to) {
                                        None => {
                                            if let Some(ek) =
                                                session.read().await.get_encryption_key()
                                            {
                                                let response = ServerResponse::new(
                                                    ResponseCode::NotFound,
                                                    "User not found".to_string(),
                                                )
                                                .to_string();
                                                if let Ok(enc) =
                                                    ek.encrypt(response.as_bytes(), &aad)
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
                                    if user != user_asked {
                                        handle_get_bundle_request(
                                            peers.clone(),
                                            user_asked,
                                            &session,
                                            sender.clone(),
                                            &aad,
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
                } else {
                    send_message(
                        sender.clone(),
                        ServerResponse::new(
                            ResponseCode::BadRequest,
                            "Establish a secure connection first".to_string(),
                        )
                        .to_string(),
                    )
                    .await
                    .expect("Failed to send message.");
                }
            }

            Message::Close(_) => {
                peers.write().await.remove(&user);
                info!("Connection closed with {}", &addr);
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
    aad: &AssociatedData,
    addr: &str,
) {
    match peers.write().await.get_mut(&user) {
        None => {
            send_message(
                sender.clone(),
                ServerResponse::new(ResponseCode::NotFound, "User not found".to_string()).to_string(),
            )
                .await
                .expect("Failed to send message.");
            error!("User not found: {}", &user);
        },

        Some(peer) => {
            let bundle = peer.get_bundle();

            let response =
                ServerResponse::new(ResponseCode::Ok, bundle.to_base64()).to_string();

            match session.read().await.get_encryption_key() {
                Some(ek) => {
                    info!("Sending response: {}", &response);
                    match ek.encrypt(&response.into_bytes(), aad) {
                        Ok(enc) => {
                            info!("Sent encrypted response: {}", &enc);
                            send_message(sender.clone(), enc)
                                .await
                                .expect("Failed to send message.");
                            info!("Sent prekey bundle of {} to {}", &user, addr);
                        }
                        Err(e) => {
                            // TODO: handle error
                            error!("Failed to send response to client due to error: {}", e);
                        }
                    }
                }
                None => {
                    // ek is None, no need to check is there is an ek in the
                    // session
                    let response = ServerResponse::new(
                        ResponseCode::BadRequest,
                        "Establish a secure connection first".to_string(),
                    )
                    .to_string();
                    send_message(sender.clone(), response)
                        .await
                        .expect("Failed to send message.");
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
                    }
                    Err(_) => error!("Failed to encrypt: {}", msg_result.to_string()),
                }
            }
        }
    }
}
