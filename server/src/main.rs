mod errors;
mod utils;

mod tests;

use crate::errors::ServerError;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use aes_gcm::Nonce;
use base64::engine::general_purpose;
use base64::{write, Engine};
use futures::channel::mpsc::UnboundedReceiver;
use futures::stream::SplitSink;
use log::{error, info};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use futures_util::{SinkExt, StreamExt};
use futures_util::stream::SplitStream;
use serde_json::{json, Value};
use tokio::sync::RwLock;
use tokio_tungstenite::tungstenite::Utf8Bytes;
use protocol::errors::X3DHError;
use protocol::utils::{AssociatedData, DecryptionKey, EncryptionKey, PreKeyBundle, PrivateKey};
use protocol::x3dh::process_prekey_bundle;
use utils::{Action, RegisterRequest, RequestType, ServerResponse, Tx};
use crate::utils::{
    Peer,
    PeerMap,
    ResponseCode
};


// Keys for testing
const PRIVATE_KEY: &str = "QPdkjPrBYWzwTq70jdeVbr4f4kdS140HeuOXi88hgPc=";
const PUBLIC_KEY: &str = "NwAHzj8jBk6dkZxmUZsYKpCqwSUt1i2zK44ylb2bmw8=";

// server address
const IP: &str = "127.0.0.1";
const PORT: &str = "3333";

struct SessionKeys {
    ek: Option<EncryptionKey>,
    dk: Option<DecryptionKey>
}

impl SessionKeys {
    fn new() -> Self {
        Self{
            ek: None,
            dk: None
        }
    }

    fn new_with_keys(ek: EncryptionKey, dk: DecryptionKey) -> Self {
        Self {
            ek: Some(ek),
            dk: Some(dk)
        }
    }

    fn get_ecryption_key(&self) -> Option<EncryptionKey> {
        self.ek.clone()
    }

    fn get_decryption_key(&self) -> Option<DecryptionKey> {
        self.dk.clone()
    }

    fn set_encryption_key(&mut self, ek: EncryptionKey) {
        self.ek = Some(ek);
    }

    fn set_decryption_key(&mut self, dk: DecryptionKey) {
        self.dk = Some(dk);
    }
}

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
        Err(_) => "Unknown".to_string()
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

    let (sender, receiver) = ws_stream.split();
    let (tx, _rx) = mpsc::unbounded_channel();

    let _task_receiver = tokio::spawn(task_receiver(sender, receiver, tx.clone(), peers.clone(), addr.to_string()));

    // TODO: task for forward messages to other client

    //tokio::select! {
    //_ = task_receiver => (),
    //_ = task_sender => (),
    //}*/

}


fn establish_connection(bundle: String) -> Result<(String, SessionKeys), String> {

    if let Ok(bundle) = PreKeyBundle::try_from(bundle){
        match process_prekey_bundle(PrivateKey::from_base64(PRIVATE_KEY.to_string()).unwrap(), bundle.clone()) {
            Ok((im, ek, dk)) => {
                let session = SessionKeys::new_with_keys(ek, dk);
                let msg = ServerResponse::new(ResponseCode::OK, im.to_base64()).to_string();
                Ok((msg, session))

            }
            Err(e) => Err(
                ServerResponse::new(
                    ResponseCode::ERROR(ServerError::X3DHError(e)),
                    "Can't process bundle".to_string(),
                ).to_string()
            )
        }
    } else {
        Err(
            ServerResponse::new(
                ResponseCode::ERROR(ServerError::InvalidPreKeyBundle),
                "Prekey Bundle is malformed".to_string(),
            ).to_string()
        )
    }
}

async fn handle_registration(
    mut request: RegisterRequest,
    peers: PeerMap,
    sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
    tx: Tx,
    ek: EncryptionKey,
    aad: AssociatedData
) {
    request.bundle.retain(|c| !c.eq(&("\"".parse::<char>().unwrap())));

    if !peers.read().await.contains_key(&request.username) {
        match PreKeyBundle::try_from(request.bundle) {
            Ok(pb) => {
                let peer = Peer::new(tx, pb);
                peers.write().await.insert(request.username, peer);
                let response = ServerResponse::new(
                    ResponseCode::OK,
                    "User registerd successfully.".to_string(),
                ).to_string();

                match ek.encrypt(&response.into_bytes(), &aad) {
                    Ok(res) => {
                        sender.send(Message::Text(
                            Utf8Bytes::from(
                                res
                            )
                        )).await.expect("Failed to send message.");
                    } ,
                    Err(_) => todo!(),
                }
            },
            Err(e) => {
                let response = ServerResponse::new(
                    ResponseCode::ERROR(ServerError::X3DHError(e)),
                    "Try another time.".to_string()
                ).to_string();

                match ek.encrypt(&response.into_bytes(), &aad) {
                    Ok(enc) => {
                        sender.send(
                            Message::Text(
                                Utf8Bytes::from(
                                    enc
                                )
                            )
                        ).await.expect("Failed to send message.");
                    }
                    Err(e) => {error!("Failed to send response to client due to error: {}", e);}
                }
            },
        }
    } else {

        let response = ServerResponse::new(
            ResponseCode::ERROR(ServerError::UserAlreadyExists),
            "Try with other username.".to_string()
        ).to_string();

        match ek.encrypt(&response.into_bytes(), &aad) {
            Ok(enc) => {
                sender.send(
                    Message::Text(
                        Utf8Bytes::from(
                            enc
                        )
                    )
                ).await.expect("Failed to send message.");
            }
            Err(e) => {error!("Failed to send response to client due to error: {}", e);}
        }
    }
}

async fn task_receiver(
    mut sender: SplitSink<WebSocketStream<TcpStream>, Message>,
    mut receiver: SplitStream<WebSocketStream<TcpStream>>,
    tx: Tx,
    peers: PeerMap,
    addr: String
) {
    let mut session =  SessionKeys::new();

    while let Some(Ok(msg_result)) = StreamExt::next(&mut receiver).await {
        match msg_result {
            Message::Text(text) => {
                info!("Received message: \"{}\", from: {}", &text, &addr);
                if let Some(request) = RequestType::from_json(&serde_json::from_str::<Value>(text.as_str()).unwrap_or(Value::Null)) {
                    if let RequestType::EstablishConnection(bundle) = &request {
                        match establish_connection(bundle.to_string()) {
                            Ok((msg, s)) => {
                                session = s;
                                sender.send(Message::Text(Utf8Bytes::from(msg))).await.expect("Failed to send message.");
                            },

                            Err(e) => {
                                sender.send(Message::Text(Utf8Bytes::from(e))).await.expect("Failed to send message.");
                            }

                        }
                    
                    } else {
                        sender.send(
                            Message::Text(
                                Utf8Bytes::from(
                                    ServerResponse::new(
                                        ResponseCode::ERROR(ServerError::InvalidRequest),
                                        "Bad request".to_string()
                                    ).to_string()
                                )
                            )
                        ).await.expect("Failed to send message.");
                    }
                } else if let Some(dk) = session.get_decryption_key() {
                    match RequestType::decrypt_request(&text.to_string(), &dk) {
                        Ok((action, aad)) => {
                            match action {
                                Action::Register(register_request) => {
                                    if let Some(ek) = session.get_ecryption_key() {
                                       handle_registration(register_request, peers.clone(), &mut sender, tx.clone(), ek, aad).await;
                                    }
                                }
                                Action::SendMessage(send_message_request) => todo!(),
                                Action::GetPrekeyBundle(_) => todo!(),
                            }
                        },

                        Err(_e) => {

                            // TODO: encrypt error message or do not send any message

                            sender.send(
                                Message::Text(
                                    Utf8Bytes::from(
                                        ServerResponse::new(
                                            ResponseCode::ERROR(ServerError::InvalidRequest),
                                            "Establish a secure connection first".to_string()
                                        ).to_string()
                                    )
                                )
                            ).await.expect("Failed to send message.");
                        }
                    }
                }

            },

            Message::Close(_) => {
                info!("Connection closed");
            },
            _ => {}
        }
    }
}
