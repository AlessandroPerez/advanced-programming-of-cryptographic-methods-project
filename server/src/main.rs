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
use log::{error, info};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::sync::RwLock;
use tokio_tungstenite::tungstenite::Utf8Bytes;
use protocol::utils::{PreKeyBundle, PrivateKey};
use protocol::x3dh::process_prekey_bundle;
use utils::{Action, RequestType, ServerResponse};
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

    let (mut sender, mut receiver) = ws_stream.split();
    let (tx, _rx) = mpsc::unbounded_channel();
    let (mut enc_key, mut dec_key) = (None, None);
    let _task_receiver = tokio::spawn( async move {
        while let Some(Ok(msg_result)) = StreamExt::next(&mut receiver).await {
            match msg_result {
                Message::Text(text) => {
                    info!("Received message: \"{}\", from: {}", &text, &addr);
                    if let Some(request) = RequestType::from_json(&serde_json::from_str::<Value>(text.as_str()).unwrap_or(Value::Null)) {
                        match &request {
                            RequestType::EstablishConnection(bundle) => {
                                if let Ok(bundle) = PreKeyBundle::try_from(bundle.to_string()){
                                    match process_prekey_bundle(PrivateKey::from_base64(PRIVATE_KEY.to_string()).unwrap(), bundle.clone()) {
                                        Ok((im, ek, dk)) => {
                                            enc_key = Some(ek);
                                            dec_key = Some(dk);
                                            sender.send(
                                                Message::Text(
                                                    Utf8Bytes::from(
                                                        ServerResponse::new(
                                                            ResponseCode::OK,
                                                            im.to_base64()
                                                        ).to_string()
                                                    )
                                                )
                                            ).await.expect("Failed to send message");
                                        }
                                        Err(e) => {
                                            error!("Failed to establish secure connection with {}", &addr);
                                            sender.send(
                                                Message::Text(
                                                    Utf8Bytes::from(
                                                        ServerResponse::new(
                                                            ResponseCode::ERROR(ServerError::X3DHError(e)),
                                                            "Something happened".to_string(),
                                                        ).to_string()
                                                    )
                                                )
                                            ).await.expect("Failed to send message");
                                        }
                                    }
                                } else {
                                    error!("Invalid PreKeyBundle from {}", &addr);
                                    sender.send(Message::Text(Utf8Bytes::from("Invalid PreKeyBundle"))).await.expect("Failed to send message");
                                }
                            },

                            _ => {}
                        }
                    } else {
                        if let Some(dk) = &dec_key {
                            let r = RequestType::decrypt_request(text.as_str(), dk);
                            match r {
                                Ok((action, nonce, aad)) => {
                                    info!("Request decrypted successfully");
                                    match action {
                                        Action::Register(mut req) => {
                                            info!("Register request from {}", &addr);

                                            req.bundle.retain(|c| !c.eq(&("\"".parse::<char>().unwrap())));

                                            if let Ok(pb) = PreKeyBundle::try_from(req.bundle) {
                                                info!("PreKeyBundle parsed successfully");
                                                if !peers.read().await.contains_key(&req.username) {
                                                    info!("Registered user {}", &req.username);
                                                    peers.write().await.insert(req.username.to_string(), Peer::new(tx.clone(), pb));

                                                    let response = ServerResponse::new(
                                                        ResponseCode::OK,
                                                        "User registered successfully.".to_string()
                                                    ).to_string();

                                                    let enc_response: Vec<u8> = if enc_key.is_some() {
                                                        let nonce =  b"123456789012";
                                                        enc_key.clone().unwrap().encrypt(&response.into_bytes(), &nonce, &aad).unwrap()
                                                    } else {
                                                        error!("Missing encryption key");
                                                        return;
                                                    };
                                                    let b64_response = general_purpose::STANDARD.encode(enc_response);

                                                    sender.send(
                                                        Message::Text(
                                                            Utf8Bytes::from(
                                                                b64_response
                                                            )
                                                        )
                                                    ).await.expect("Failed to send message");
                                                } else {
                                                    sender.send(
                                                        Message::Text(
                                                            Utf8Bytes::from(
                                                                ServerResponse::new(
                                                                    ResponseCode::ERROR(ServerError::UserAlreadyExists),
                                                                    "Choose another username.".to_string()
                                                                ).to_string()
                                                            )
                                                        )
                                                    ).await.expect("Failed to send message");
                                                }
                                            }
                                        },
                                        Action::SendMessage(req) => {},
                                        Action::GetPrekeyBundle(usr) => {},
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to decrypt request: {}", e);
                                    sender.send(
                                        Message::Text(
                                            Utf8Bytes::from(
                                                ServerResponse::new(
                                                    ResponseCode::ERROR(ServerError::InvalidRequest),
                                                    "Invalid request".to_string()
                                                ).to_string()
                                            )
                                        )
                                    ).await.expect("Failed to send message")
                                },
                            }
                        } else {
                            sender.send(
                                Message::Text(
                                    Utf8Bytes::from(
                                        ServerResponse::new(
                                            ResponseCode::ERROR(ServerError::InvalidRequest),
                                            "Establish a secure connection first".to_string()
                                        ).to_string()
                                    )
                                )
                            ).await.expect("Failed to send message");
                        }
                    }
                },

                Message::Close(_) => {
                    info!("Connection closed with {}", addr);
                },
                _ => {}
            }
        }
    });


    /*let (tx, rx) = mpsc::unbounded_channel();



    let task_receiver = tokio::spawn(receive_messages(&mut receiver, &mut peers));
    let task_sender = tokio::spawn(send_messages(&mut sender, &mut peers));

    tokio::select! {
        _ = task_receiver => (),
        _ = task_sender => (),
    }*/

}
