mod errors;
mod utils;

mod tests;

use crate::errors::ServerError;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use log::{error, info};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::{accept_async, tungstenite::Message, WebSocketStream};
use futures_util::{SinkExt, StreamExt};
use futures_util::stream::{SplitSink, SplitStream};
use serde_json::Value;
use tokio::sync::RwLock;
use tokio_tungstenite::tungstenite::{Error, Utf8Bytes};
use protocol::errors::X3DHError;
use protocol::utils::{DecryptionKey, EncryptionKey, InitialMessage, PreKeyBundle, PrivateKey};
use protocol::x3dh::process_prekey_bundle;
use utils::{RequestType, ServerResponse};
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

async fn handle_connection(stream: TcpStream, mut peers: PeerMap) {
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
    let mut user_ik = None;

    let _task_receiver = tokio::spawn( async move {
        while let Some(Ok(msg_result)) = StreamExt::next(&mut receiver).await {
            match msg_result {
                Message::Text(text) => {
                    info!("Received message: \"{}\", from: {}", &text, &addr);

                    if let Some(request) = RequestType::from_json(&serde_json::from_str::<Value>(text.as_str()).unwrap_or(Value::Null)) {
                        match request {
                            RequestType::EstablishConnection(bundle) => {
                                if let Ok(bundle) = PreKeyBundle::try_from(bundle.to_string()){
                                    match process_prekey_bundle(PrivateKey::from_base64(PRIVATE_KEY.to_string()).unwrap(), bundle.clone()) {
                                        Ok((im, ek, dk)) => {
                                            info!("Secure connection established with {}", &addr);
                                            let ik = bundle.ik.clone();
                                            user_ik = Some(ik.clone().to_base64());
                                            let peer = Peer::new(tx.clone(), ek, dk, bundle);
                                            if peers.write().await.insert(ik.to_base64(), peer).is_none() {
                                                info!("Added peer to list of online users");
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
                                            } else {
                                                error!("Secure connection already established");
                                                sender.send(
                                                    Message::text(
                                                        Utf8Bytes::from(
                                                            ServerResponse::new(
                                                                ResponseCode::ERROR(ServerError::UserAlreadyExists),
                                                                "User already exist".to_string()
                                                            ).to_string()
                                                        )
                                                    )
                                                ).await.expect("Failed to send message");
                                            }
                                        }
                                        Err(e) => {error!("Failed to establish secure connection with {}", &addr);
                                            sender.send(
                                                Message::Text(
                                                    Utf8Bytes::from(
                                                        ServerResponse::new(
                                                            ResponseCode::ERROR(ServerError::X3DHError(e)),
                                                            "Something happened".to_string(),
                                                        ).to_string()
                                                    )
                                                )
                                            ).await.expect("Failed to send message");}
                                    }
                                } else {
                                    error!("Invalid PreKeyBundle from {}", &addr);
                                    sender.send(Message::Text(Utf8Bytes::from("Invalid PreKeyBundle"))).await.expect("Failed to send message");
                                }
                            },

                            RequestType::Register(req) => {},
                            RequestType::SendMessage(req) => {},
                            RequestType::GetPrekeyBundle(usr) => {}
                        }

                    } else {
                        error!("Invalid request from {}", &addr);
                        sender.send(Message::Text(Utf8Bytes::from("Invalid request"))).await.unwrap();
                    }

                }

                Message::Close(_) => {
                    info!("Connection closed with {}", addr);
                    peers.write().await.remove(&user_ik.clone().unwrap_or("".to_string()));
                }
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
