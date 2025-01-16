mod errors;
mod utils;

use crate::errors::ServerError;
use std::collections::HashMap;
use std::env;
use std::fmt::Display;
use std::sync::Arc;
use log::{error, info};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::{accept_async, tungstenite::Message, WebSocketStream};
use futures_util::{SinkExt, StreamExt};
use futures_util::stream::{SplitSink, SplitStream};
use serde_json::Value;
use tokio::sync::RwLock;
use tokio_stream::StreamExt as tokioStreamExt;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_tungstenite::tungstenite::{Error, Utf8Bytes};
use protocol::utils::{
    EncryptionKey,
    DecryptionKey,
    PreKeyBundle,
    PrivateKey,
    PublicKey,
};
use protocol::x3dh::process_prekey_bundle;
use protocol::errors::X3DHError;
use crate::utils::{
    Peer,
    PeerMap,
    Action,
    Request
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

async fn handle_connection(stream: TcpStream, mut peers: PeerMap<'_>) {
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

    let task_receiver = tokio::spawn( async move {
        while let Some(Ok(msg_result)) = StreamExt::next(&mut receiver).await {
            match msg_result {
                Message::Text(text) => {
                    info!("Received message: \"{}\", from: {}", &text, &addr);
                    if let Some(request) = Request::from_json(&serde_json::from_str::<Value>(text.as_str()).unwrap()) {
                        match request.action {
                            Action::EstablishConnection => { info!("Establishing secure connection with {}", &addr); }
                            Action::Register => {}
                            Action::SendMessage => {}
                            Action::GetPrekeyBundle => {}
                        }

                    } else {
                        error!("Invalid request from {}", &addr);
                        sender.send(Message::Text(Utf8Bytes::from("Invalid request"))).await.unwrap();
                    }

                }

                Message::Close(_) => { info!("Connection closed with {}", addr); }
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

fn send_messages(p0: &mut SplitSink<WebSocketStream<TcpStream>, Message>, p1: &mut PeerMap) {
    todo!()
}

fn receive_messages(p0: &mut SplitStream<WebSocketStream<TcpStream>>, p1: &mut PeerMap) {
    todo!()
}

