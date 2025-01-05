mod errors;
use crate::errors::ServerError;
use std::collections::HashMap;
use std::env;
use std::fmt::Display;
use std::sync::Arc;
use log::info;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use futures::StreamExt;
use futures_util::SinkExt;
use futures_util::stream::SplitSink;
use serde_json::Value;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Utf8Bytes;
use protocol::x3dh::{
    EncryptionKey,
    DecryptionKey,
    PreKeyBundle,
    PrivateKey,
    PublicKey,
    X3DHError,
    process_prekey_bundle
};
use uuid::Uuid;

type Tx = mpsc::UnboundedSender<Message>;
type PeerMap = Arc<RwLock<HashMap<String, Peer>>>;
struct Peer {
    id: String,
    sender: Tx,
    encryption_key: Option<EncryptionKey>,
    decryption_key: Option<DecryptionKey>,
    pb: Option<PreKeyBundle>,
}

enum Action {
    EstablishConnection,
    SendMessage,
    GetPrekeyBundle,
}

impl Action {
    fn from_str(action: &str) -> Option<Self> {
        match action {
            "establish_connection" => Some(Self::EstablishConnection),
            "send_message" => Some(Self::SendMessage),
            "get_prekey_bundle" => Some(Self::GetPrekeyBundle),
            _ => None
        }
    }
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    env_logger::init();

    env::set_var("SERVER_IK", PrivateKey::new().to_base64());
    let spk = PrivateKey::new();
    env::set_var("SERVER_PUBLIC_SPK", PublicKey::from(&spk).to_base64());
    env::set_var("SERVER_SECRET_SPK", spk.to_base64());

    let peers: PeerMap = Arc::new(RwLock::new(HashMap::new()));

    let addr = "127.0.0.1:3333";
    let listener = TcpListener::bind(&addr).await.unwrap();
    info!("WebSocket server started listening on port 3333");
    while let Ok((stream, _)) = listener.accept().await {
        let peers = peers.clone();
        tokio::spawn(handle_connection(stream, peers));
    }
}

async fn handle_connection(stream: TcpStream, peers: PeerMap) {
    let ws_stream = accept_async(stream)
        .await
        .expect("Error during websocket handshake");

    let (mut write, mut read) = ws_stream.split();
    info!("New WebSocket connection established");

    let (tx, mut rx) = mpsc::unbounded_channel();

    let peer_uuid = Uuid::new_v4().to_string();
    peers.write().await.insert(
        peer_uuid.clone(),
        Peer {
            id: peer_uuid.clone(),
            sender: tx,
            encryption_key: None,
            decryption_key: None,
            pb: None,
        }
    );

    let task_sender = tokio::spawn( async move {
        while let Some(msg) = rx.next().await {
            if let Ok(msg) = msg {
                if write.send(msg).await.is_err() {
                    break;
                }
            }
        }
    });

    let peers_clone = peers.clone();
    let task_receiver = tokio::spawn( async move {
        while let Some(Ok(msg)) = read.next().await {
            if let Message::Text(text) = msg {
                println!("Received: {}", text);

                // Parse the target peer and message content
                if let Some((action, target_id, content)) = parse_message(&text).await {
                    if let Ok(msg) = handle_message(action, target_id, content, &peers_clone, peer_uuid.clone()).await {
                        if let Some(target) = peers_clone.read().await.get(&target_id) {
                            let _ = target.sender.send(Message::Text(Utf8Bytes::from(msg)));
                        }
                    }
                }
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = task_receiver => (),
        _ = task_sender => (),
    }

    // Cleanup when the client disconnects
    peers.write().await.remove(&peer_uuid);
    println!("Connection closed with peer: {}", peer_uuid);

}

async fn handle_message(action: Action, target: String, content: String, peer_map: &PeerMap, peer_uuid: String) -> Result<String, ServerError> {
    match action {
        Action::EstablishConnection => {
            let ik = env::var("SERVER_IK")?;
            let ik = PrivateKey::from_base64(ik)?;
            let (im, enc_key, dec_key) = process_prekey_bundle(ik, PreKeyBundle::try_from(content.clone())?)?;
            let im = im.to_base64();
            let mut peer_update = peer_map.write().await.remove(&peer_uuid).unwrap();
            peer_update.encryption_key = Some(enc_key);
            peer_update.decryption_key = Some(dec_key);
            peer_update.pb = Some(PreKeyBundle::try_from(content)?);
            peer_map.write().await.insert(peer_uuid, peer_update);
            Ok(im)
        }
        Action::SendMessage => Ok(content),
        Action::GetPrekeyBundle => {
            if let Some(peer) = peer_map.read().await.get(&target) {
                if let Some(pb) = &peer.pb {
                    Ok(pb.clone().to_base64())
                } else {
                    Err(ServerError::UserNotFoundError)
                }
            } else {
                Err(ServerError::UserNotFoundError)
            }
        }
    }
}

async fn parse_message(text: &str) -> Option<(Action, String, String)> {
    if let Ok(json) = serde_json::from_str::<Value>(text) {
        let action = json.get("action")?.as_str()?.to_string();
        let action = Action::from_str(&action)?;
        let target = json.get("target")?.as_str()?.to_string();
        let content = json.get("content")?.as_str()?.to_string();
        Some((action, target, content))
    } else {
        None
    }
}
