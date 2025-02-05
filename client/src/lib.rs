pub mod errors;

use std::{collections::HashMap, env::set_var, hash::Hash, process::exit};
use std::fmt::Display;
use std::ops::Add;
use std::sync::Arc;
use aes_gcm::aes::cipher::typenum::Le;
use chrono::{DateTime, Utc};
use common::{ResponseCode, ServerResponse, ResponseWrapper, RequestWrapper};
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use log::{error, info};
use protocol::x3dh::{generate_prekey_bundle, generate_prekey_bundle_with_otpk, process_initial_message, process_server_initial_message};
use protocol::{
    utils::{
        AssociatedData, DecryptionKey, EncryptionKey, InitialMessage, PreKeyBundle, PrivateKey,
        SessionKeys,
    },
    x3dh::process_prekey_bundle,
};
use serde_json::{json, Value};

use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::{
    tungstenite::{Message, Utf8Bytes},
    MaybeTlsStream, WebSocketStream,
};
use uuid::Uuid;
use protocol::utils::PublicKey;
use serde::{Deserialize, Serialize};
use crate::errors::ClientError;

pub const SERVER_URL: &str = "ws://127.0.0.1:3333";
pub const SERVER_IK: &str = "KidEmuJzis1xt3+XwkzEBx4rB8hjuEvHK0LV0vY5aE8=";
type Sender = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type Receiver = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;



pub struct Client {
    pub friends: HashMap<String, Friend>,
    session: SessionKeys,
    write: Sender,
    read: Option<Receiver>,
    pub username: String,
    bundle: PreKeyBundle,
    identity_key: PrivateKey,
    signed_prekey: PrivateKey,
    one_time_prekey: Vec<PrivateKey>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<serde_json::Value>>>>,
    listener: Option<tokio::task::JoinHandle<()>>,

    chat_tx: mpsc::Sender<ChatMessage>,

}


impl Client {

    pub async fn new(chat_tx: mpsc::Sender<ChatMessage>) -> Result<Self, ClientError> {
        let (write, read) = Self::connect().await?;
        let (bundle, ik, spk, otpk) = generate_prekey_bundle_with_otpk(10);
        let session = SessionKeys::new();
        let username = "".to_string();

        let mut client = Self {
            friends: HashMap::new(),
            session,
            write,
            read: Some(read),
            username,
            bundle,
            identity_key: ik,
            signed_prekey: spk,
            one_time_prekey: otpk,
            pending: Arc::new(Mutex::new(HashMap::new())),
            listener: None,
            chat_tx,
        };

        client.establish_connection().await?;
        client.listener = Some(client.start_read_loop());
        Ok(client)
    }

    async fn connect() -> Result<(Sender, Receiver), ClientError> {
        let (ws_stream, _) = tokio_tungstenite::connect_async(SERVER_URL).await?;
        let (write, read) = ws_stream.split();
        Ok((write, read))
    }

    pub async fn establish_connection(&mut self) -> Result<(), ClientError> {

        let msg = json!({
        "request_type": "EstablishConnection",
        "bundle": self.bundle.clone().to_base64()
        });

        self.write
            .send(Message::Text(Utf8Bytes::from(msg.to_string())))
            .await
            .expect("Failed to send message");


        if let Some(read) = &mut self.read {

            // Wait for server response
            if let Some(Ok(Message::Text(initial_msg))) = StreamExt::next(read).await {

                let resp = ServerResponse::from_json(initial_msg.to_string())
                    .ok_or(ClientError::ServerResponseError)?;

                let mut im = resp.text;
                info!("im: {}", &im);
                im.retain(|c| !c.eq(&("\"".parse::<char>().unwrap())));
                let initial_message = InitialMessage::try_from(im)?;
                let (ek, dk) = process_server_initial_message(
                    self.identity_key.clone(),
                    self.signed_prekey.clone(),
                    Some(self.one_time_prekey.pop().unwrap()),
                    &PublicKey::from_base64(SERVER_IK.to_string()).unwrap(),
                    initial_message.clone(),
                )?;

                self.session.set_encryption_key(ek);
                self.session.set_decryption_key(dk);
                self.session.set_associated_data(initial_message.associated_data);
                Ok(())
            } else {
                Err(ClientError::ServerResponseError)
            }
        } else {
            Err(ClientError::ServerResponseError)
        }
    }

    fn start_read_loop(&mut self) -> tokio::task::JoinHandle<()> {
        let mut read = self.read.take().expect("Reader already taken");
        let pending_map = Arc::clone(&self.pending);
        let decryption_key = self.session.get_decryption_key().unwrap();
        let chat_tx = self.chat_tx.clone();
        tokio::task::spawn( async move {
            while let Some(msg_result) = StreamExt::next(&mut read).await {
                match msg_result {
                    Ok(Message::Text(msg)) => {
                        if let Ok(decrypted) = decrypt_server_request(msg.to_string(), &decryption_key) {
                            if let Ok(response) = serde_json::from_str::<ResponseWrapper>(&decrypted.to_string()) {

                                // Look up the request_id in the pending map
                                let mut lock = pending_map.lock().await;
                                if let Some(tx) = lock.remove(&response.request_id) {
                                    // Send the "body" to whoever is waiting
                                    let _ = tx.send(response.body);
                                }

                            } else if let Ok(chat_msg) = serde_json::from_str::<ChatMessage>(&decrypted.to_string()) {
                                // Forward to the chat channel
                                let _ = chat_tx.send(chat_msg).await;
                            }
                            // 4) Otherwise, ignore or log unknown format
                            else {
                                error!("Unknown message format: {}", decrypted);
                            }
                        }
                    },
                    Ok(Message::Close(_)) => {
                        info!("WebSocket closed by server.");
                        break;
                    },
                    Err(e) => {
                        error!("WebSocket error: {:?}", e);
                        break;
                    },
                    _ => {}
                }
            }
        })
    }

    pub async fn register_user(&mut self) -> Result<(), ClientError> {
        let req = json!({
            "action" : "register",
            "username" : self.username.clone(),
            "bundle": self.bundle.clone().to_base64()
        });

        let response_json = self.send_encrypted_message(req).await?;
        let response = ServerResponse::from_json(response_json.to_string())
            .ok_or(ClientError::ServerResponseError)?;
        match response.code {
            ResponseCode::Ok => {
                Ok(())
            }
            ResponseCode::Conflict => {
                Err(ClientError::UserAlreadyExistsError)
            }
            _ => {
                Err(ClientError::ServerResponseError)
            }
        }
    }

    pub async fn get_user_prekey_bundle(
        &mut self,
        username: String,
    ) -> Result<(), ClientError> {
        let req = json!({
            "action": "get_prekey_bundle",
            "who": username.clone(),
        });

        let response_json = self.send_encrypted_message(req).await?;
        let response = ServerResponse::from_json(response_json.to_string())
            .ok_or(ClientError::ServerResponseError)?;
        match response.code {
            ResponseCode::Ok => {
                let pb = PreKeyBundle::try_from(response.text)?;
                let (im, ek, dk) = process_prekey_bundle(
                    self.identity_key.clone(),
                    pb.clone()
                )?;
                let friend_session =  SessionKeys::new_with_keys(ek, dk, Some(im.associated_data.clone()));
                self.friends.insert(username.clone(), Friend::new(friend_session, Some(pb.clone())));
                let chat_message = ChatMessage::new(
                    "initial_message".to_string(),
                    username.clone(),
                    self.username.clone(),
                    im.to_base64(),
                    Utc::now()
                );
                self.send_chat_message(chat_message).await?;
                Ok(())
            },
            ResponseCode::NotFound => {
                Err(ClientError::UserNotFoundError)
            },
            _ => {
                Err(ClientError::ServerResponseError)
            }
        }
    }

    async fn send_encrypted_message(&mut self, req: Value) -> Result<Value, ClientError> {
        let request_id = Uuid::new_v4().to_string();
        let wrapper = RequestWrapper{ request_id: request_id.clone(), body: req };
        let serialized = serde_json::to_string(&wrapper)
            .map_err(|_| ClientError::SerializationError)?;


        let enc = self.session
            .get_encryption_key()
            .unwrap()
            .encrypt(
                serialized.as_bytes(),
                &self.session.get_associated_data().unwrap(),
            )?;


        let (tx, rx) = oneshot::channel();

        {
            // Insert the sender into the HashMap so the read loop can find it
            let mut lock = self.pending.lock().await;
            lock.insert(request_id, tx);
        }


        self.write
            .send(Message::Text(Utf8Bytes::from(enc)))
            .await
            .map_err(|_| ClientError::SendError)?;

        // 7. Wait for the response from the read loop
        rx.await.map_err(|_| ClientError::ServerResponseError)
    }

    pub fn set_username(&mut self, username: String) {
        self.username = username;
    }

    pub async fn disconnect(&mut self) {
        if let Some(listener) = self.listener.take() {
            listener.abort();
        }
        self.write.close().await.expect("Failed to close connection");
    }

    pub fn is_registered(&self) -> bool {
        self.username != "".to_string()
    }

    pub async fn send_chat_message(&mut self, mut message: ChatMessage) -> Result<(), ClientError> {

        let mut req = json!(message.clone());
        req["action"] = serde_json::from_str("\"send_message\"").unwrap();
        let mut req = req.to_string();

        if message.msg_type != "initial_message".to_string() {
            let (friend_ek, friend_aad) = if let Some(friend) = self.friends.get(&message.to) {
                (
                    friend.get_friend_keys().get_encryption_key().unwrap(),
                    friend.get_friend_keys().get_associated_data().unwrap(),
                )
            } else {
                return Err(ClientError::UserNotFoundError);
            };
            let enc_text = friend_ek.encrypt(
                message.text.as_bytes(),
                &friend_aad,
            )?;

            message.text = enc_text;
            req = json!(message).to_string();
        }
        let enc = self.session
                .get_encryption_key()
                .unwrap()
                .encrypt(
                    req.as_bytes(),
                    &self.session.get_associated_data().unwrap(),
                )?;

        self.write
                .send(Message::Text(Utf8Bytes::from(enc)))
                .await
                .map_err(|_| ClientError::SendError)?;

        Ok(())
    }


    pub fn add_friend(&mut self, message: ChatMessage) -> Result<(), ClientError> {
        let im = InitialMessage::try_from(message.text.clone())?;
        let (ek, dk) = process_initial_message(
            self.identity_key.clone(),
            self.signed_prekey.clone(),
            self.one_time_prekey.pop(),
            im.clone()
        )?;
        let friend_session = SessionKeys::new_with_keys(ek, dk, Some(im.associated_data.clone()));
        let friend = Friend::new(friend_session, None);
        self.friends.insert(message.from, friend);
        Ok(())
    }

    pub fn add_chat_message(&mut self, message: ChatMessage) {
        if let Some(friend) = self.friends.get_mut(&message.from) {
            friend.add_message(message);
        }
    }

    pub fn get_chat_messages(&self, username: &str) -> Option<&Vec<ChatMessage>> {
        self.friends.get(username).map(|f| &f.chat)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatMessage {
    pub msg_type: String,
    pub to: String,
    pub from: String,
    pub text: String,
    pub timestamp: String
}

impl ChatMessage {
    fn new(msg_type: String, to: String,  from: String, text: String, timestamp: DateTime<Utc>) -> Self {
        Self {
            msg_type,
            to,
            from,
            text,
            timestamp: timestamp.to_rfc3339()
        }
    }
}

impl Display for ChatMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.from, self.text)
    }
}

struct Friend {
    keys: SessionKeys,
    pb: Option<PreKeyBundle>,
    chat: Vec<ChatMessage>
}

impl Friend {
    fn new(keys: SessionKeys, pb: Option<PreKeyBundle>) -> Self {
        Self {
            keys,
            pb,
            chat: Vec::new()
        }
    }

    fn get_friend_bundle(&self) -> Option<PreKeyBundle> {
        self.pb.clone()
    }

    fn get_friend_keys(&self) -> SessionKeys {
        self.keys.clone()
    }

    fn add_message(&mut self, message: ChatMessage) {
        self.chat.push(message);
    }
}

fn decrypt_server_request(req: String, dk: &DecryptionKey) -> Result<Value, ()> {
    match common::decrypt_request(&req, dk) {
        Ok((dec, _)) => Ok(dec),
        Err(_) => Err(())
    }
}

