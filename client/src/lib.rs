pub mod errors;

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;
use arrayref::array_ref;
use base64::Engine;
use base64::engine::general_purpose;
use chrono::{DateTime, Utc};
use common::{ResponseCode, ServerResponse, ResponseWrapper, RequestWrapper, CONFIG};
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use log::{debug, error, info};
use protocol::x3dh::{generate_prekey_bundle_with_otpk, process_initial_message, process_server_initial_message};
use protocol::{
    utils::{
        AssociatedData, DecryptionKey, InitialMessage, PreKeyBundle, PrivateKey,
        SessionKeys,
    },
    x3dh::process_prekey_bundle,
    ratchet::{Ratchet, RatchetKeyPair},

};
use serde_json::{json, Value};

use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::{
    tungstenite::{Message, Utf8Bytes},
    MaybeTlsStream, WebSocketStream,
};
use uuid::Uuid;
use protocol::utils::{PublicKey, Sha256Hash, SharedSecret};
use serde::{Deserialize, Serialize};
use protocol::constants::AES256_NONCE_LENGTH;
use crate::errors::ClientError;

type Sender = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type Receiver = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

pub struct Client {
    pub(crate) friends: HashMap<String, Friend>,
    session: SessionKeys,
    write: Sender,
    read: Option<Receiver>,
    pub username: String,
    bundle: PreKeyBundle,
    identity_key: PrivateKey,
    signed_prekey: PrivateKey,
    one_time_prekeys: HashMap<Sha256Hash, PrivateKey>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<Value>>>>,
    listener: Option<tokio::task::JoinHandle<()>>,
    chat_tx: mpsc::Sender<ChatMessage>,
}

impl Client {

    pub async fn new(chat_tx: mpsc::Sender<ChatMessage>) -> Result<Self, ClientError> {
        let (write, read) = Self::connect().await?;
        let (bundle, ik, spk, otpk) = generate_prekey_bundle_with_otpk(31);
        let session = SessionKeys::new();
        let username = "".to_string();
        let public_otpk = bundle.otpk.clone();
        let hash_otpk = public_otpk.iter().map(|v| v.hash()).collect::<Vec<Sha256Hash>>();
        let otpk = hash_otpk
            .iter()
            .zip(otpk.iter())
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();

        let mut client = Self {
            friends: HashMap::new(),
            session,
            write,
            read: Some(read),
            username,
            bundle,
            identity_key: ik,
            signed_prekey: spk,
            one_time_prekeys: otpk,
            pending: Arc::new(Mutex::new(HashMap::new())),
            listener: None,
            chat_tx,
        };

        client.establish_connection().await?;
        client.listener = Some(client.start_read_loop());
        Ok(client)
    }

    async fn connect() -> Result<(Sender, Receiver), ClientError> {
        let (ws_stream, _) = tokio_tungstenite::connect_async(CONFIG.get_server_url()).await?;
        let (write, read) = ws_stream.split();
        Ok((write, read))
    }

    pub async fn establish_connection(&mut self) -> Result<(), ClientError> {

        let msg = json!({
        "request_type": "establish_connection",
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
                debug!("im: {}", &im);
                im.retain(|c| !c.eq(&("\"".parse::<char>().unwrap())));
                let initial_message = InitialMessage::try_from(im)?;
                let otpk_used = self.one_time_prekeys.get(
                    &initial_message.one_time_key_hash
                        .clone()
                        .unwrap()
                );
                let (ek, dk) = process_server_initial_message(
                    self.identity_key.clone(),
                    self.signed_prekey.clone(),
                    otpk_used.cloned(),
                    &PublicKey::from_base64(CONFIG.get_public_key_server()).unwrap(),
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
        self.bundle.otpk.pop();
        let req = json!({
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
                let sk = SharedSecret::from((ek, dk));
                let ratchet = Ratchet::init_alice(sk, pb.spk.clone());

                self.friends.insert(username.clone(), Friend::new(ratchet, Some(pb.clone()), im.associated_data.clone()));
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
                &self.session
                    .get_associated_data()
                    .unwrap()
                    .to_bytes(),
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
        if message.msg_type != "initial_message".to_string() {
            let mut friend = self.friends.get_mut(&message.to);
            if let Some(friend) = friend {
               let aad = friend.get_friend_aad();
                message.text = friend.ratchet.encrypt(
                    message.text.as_bytes(),
                    &aad.to_bytes(),
                )?;
            } else {
                return Err(ClientError::UserNotFoundError);
            }
        }
        let mut req = serde_json::to_value(message)
            .map_err(|_| ClientError::SerializationError)?;

        let enc = self.session
                .get_encryption_key()
                .unwrap()
                .encrypt(
                    req.to_string().as_bytes(),
                    &self.session
                        .get_associated_data()
                        .unwrap()
                        .to_bytes(),
                )?;

        self.write
                .send(Message::Text(Utf8Bytes::from(enc)))
                .await
                .map_err(|_| ClientError::SendError)?;

        Ok(())
    }


    pub fn add_friend(&mut self, message: ChatMessage) -> Result<(), ClientError> {

        let im = InitialMessage::try_from(message.text.clone())?;
        let otpk_used = self.one_time_prekeys.get(
            &im.one_time_key_hash
                .clone()
                .unwrap()
        );
        let (ek, dk) = process_initial_message(
            self.identity_key.clone(),
            self.signed_prekey.clone(),
            otpk_used.cloned(),
            im.clone()
        )?;

        let sk = SharedSecret::from((dk, ek));
        let keypair = RatchetKeyPair::new_from(
            self.signed_prekey.clone(),
            self.bundle.spk.clone(),
        );
        let ratchet = Ratchet::init_bob(sk, keypair);

        let friend = Friend::new(ratchet, None, im.associated_data.clone());
        self.friends.insert(message.from, friend);
        Ok(())
    }

    pub fn add_chat_message(&mut self, message: ChatMessage, friend: &str) {
        if let Some(friend) = self.friends.get_mut(friend) {
            friend.add_message(message);
        }
    }

    pub fn decrypt_chat_message(&mut self, mut message: ChatMessage) -> Result<(), ClientError> {
        let mut friend = self.friends.get_mut(&message.from);

        if let Some(friend) = friend {
            let text = friend.ratchet.decrypt(message.text)?;
            message.text = String::from_utf8(text)?;

            self.add_chat_message(message.clone(), &message.from);
            Ok(())
        } else {
            Err(ClientError::UserNotFoundError)
        }
    }

    pub fn get_chat_history(&self, username: &str) -> Option<Vec<ChatMessage>> {
        self.friends.get(username).map(|f| &f.chat).cloned()
    }

    pub fn get_open_chats(&self) -> Vec<String> {
        self.friends.keys().cloned().collect()
    }

    pub async fn close_chat(&mut self, f: String) -> Result<(), ClientError> {

        self.send_chat_message(ChatMessage::new(
            "close_chat".to_string(),
            f.clone(),
            self.username.clone(),
            "".to_string(),
            Utc::now()
        )).await?;
        Ok(())
    }

    pub fn remove_friend(&mut self, f: String) {
        self.friends.remove(&f);
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatMessage {
    pub msg_type: String,
    pub from: String,
    pub to: String,
    pub text: String,
    pub timestamp: String
}

impl ChatMessage {
    pub fn new(msg_type: String, to: String,  from: String, text: String, timestamp: DateTime<Utc>) -> Self {
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
    pub ratchet: Ratchet,
    pb: Option<PreKeyBundle>,
    chat: Vec<ChatMessage>,
    aad: AssociatedData,
}

impl Friend {
    fn new(ratchet: Ratchet, pb: Option<PreKeyBundle>, aad: AssociatedData) -> Self {
        Self {
            ratchet,
            pb,
            chat: Vec::new(),
            aad,
        }
    }

    fn get_friend_bundle(&self) -> Option<PreKeyBundle> {
        self.pb.clone()
    }

    fn get_friend_aad(&self) -> AssociatedData {
        self.aad.clone()
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

