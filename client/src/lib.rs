pub mod errors;

use std::{collections::HashMap, env::set_var, hash::Hash, process::exit};
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
use tokio::sync::{oneshot, Mutex};
use tokio_tungstenite::{
    tungstenite::{Message, Utf8Bytes},
    MaybeTlsStream, WebSocketStream,
};
use uuid::Uuid;
use protocol::utils::PublicKey;
use crate::errors::ClientError;
use crate::TypeOr::{Left, Right};

pub const SERVER_URL: &str = "ws://127.0.0.1:3333";
pub const SERVER_IK: &str = "KidEmuJzis1xt3+XwkzEBx4rB8hjuEvHK0LV0vY5aE8=";
type Sender = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type Receiver = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

enum TypeOr<L, R> {
    Left(L),
    Right(R)
}


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
    listener: Option<tokio::task::JoinHandle<()>>
}


impl Client {

    pub async fn new() -> Result<Self, ClientError> {
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
            listener: None
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
        tokio::task::spawn( async move {
            while let Some(msg_result) = StreamExt::next(&mut read).await {
                match msg_result {
                    Ok(Message::Text(msg)) => {
                        if let Ok(decrypted) = decrypt_server_request(msg.to_string(), &decryption_key) {
                            match serde_json::from_str::<ResponseWrapper>(&decrypted.to_string()) {
                                Ok(response) => {
                                    // Look up the request_id in the pending map
                                    let mut lock = pending_map.lock().await;
                                    if let Some(tx) = lock.remove(&response.request_id) {
                                        // Send the "body" to whoever is waiting
                                        let _ = tx.send(response.body);
                                    }
                                },
                                Err(e) => {
                                    // Possibly a broadcast or push message with no request_id
                                    // handle it differently or log error
                                    error!("Failed to parse ResponseWrapper: {:?}", e);
                                }
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
            "who": username,
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
                let friend_session =  SessionKeys::new_with_keys(ek, dk, Some(im.associated_data));
                self.friends.insert(username.clone(), Friend::new(friend_session, pb.clone()));
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
}

struct ChatMessage {
    from: String,
    text: String,
    timestamp: DateTime<Utc>
}

impl ChatMessage {
    fn new(from: String, text: String, timestamp: DateTime<Utc>) -> Self {
        Self { from, text, timestamp }
    }
}

struct Friend {
    keys: SessionKeys,
    pb: PreKeyBundle,
    chat: Vec<ChatMessage>
}

impl Friend {
    fn new(keys: SessionKeys, pb: PreKeyBundle) -> Self {
        Self { keys, pb, chat: Vec::new() }
    }

    fn get_friend_bundle(&self) -> PreKeyBundle {
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


#[cfg(test)]
mod tests {
    use super::*;

}
