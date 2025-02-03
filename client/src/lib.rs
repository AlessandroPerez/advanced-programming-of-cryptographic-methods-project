pub mod errors;

use std::{collections::HashMap, env::set_var, hash::Hash, process::exit};

use common::{ResponseCode, ServerResponse};
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
use tokio_tungstenite::{
    tungstenite::{Message, Utf8Bytes},
    MaybeTlsStream, WebSocketStream,
};
use protocol::utils::PublicKey;
use crate::errors::ClientError;

pub const SERVER_URL: &str = "ws://127.0.0.1:3333";
pub const SERVER_IK: &str = "KidEmuJzis1xt3+XwkzEBx4rB8hjuEvHK0LV0vY5aE8=";
type Sender = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type Receiver = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;


pub struct Client {
    friends: HashMap<String, Friend>,
    session: SessionKeys,
    write: Sender,
    read: Receiver,
    username: String,
    bundle: PreKeyBundle,
    identity_key: PrivateKey,
    signed_prekey: PrivateKey,
    one_time_prekey: Vec<PrivateKey>
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
            read,
            username,
            bundle,
            identity_key: ik,
            signed_prekey: spk,
            one_time_prekey: otpk
        };
        client.establish_connection().await?;
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

        // Wait for server response
        if let Some(Ok(Message::Text(initial_msg))) = StreamExt::next(&mut self.read).await {
            if let Ok(resp) = ServerResponse::try_from(
                serde_json::from_str::<Value>(initial_msg.as_str()).unwrap_or(Value::Null),
            ) {
                let mut im = resp.text;
                info!("im: {}", &im);
                im.retain(|c| !c.eq(&("\"".parse::<char>().unwrap())));
                let initial_message = InitialMessage::try_from(im)?;
                let (ek, dk) = process_server_initial_message(
                    self.identity_key.clone(),
                    self.signed_prekey.clone(),
                    Some(self.one_time_prekey.remove(0)),
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

    pub async fn register_user(&mut self) -> Result<(), ClientError> {
        let req = json!({
            "action" : "register",
            "username" : self.username.clone(),
            "bundle": self.bundle.clone().to_base64()
        });

        let enc_req = self.session
            .get_encryption_key()
            .unwrap()
            .encrypt(
                req.to_string().as_ref(),
                &self.session.get_associated_data().unwrap(),
            )
            .expect("Failed to encrypt request");

        self.write
            .send(Message::Text(Utf8Bytes::from(enc_req)))
            .await
            .expect("Failed to send message");

        if let Some(Ok(Message::Text(response))) = StreamExt::next(&mut self.read).await {
            match decrypt_server_request(response.to_string(), &self.session.get_decryption_key().unwrap()) {
                Ok((res, _)) => {

                    match ServerResponse::try_from(res)?.code {
                        ResponseCode::Ok => Ok(()),
                        _ => Err(ClientError::UserAlreadyExistsError)
                    }
                },
                Err(_) => Err(ClientError::ServerResponseError),
            }
        } else {
            panic!("Did not receive connection establishment acknowledgment");
        }
    }

    pub fn set_username(&mut self, username: String) {
        self.username = username;
    }
}
struct Friend {
    keys: SessionKeys,
    pb: PreKeyBundle,
    im: InitialMessage,
}

impl Friend {
    fn new(keys: SessionKeys, pb: PreKeyBundle, im: InitialMessage) -> Self {
        Self { keys, pb, im }
    }

    fn get_friend_bundle(&self) -> PreKeyBundle {
        self.pb.clone()
    }

    fn get_friend_keys(&self) -> SessionKeys {
        self.keys.clone()
    }
}

fn decrypt_server_request(req: String, dk: &DecryptionKey) -> Result<(Value, AssociatedData), ()> {
    common::decrypt_request(&req, dk)
}

fn prompt(text: &str) -> String {
    print!("{} ", text);

    let mut response = String::new();
    std::io::stdin()
        .read_line(&mut response)
        .expect("Failed to get input");

    response.trim_end().to_string()
}



async fn get_user_prekey_bundle(
    dk: &DecryptionKey,
    username: &str,
    write: &mut Sender,
    read: &mut Receiver,
    session: &mut SessionKeys,
) -> Result<ServerResponse, ()> {
    let req = json!({
        "action": "get_prekey_bundle",
        "who": username,
    });
    let enc = session
        .get_encryption_key()
        .unwrap()
        .encrypt(
            req.to_string().as_bytes(),
            &session.get_associated_data().unwrap(),
        )
        .expect("Failed to encrypt request");

    write
        .send(Message::Text(Utf8Bytes::from(enc)))
        .await
        .expect("Failed to send request.");

    if let Some(Ok(Message::Text(response))) = StreamExt::next(read).await {
        match decrypt_server_request(response.to_string(), dk) {
            Ok((r, _aad)) => Ok(ServerResponse::try_from(r)?),
            Err(_) => Err(()),
        }
    } else {
        panic!("Did not received any request.")
    }
}



async fn send_message(
    to: &str,
    session: &mut SessionKeys,
    text: &str,
    write: &mut Sender,
    read: &mut Receiver,
) {
}

#[cfg(test)]
mod tests {
    use super::*;

}
