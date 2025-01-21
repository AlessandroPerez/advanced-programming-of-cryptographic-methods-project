use std::{collections::HashMap, fmt::Display, usize};
use arrayref::array_ref;
use base64::{Engine as _, engine:: general_purpose};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use log::{error, info};
use serde_json::{json, Value};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;
use protocol::{constants::AES256_NONCE_LENGTH, errors::X3DHError, utils::{AssociatedData, DecryptionKey, PreKeyBundle}};
use crate::errors::ServerError;

pub(crate) type Tx = mpsc::UnboundedSender<Message>;
pub(crate) type PeerMap = Arc<RwLock<HashMap<String, Peer>>>;
pub(crate) struct Peer {
    pub(crate) sender: Tx,
    pub(crate) pb: PreKeyBundle,
}

impl Peer {
    pub(crate) fn new(sender: Tx, pb: PreKeyBundle) -> Self {
        Self {
            sender,
            pb,
        }
    }

    pub(crate) fn send(&self, msg: Message) {
        self.sender.send(msg).unwrap();
    }

    pub(crate) fn get_bundle(&self) -> PreKeyBundle {
        self.pb.clone()
    }
}

pub(crate) enum ResponseCode {
    OK,
    ERROR(ServerError),
}

pub(crate) struct ServerResponse {
    code: ResponseCode,
    text: String,
}

impl ServerResponse {
    pub(crate) fn new(code: ResponseCode, text: String) -> Self {
        Self {
            code,
            text,
        }
    }
}

impl Display for ServerResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.code {
            ResponseCode::OK => write!(f, "{{\"code\": \"OK\", \"text\": \"{}\"}}", self.text),
            ResponseCode::ERROR(e) => write!(f, "{{\"code\": \"ERROR\", \"text\": \"{}. {}\"}}", e, self.text),
        }
    }
}

pub(crate) struct RegisterRequest {
    pub(crate) username: String,
    pub(crate) bundle: String,
}

pub(crate) struct  SendMessageRequest {
    from: String,
    pub(crate) to: String,
    text: String,
    timestamp: DateTime<Utc>
}

impl SendMessageRequest {
    pub(crate) fn to_json(&self) -> String {
        json!({
            "event": "chat message",
            "from": self.from,
            "to": self.to,
            "text": self.text,
            "timestamp": self.timestamp.to_rfc3339()
        }).to_string()
    }
}

pub(crate) enum RequestType<'a> {
    EncryptedRequest(&'a str),
    EstablishConnection(&'a str),
}

impl<'a> RequestType<'a> {
    pub(crate) fn from_json(request: &'a serde_json::Value) -> Option<Self> {
        match request.get("request_type") {
            None => None,
            Some(req) => {
                let req = req.as_str()?;
                match req {
                    "EstablishConnection" => {
                         Some(
                            Self::EstablishConnection(
                                request.get("bundle")?.as_str()?
                            )
                        )
                    },
                    _ => None
                }
            }
        }
    }

    pub(crate) fn from_str(req: &'a str) -> Option<Self> {
        Some(
            Self::EncryptedRequest(req)
        )
    }

    pub(crate) fn decrypt_request(req: &'a str, dk: &'a DecryptionKey) -> Result<(Action, AssociatedData), ServerError> {
        let enc_req = general_purpose::STANDARD.decode(req.to_string())?;
        let nonce = *array_ref!(enc_req, 0, AES256_NONCE_LENGTH);
        let aad = AssociatedData::try_from(array_ref!(enc_req, AES256_NONCE_LENGTH, AssociatedData::SIZE))?;
        let offset = AES256_NONCE_LENGTH + AssociatedData::SIZE; 
        let end = enc_req.len();
        let cipher_text = &enc_req[offset..end]; 
        let text = dk.decrypt(cipher_text, &nonce, &aad)?;
        info!("Decrypted request: {}", String::from_utf8(text.clone()).unwrap());
        let req = match String::from_utf8(text) {
            Ok(s) => serde_json::from_str::<Value>(&s),
            Err(e) => {
                error!("Failed to parse request: {}", e);
                return Err(ServerError::InvalidRequest);
            }
        };

        println!("Request: {:?}", &req);

        match Action::from_json(&req.unwrap()) {
            Some(action) => Ok((action, aad)),
            None => {
                error!("Failed to parse request");
                Err(ServerError::InvalidRequest)
            },
        }
    }
}
pub(crate) enum Action{
    Register(RegisterRequest),
    SendMessage(SendMessageRequest),
    GetPrekeyBundle(String),
}

impl Action{
    pub(crate) fn from_json(request: &serde_json::Value) -> Option<Self>{
        let action = request.get("action")?.as_str()?;
        match action {
            "register" => {
                Some(Self::Register(RegisterRequest {
                    username: request.get("username")?.to_string(),
                    bundle: request.get("bundle")?.to_string(),
                }))
            },

            "send_message" => {
                let timestamp: DateTime<Utc> = request.get("timestamp")?.as_str()?.parse().unwrap_or(Utc::now());
                Some(Self::SendMessage(SendMessageRequest {
                    from: request.get("from")?.to_string(),
                    to: request.get("to")?.to_string(),
                    text: request.get("text")?.to_string(),
                    timestamp
                }))
            },
            "get_prekey_bundle" => {
                let user = request.get("user")?.to_string();
                Some(Self::GetPrekeyBundle(user))
            },

            _ => None,
        }
    }
}
