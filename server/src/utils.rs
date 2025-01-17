use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;
use protocol::utils::{DecryptionKey, EncryptionKey, PreKeyBundle};
use crate::errors::ServerError;

type Tx = mpsc::UnboundedSender<Message>;
pub(crate) type PeerMap = Arc<RwLock<HashMap<String, Peer>>>;
pub(crate) struct Peer {
    sender: Tx,
    encryption_key: Option<EncryptionKey>,
    decryption_key: Option<DecryptionKey>,
    pb: Option<PreKeyBundle>,
    online: bool
}

impl Peer {
    pub(crate) fn new(sender: Tx, ek: EncryptionKey, dk: DecryptionKey, pb: PreKeyBundle) -> Self {
        Self {
            sender,
            encryption_key: Some(ek),
            decryption_key: Some(dk),
            pb: Some(pb),
            online: true
        }
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

    pub(crate) fn to_string(&self) -> String {
        match &self.code {
            ResponseCode::OK => format!("{{\"code\": \"OK\", \"text\": \"{}\"}}", self.text),
            ResponseCode::ERROR(e) => format!("{{\"error\": \"{}\", \"text\": \"{}\"}}", e, self.text),
        }
    }
}



pub(crate) struct RegisterRequest<'a> {
    username: &'a str,
    password: &'a str
}

pub(crate) struct  SendMessageRequest<'a> {
    from: &'a str,
    to: &'a str,
    timestamp: DateTime<Utc>
}


pub(crate) enum RequestType <'a>{
    EstablishConnection(&'a str),
    Register(RegisterRequest<'a>),
    SendMessage(SendMessageRequest<'a>),
    GetPrekeyBundle(&'a str)
}

impl<'a> RequestType<'a> {
    pub(crate) fn from_json(request: &'a serde_json::Value) -> Option<Self>{
        let request_type = request.get("request_type")?.as_str()?;
        match request_type {
            "establish_connection" => {
                return Some(Self::EstablishConnection(request.get("bundle")?.as_str()?))
            },
            "register" => {
                return Some(Self::Register(RegisterRequest {
                    username: request.get("username")?.as_str()?,
                    password: request.get("password")?.as_str()?
                }))
            },

            "send_message" => {
                let timestamp: DateTime<Utc> = request.get("timestamp")?.as_str()?.parse().unwrap_or(Utc::now());
                return Some(Self::SendMessage(SendMessageRequest {
                    from: request.get("from")?.as_str()?,
                    to: request.get("to")?.as_str()?,
                    timestamp
                }))
            },
            "get_prekey_bundle" => {
                let user = request.get("user")?.as_str()?;
                return Some(Self::GetPrekeyBundle(user))
            },

            _ => None,
        }
    }
}
