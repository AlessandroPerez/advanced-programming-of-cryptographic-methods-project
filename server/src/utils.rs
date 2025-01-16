use std::collections::HashMap;
use std::sync::Arc;
use env_logger::Target;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;
use protocol::utils::{DecryptionKey, EncryptionKey, PreKeyBundle};
use crate::errors::ServerError;

type Tx = mpsc::UnboundedSender<Message>;
pub(crate) type PeerMap<'a> = Arc<RwLock<HashMap<&'a str, Peer<'a>>>>;
pub(crate) struct Peer<'a> {
    id: &'a str,
    sender: Tx,
    encryption_key: Option<EncryptionKey>,
    decryption_key: Option<DecryptionKey>,
    pb: Option<PreKeyBundle>,
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
            ResponseCode::ERROR(e) => format!("{{\"code\": \"ERROR\", \"text\": \"{}\"}}", e),
        }
    }
}

pub(crate) enum Action {
    EstablishConnection,
    Register,
    SendMessage,
    GetPrekeyBundle,
}

impl Action {
    pub(crate) fn from_str(action: &str) -> Option<Self> {
        match action {
            "establish_connection" => Some(Self::EstablishConnection),
            "send_message" => Some(Self::SendMessage),
            "get_prekey_bundle" => Some(Self::GetPrekeyBundle),
            "register" => Some(Self::Register),
            _ => None
        }
    }
}

pub(crate) struct Request {
    pub(crate) action: Action,
    pub(crate) text: String,
    pub(crate) target: String,
}

impl Request {
    pub(crate) fn new(action: Action, text: String, target: String) -> Self {
        Self {
            action,
            text,
            target,
        }
    }

    pub(crate) fn from_json(json: &serde_json::Value) -> Option<Self> {
        let action = json.get("action")?.as_str()?;
        let action = Action::from_str(action)?;
        let target = json.get("target")?.as_str()?.to_string();
        let text = json.get("text")?.as_str()?.to_string();
        Some(Self {
            action,
            text,
            target,
        })
    }
}