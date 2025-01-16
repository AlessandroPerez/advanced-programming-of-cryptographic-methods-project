use std::collections::HashMap;
use std::sync::Arc;
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
            _ => None
        }
    }
}