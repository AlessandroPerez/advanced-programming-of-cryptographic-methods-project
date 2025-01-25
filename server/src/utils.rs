use crate::errors::ServerError;
use chrono::{DateTime, Utc};
use common::{RegisterRequest, SendMessageRequest};
use log::error;
use protocol::utils::{AssociatedData, DecryptionKey, PreKeyBundle};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;

pub(crate) type Tx = mpsc::UnboundedSender<Message>;
pub(crate) type PeerMap = Arc<RwLock<HashMap<String, Peer>>>;
pub(crate) struct Peer {
    pub(crate) sender: Tx,
    pub(crate) pb: PreKeyBundle,
}

impl Peer {
    pub(crate) fn new(sender: Tx, pb: PreKeyBundle) -> Self {
        Self { sender, pb }
    }

    pub(crate) fn get_bundle(&self) -> PreKeyBundle {
        self.pb.clone()
    }
}

pub(crate) struct EstablishConnection<'a>(pub &'a str);

impl<'a> EstablishConnection<'a> {
    pub(crate) fn from_json(request: &'a serde_json::Value) -> Option<Self> {
        match request.get("request_type") {
            None => None,
            Some(req) => {
                let req = req.as_str()?;
                match req {
                    "EstablishConnection" => Some(Self(request.get("bundle")?.as_str()?)),
                    _ => None,
                }
            }
        }
    }
}

pub(crate) fn decrypt_client_request(
    req: &str,
    dk: &DecryptionKey,
) -> Result<(Action, AssociatedData), ServerError> {
    let (req, aad) = match common::decrypt_request(req, dk) {
        Ok(dec) => dec,
        Err(_) => return Err(ServerError::InvalidRequest),
    };

    match Action::from_json(&req) {
        Some(action) => Ok((action, aad)),
        None => {
            error!("Failed to parse request");
            Err(ServerError::InvalidRequest)
        }
    }
}

pub(crate) enum Action {
    Register(RegisterRequest),
    SendMessage(SendMessageRequest),
    GetPrekeyBundle(String),
}

impl Action {
    pub(crate) fn from_json(request: &serde_json::Value) -> Option<Self> {
        let action = request.get("action")?.as_str()?;
        match action {
            "register" => Some(Self::Register(RegisterRequest {
                username: request.get("username")?.to_string(),
                bundle: request.get("bundle")?.to_string(),
            })),

            "send_message" => {
                let timestamp: DateTime<Utc> = request
                    .get("timestamp")?
                    .as_str()?
                    .parse()
                    .unwrap_or(Utc::now());
                Some(Self::SendMessage(SendMessageRequest {
                    msg_type: request.get("type")?.to_string(),
                    from: request.get("from")?.to_string(),
                    to: request.get("to")?.to_string(),
                    text: request.get("text")?.to_string(),
                    timestamp,
                }))
            }
            "get_prekey_bundle" => {
                let user = request.get("user")?.to_string();
                Some(Self::GetPrekeyBundle(user))
            }

            _ => None,
        }
    }
}
