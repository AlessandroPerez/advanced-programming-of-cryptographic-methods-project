use crate::errors::ServerError;
use chrono::{DateTime, Utc};
use common::{RegisterRequest, RequestWrapper, ResponseWrapper, SendMessageRequest};
use log::error;
use protocol::utils::{AssociatedData, DecryptionKey, PreKeyBundle};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

pub(crate) type Tx = mpsc::UnboundedSender<Message>;
pub(crate) type PeerMap = Arc<RwLock<HashMap<String, Peer>>>;

#[derive(Debug, Clone)]
pub(crate) struct Peer {
    pub(crate) sender: Tx,
    pub(crate) pb: PreKeyBundle,
}

impl Peer {
    pub(crate) fn new(sender: Tx, pb: PreKeyBundle) -> Self {
        Self { sender, pb }
    }

    pub(crate) fn get_bundle(&mut self) -> PreKeyBundle {
        let otpk = self.pb.otpk.pop();
        let mut pb = self.pb.clone();
        pb.otpk = vec![otpk.unwrap()];
        pb
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
) -> Result<(Action, String), ServerError> {
    let decrypted = match common::decrypt_request(req, dk) {
        Ok((dec, _ )) => dec,
        Err(_) => return Err(ServerError::InvalidRequest),
    };


    let (id, req )= match serde_json::from_str::<RequestWrapper>(&decrypted.to_string()){
        Ok(request) => {
            (request.request_id, request.body)
        }
        Err(_) => return Err(ServerError::InvalidRequest)
    };

    match Action::from_json(&req) {
        Some(action) => Ok((action, id.to_string())),
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
    // TODO: BUG: This function is not working as expected, the char " is being added to the string
    //      when it is parsed from the json but server does not work without it
    pub(crate) fn from_json(request: &serde_json::Value) -> Option<Self> {
        let action = request.get("action")?.as_str()?;
        match action {
            "register" => Some(Self::Register(RegisterRequest {
                username: request.get("username")?.as_str()?.to_string(),
                bundle: request.get("bundle")?.as_str()?.to_string(),
            })),

            "send_message" => {
                let timestamp: DateTime<Utc> = request
                    .get("timestamp")?
                    .as_str()?
                    .parse()
                    .unwrap_or(Utc::now());
                Some(Self::SendMessage(SendMessageRequest {
                    msg_type: request.get("type")?.as_str()?.to_string(),
                    from: request.get("from")?.as_str()?.to_string(),
                    to: request.get("to")?.as_str()?.to_string(),
                    text: request.get("text")?.as_str()?.to_string(),
                    timestamp,
                }))
            }
            "get_prekey_bundle" => {
                // TODO: understand why this is not working
                let user = request.get("who")?.as_str()?.to_string();
                // let user = request.get("who")?.to_string();
                Some(Self::GetPrekeyBundle(user))
            }

            _ => None,
        }
    }
}
