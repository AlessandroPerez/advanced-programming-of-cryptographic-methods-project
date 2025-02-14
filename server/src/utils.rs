use crate::errors::ServerError;
use common::{RegisterRequest, RequestWrapper, SendMessageRequest};
use log::error;
use protocol::utils::{DecryptionKey, PreKeyBundle};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;

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
        let mut old_bundle = self.pb.clone();

        // We need at least one key in 'otpk' to split
        let last_key = old_bundle.otpk.pop();

        // Build a new PreKeyBundle that just contains the last key in its 'otpk'
        let new_bundle_with_last = PreKeyBundle {
            verifying_key: old_bundle.verifying_key.clone(),
            ik: old_bundle.ik.clone(),
            spk: old_bundle.spk.clone(),
            sig: old_bundle.sig.clone(),
            otpk: if last_key.is_some() {
                vec![last_key.unwrap()]
            } else {
                vec![]
            },
        };

        // Now update the *peer's* bundle (remove last key from its 'otpk').
        // old_bundle no longer has the last key, because we popped it above.
        self.pb = old_bundle;
        new_bundle_with_last
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
                    "establish_connection" => Some(Self(request.get("bundle")?.as_str()?)),
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


    if let Ok(req) = serde_json::from_str::<RequestWrapper>(&decrypted.to_string()) {
        let id = req.request_id;
        let body = req.body;
        match Action::from_json(&body) {
            Some(action) => Ok((action, id.to_string())),
            None => {
                error!("Failed to parse request");
                Err(ServerError::InvalidRequest)
            }
        }
    } else  {
        match Action::from_json(&decrypted) {
            None => Err(ServerError::InvalidRequest),
            Some(action) => {
                Ok((action, String::new()))
            }
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
                username: request.get("username")?.as_str()?.to_string(),
                bundle: request.get("bundle")?.as_str()?.to_string(),
            })),

            "send_message" => {
                let timestamp = request
                    .get("timestamp")?
                    .as_str()?
                    .to_string();
                Some(Self::SendMessage(SendMessageRequest {
                    msg_type: request.get("msg_type")?.as_str()?.to_string(),
                    from: request.get("from")?.as_str()?.to_string(),
                    to: request.get("to")?.as_str()?.to_string(),
                    text: request.get("text")?.as_str()?.to_string(),
                    timestamp,
                }))
            }
            "get_prekey_bundle" => {
                let user = request.get("who")?.as_str()?.to_string();
                Some(Self::GetPrekeyBundle(user))
            }

            _ => None,
        }
    }
}
