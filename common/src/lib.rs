use arrayref::array_ref;
use base64::write;
use base64::{engine::general_purpose, Engine as _};
use chrono::DateTime;
use chrono::Utc;
use log::{error, info};
use protocol::{
    constants::AES256_NONCE_LENGTH,
    utils::{AssociatedData, DecryptionKey},
};
use serde_json::{json, Value};
use std::fmt::Display;
use serde::{Serialize, Deserialize};
use serde::de::Error;
use uuid::Uuid;

pub fn decrypt_request(req: &str, dk: &DecryptionKey) -> Result<(Value, AssociatedData), ()> {
    let enc_req = match general_purpose::STANDARD.decode(req.to_string()) {
        Ok(s) => s,
        Err(_e) => {
            error!("Failed to decode request");
            return Err(());
        }
    };
    let nonce = *array_ref!(enc_req, 0, AES256_NONCE_LENGTH);
    let aad = match AssociatedData::try_from(array_ref!(
        enc_req,
        AES256_NONCE_LENGTH,
        AssociatedData::SIZE
    )) {
        Ok(aad) => aad,
        Err(_) => return Err(()),
    };
    let offset = AES256_NONCE_LENGTH + AssociatedData::SIZE;
    let end = enc_req.len();
    let cipher_text = &enc_req[offset..end];
    let text = match dk.decrypt(cipher_text, &nonce, &aad) {
        Ok(dec) => dec,
        Err(_) => return Err(()),
    };

    info!(
        "Decrypted request: {}",
        String::from_utf8(text.clone()).unwrap()
    );
    match String::from_utf8(text) {
        Ok(s) => Ok((
            serde_json::from_str::<Value>(&s).unwrap_or(Value::Null),
            aad,
        )),
        Err(e) => {
            error!("Failed to parse request: {}", e);
            Err(())
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RequestWrapper {
    pub request_id: String,
    pub body: serde_json::Value,
}


/// Server -> Client
#[derive(Serialize, Deserialize)]
pub struct ResponseWrapper {
    pub request_id: String,
    pub body: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub enum ResponseCode {
    Ok,
    BadRequest,
    NotFound,
    InternalServerError,
    Conflict,
}

impl Display for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseCode::Ok => write!(f, "200"),
            ResponseCode::BadRequest => write!(f, "400"),
            ResponseCode::NotFound => write!(f, "404"),
            ResponseCode::InternalServerError => write!(f, "500"),
            ResponseCode::Conflict => write!(f, "409"),
        }
    }
}


impl TryFrom<&str> for ResponseCode {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, ()> {
        match value {
            "200" => Ok(Self::Ok),
            "400" => Ok(Self::BadRequest),
            "404" => Ok(Self::NotFound),
            "500" => Ok(Self::InternalServerError),
            "409" => Ok(Self::Conflict),
            _ => Err(()),
        }
    }
}
#[derive(Serialize, Deserialize)]
pub struct ServerResponse {
    pub code: ResponseCode,
    pub text: String,
}

impl ServerResponse {
    pub fn new(code: ResponseCode, text: String) -> Self {
        Self { code, text }
    }

    pub fn from_json(value: String) -> Option<Self>{
        let value = serde_json::from_str::<Value>(&value).ok()?;
        let code = value.get("code")?.as_str()?;
        let text = value.get("message")?.as_str()?;
        let code = ResponseCode::try_from(code).ok()?;
        Some(Self::new(code, text.to_string()))
    }
}


impl Display for ServerResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let res = json!({
            "code": self.code.to_string(),
            "message": self.text
        })
        .to_string();

        write!(f, "{}", res)
    }
}

pub struct RegisterRequest {
    pub username: String,
    pub bundle: String,
}

pub struct SendMessageRequest {
    pub msg_type: String,
    pub from: String,
    pub to: String,
    pub text: String,
    pub timestamp: DateTime<Utc>,
}

impl SendMessageRequest {
    pub fn to_json(&self) -> String {
        json!({
            "type": self.msg_type,
            "from": self.from,
            "to": self.to,
            "text": self.text,
            "timestamp": self.timestamp.to_rfc3339()
        })
        .to_string()
    }
}
