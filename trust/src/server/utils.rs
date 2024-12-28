use crate::server::state::KeyBundle;
use warp::{reply, Reply, reject, Rejection, http::StatusCode};

#[derive(Clone)]
pub struct User {
    username: String,
    password: String,
    key_bundle: KeyBundle
}
impl User {
    pub fn new(username: String, password: String, key_bundle: KeyBundle) -> Self {
        Self {
            username,
            password,
            key_bundle
        }
    }
    pub fn get_username(&self) -> String {
        self.username.clone()
    }

    pub fn get_password(&self) -> String {
        self.password.clone()
    }

    pub fn get_key_bundle(&self) -> KeyBundle {
        self.key_bundle.clone()
    }

}
/// Helper function to parse a `[u8; 32]` from a JSON array
pub fn parse_key_array(value: &serde_json::Value) -> Result<[u8; 32], warp::Rejection> {
    let array = value
        .as_array()
        .ok_or_else(|| warp::reject::custom(DeserializationError))?;

    if array.len() != 32 {
        return Err(warp::reject::custom(DeserializationError));
    }

    let mut result = [0u8; 32];
    for (i, v) in array.iter().enumerate() {
        result[i] = v.as_u64().ok_or_else(|| warp::reject::custom(DeserializationError))? as u8;
    }
    Ok(result)
}

/// Helper function to parse a `[u8; 64]` from a JSON array
pub fn parse_key_array64(value: &serde_json::Value) -> Result<[u8; 64], warp::Rejection> {
    let array = value
        .as_array()
        .ok_or_else(|| warp::reject::custom(DeserializationError))?;

    if array.len() != 64 {
        return Err(warp::reject::custom(DeserializationError));
    }

    let mut result = [0u8; 64];
    for (i, v) in array.iter().enumerate() {
        result[i] = v.as_u64()
            .ok_or_else(|| warp::reject::custom(DeserializationError))? as u8;
    }
    Ok(result)
}

/// Custom error type for better rejections
#[derive(Debug)]
pub struct DeserializationError;

impl reject::Reject for DeserializationError {}

#[derive(Debug)]
pub struct InvalidParameter;
impl reject::Reject for InvalidParameter {}

#[derive(Debug)]
pub struct UserNotFound;
impl reject::Reject for UserNotFound {}

#[derive(Debug)]
pub struct UserAlreadyExists;
impl reject::Reject for UserAlreadyExists {}

pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Rejection> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "Not Found";
    } else if let Some(DeserializationError) = err.find() {
        code = StatusCode::BAD_REQUEST;
        message = "Invalid JSON";
    } else if let Some(InvalidParameter) = err.find() {
        code = StatusCode::BAD_REQUEST;
        message = "Invalid parameter";
    } else if let Some(UserNotFound) = err.find() {
        code = StatusCode::NOT_FOUND;
        message = "User not found";
    } else if let Some(UserAlreadyExists) = err.find() {
        code = StatusCode::CONFLICT;
        message = "User already exists";
    } else {
        eprintln!("unhandled rejection: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error";
    }

    Ok(reply::with_status(reply::json(&message), code))
}




