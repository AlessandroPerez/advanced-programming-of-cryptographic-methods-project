use bcrypt::{hash, DEFAULT_COST};
use serde::Serialize;
use crate::server::utils::{parse_key_array, parse_key_array64, DeserializationError};
use crate::server::state::KeyBundle;
use crate::server::state::ServerState;
use crate::server::utils::User;


#[derive(Serialize)]
struct RegistrationResponse {
    status: String,
    message: String,
}

pub async fn register_handler(
    data: serde_json::Value,
    state: ServerState,
) -> Result<impl warp::Reply, warp::Rejection> {

    let username = data["username"]
        .as_str()
        .ok_or_else(|| warp::reject::custom(DeserializationError))?;

    if state.get_user(username).is_some() {
        return Ok(warp::reply::json(&RegistrationResponse {
            status: "error".to_string(),
            message: "Username already exists.".to_string(),
        }));
    }

    let password = data["password"]
        .as_str()
        .ok_or_else(|| warp::reject::custom(DeserializationError))?;

    let password = hash(password, DEFAULT_COST).unwrap();

    let bundle = KeyBundle::new(
        parse_key_array(&data["identity_key"])?,
        parse_key_array(&data["signed_prekey"])?,
        parse_key_array64(&data["signature"])?,
        parse_key_array(&data["one_time_prekey"])?,
    );

    state
        .insert_user(
            username.to_string(),
            User::new(
                username.to_string(),
                password,
                bundle
            )
        );

    println!("Registered user: {}", username);
    Ok(warp::reply::json(&RegistrationResponse {
        status: "success".to_string(),
        message: "User registered successfully.".to_string(),
    }))
}