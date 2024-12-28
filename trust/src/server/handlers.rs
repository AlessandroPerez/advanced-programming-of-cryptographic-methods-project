use crate::server::utils::{parse_key_array, parse_key_array64, DeserializationError};
use crate::server::state::KeyBundle;
use crate::server::state::ServerState;

pub async fn register_handler(
    data: serde_json::Value,
    state: ServerState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let username = data["username"]
        .as_str()
        .ok_or_else(|| warp::reject::custom(DeserializationError))?; // Custom rejection for better error handling

    let identity_key = parse_key_array(&data["identity_key"])?;
    let signed_prekey = parse_key_array(&data["signed_prekey"])?;
    let signature = parse_key_array64(&data["signature"])?;
    let one_time_prekey = parse_key_array(&data["one_time_prekey"])?;

    let bundle = KeyBundle {
        identity_key,
        signed_prekey,
        signature,
        one_time_prekey,
    };

    if state.get_user(username).is_some() {
        return Ok(warp::reply::json(&serde_json::json!({"status": "error", "message": "User already exists"})));
    }

    state.insert_user(username.to_string(), bundle);

    println!("Registered user: {}", username);
    Ok(warp::reply::json(&serde_json::json!({"status": "ok"})))
}