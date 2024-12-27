use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use warp::Filter;

#[derive(Clone)]
struct ServerState {
    user_data: Arc<Mutex<HashMap<String, KeyBundle>>>,
}

#[derive(Debug, Clone)]
struct KeyBundle {
    identity_key: [u8; 32],
    signed_prekey: [u8; 32],
    signature: [u8; 64],
    one_time_prekey: [u8; 32],
}

#[tokio::main]
async fn main() {
    let state = ServerState {
        user_data: Arc::new(Mutex::new(HashMap::new())),
    };
    let state_filter = warp::any().map(move || state.clone());

    let register = warp::post()
        .and(warp::path("register"))
        .and(warp::body::json())
        .and(state_filter)
        .and_then(register_handler);

    warp::serve(register).run(([127, 0, 0, 1], 1337)).await;
}

async fn register_handler(
    data: serde_json::Value,
    state: ServerState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let username = data["username"].as_str().unwrap();
    let bundle = KeyBundle {
        identity_key: data["identity_key"].as_array().unwrap().clone().try_into()?,
        signed_prekey: data["signed_prekey"].as_array().unwrap().clone().try_into()?,
        signature: data["signature"].as_array().unwrap().clone().try_into()?,
        one_time_prekey: data["one_time_prekey"].as_array().unwrap().clone().try_into()?,
    };

    state
        .user_data
        .lock()
        .unwrap()
        .insert(username.to_string(), bundle);

    Ok(warp::reply::json(&serde_json::json!({"status": "ok"})))
}
