use std::path::Path;
use warp::Filter;
use crate::server::handlers::{register_handler};
use crate::server::state::ServerState;

pub async fn start_server() {
    let state = ServerState::new();

    let state_filter = warp::any().map(move || state.clone());

    let register = warp::post()
        .and(warp::path("register"))
        .and(warp::body::json())
        .and(state_filter)
        .and_then(register_handler);

    // Example route
    let hello = warp::path("hello")
        .and(warp::get())
        .map(|| warp::reply::html("Hello, secure world!"));

    let routes = hello.or(register);

    let parent_dir = env!("CARGO_MANIFEST_DIR");
    let cert_path = Path::new(&parent_dir).join("certs/cert.pem");
    let key_path = Path::new(&parent_dir).join("certs/key.rsa");

    warp::serve(routes)
        .tls()
        .cert_path(cert_path)
        .key_path(key_path)
        .run(([127, 0, 0, 1], 3030))
        .await;
}







