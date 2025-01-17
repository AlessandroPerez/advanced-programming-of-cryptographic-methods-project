use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};
#[cfg(tests)]

use protocol::utils::PreKeyBundle;
use protocol::x3dh::generate_prekey_bundle;

#[tokio::test]
async fn test_secure_connection_establishment(){

    let url = "ws://127.0.0.1:3333";
    let (ws_stream, _) = tokio_tungstenite::connect_async(url).await.expect("Failed to connect");
    let (mut write, mut read) = ws_stream.split();

    let (pb,_,_) = generate_prekey_bundle();
    // Send Register action
    let msg = json!({
        "request_type": "establish_connection",
        "bundle": &format!("{}", pb.to_base64())
    });
    write.send(Message::Text(Utf8Bytes::from(msg.to_string()))).await.unwrap();


    // Wait for server response
    if let Some(Ok(Message::Text(text))) = StreamExt::next(&mut read).await {
        println!("{}", text.to_string());
    } else {
        panic!("Did not receive connection establishment acknowledgment");
    }

}

