#![allow(warnings)]
#[cfg(test)]
use base64::{engine::general_purpose, Engine};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};

use protocol::utils::PreKeyBundle;
use protocol::{utils::{AssociatedData, InitialMessage}, x3dh::{generate_prekey_bundle, process_initial_message}};

const URL: &str = "ws://127.0.0.1:3333";


#[tokio::test]
async fn test_secure_connection_establishment(){

    let (ws_stream, _) = tokio_tungstenite::connect_async(URL).await.expect("Failed to connect");
    let (mut write, mut read) = ws_stream.split();

    let (pb,_,_) = generate_prekey_bundle();
    // Send Register action
    let msg = json!({
        "request_type": "EstablishConnection",
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

#[tokio::test]
async fn test_registration() {
    let (ws_stream, _) = tokio_tungstenite::connect_async(URL).await.expect("Failed to connect");
    let (mut write, mut read) = ws_stream.split();

    let (pb, ik, spk) = generate_prekey_bundle();

    let msg = json!({
        "request_type": "EstablishConnection",
        "bundle": pb.clone().to_base64()
    });
    write.send(Message::Text(Utf8Bytes::from(msg.to_string()))).await.unwrap();

    println!("Secure connection established");

    let mut enc_k = None;
    let mut dec_k = None;

    // Wait for server response
    if let Some(Ok(Message::Text(response))) = StreamExt::next(&mut read).await {
        println!("recived initial msg: {}", response.to_string());
        let json_req: Value = serde_json::from_str::<Value>(&response.to_string()).unwrap();
        let initial_msg = json_req.get("text").unwrap().as_str().unwrap();
        let initial_msg = InitialMessage::try_from(initial_msg.to_string()).unwrap();
        match process_initial_message(ik, spk, None, initial_msg.clone() ){
            Ok((ek, dk)) => {
                enc_k = Some(ek);
                dec_k = Some(dk);
            } 
            Err(_) => panic!("Invalid Initial Message for server")
        } 
        let registration_req = json!({
            "action" : "register",
            "username" : "ciao",
            "bundle": pb.clone().to_base64()
        });

        let aad =  initial_msg.associated_data.clone();
        let req = registration_req.to_string().into_bytes();
        let nonce = b"Hello_World!";
        let enc_req = if let Some(ek) = enc_k {
            ek.encrypt(&req, &nonce, &aad).unwrap()
        } else {
            panic!("Not encryption key found!");
        };

        let enc_req = [nonce.to_vec(), aad.clone().to_bytes().to_vec(), enc_req.to_vec()].concat();

        let enc_req = general_purpose::STANDARD.encode(enc_req.as_slice());
        write.send(Message::Text(Utf8Bytes::from(enc_req))).await.expect("Failed to send message");

        if let Some(Ok(Message::Text(response))) = StreamExt::next(&mut read).await {
            println!("received registration response: {}", response.to_string());
            if let Some(dk) = dec_k {
                let nonce = b"123456789012";
                let response = general_purpose::STANDARD.decode(response.to_string()).unwrap();
                let response = dk.decrypt(response.as_slice(), &nonce, &aad).unwrap();
                println!("Decrypted: {}", String::from_utf8(response.clone()).unwrap());
            }
        } else {
            panic!("Did not receive registration response");
        }
    } else {
        panic!("Did not receive connection establishment acknowledgment");
    }



}

