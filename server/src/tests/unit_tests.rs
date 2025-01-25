#![allow(warnings)]

use arrayref::array_ref;
#[cfg(test)]
use base64::{engine::general_purpose, Engine};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};

use protocol::utils::PreKeyBundle;
use protocol::{utils::{AssociatedData, InitialMessage}, x3dh::{generate_prekey_bundle, process_initial_message}};
use protocol::constants::AES256_NONCE_LENGTH;

const URL: &str = "ws://127.0.0.1:3333";


#[tokio::test]
async fn test_secure_connection_establishment(){

    let (ws_stream, _) = tokio_tungstenite::connect_async(URL).await.expect("Failed to connect");
    let (mut write, mut read) = ws_stream.split();

    let (pb,_,_) = generate_prekey_bundle();
    // Send Register action
    let msg = json!({
        "request_type": "EstablishConnection",
        "bundle": pb.clone().to_base64()
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
        println!("received initial msg: {}", response.to_string());
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
            "username" : "Luc",
            "bundle": pb.clone().to_base64()
        });

        println!("bundle: {}", pb.clone().to_base64());

        let aad =  initial_msg.associated_data.clone();
        let req = registration_req.to_string().into_bytes();
        let enc_req = if let Some(ek) = enc_k {
            ek.encrypt(&req, &aad).unwrap()
        } else {
            panic!("Not encryption key found!");
        };

        write.send(Message::Text(Utf8Bytes::from(enc_req))).await.expect("Failed to send message");

        if let Some(Ok(Message::Text(response))) = StreamExt::next(&mut read).await {
            println!("received registration response: {}", response.to_string());
            if let Some(dk) = dec_k {

                let r = general_purpose::STANDARD.decode(response.to_string()).unwrap();
                let end = r.len();
                let offset = AES256_NONCE_LENGTH + AssociatedData::SIZE;
                let nonce = *array_ref!(r, 0, AES256_NONCE_LENGTH);
                let aad = AssociatedData::try_from(array_ref!(r, AES256_NONCE_LENGTH, AssociatedData::SIZE)).expect("Failed to parse associated data");
                let enc_response = &r[offset..end];
                let response = dk.decrypt(enc_response, &nonce, &aad).expect("Failed to decrypt response");
                println!("Decrypted: {}", String::from_utf8(response).unwrap());
            }
        } else {
            panic!("Did not receive registration response");
        }
    } else {
        panic!("Did not receive connection establishment acknowledgment");
    }

    // write.close().await.expect("Failed to close connection");
}

#[tokio::test]
async fn test_get_bundle() {
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
        println!("received initial msg: {}", response.to_string());
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
            "username" : "Lucio",
            "bundle": pb.clone().to_base64()
        });

        let aad =  initial_msg.associated_data.clone();
        let req = registration_req.to_string().into_bytes();
        let enc_req = if let Some(ek) = enc_k.clone() {
            ek.encrypt(&req, &aad).unwrap()
        } else {
            panic!("Not encryption key found!");
        };

        write.send(Message::Text(Utf8Bytes::from(enc_req))).await.expect("Failed to send message");

        if let Some(Ok(Message::Text(response))) = StreamExt::next(&mut read).await {
            println!("received registration response: {}", response.to_string());
            if let Some(dk) = dec_k.clone() {

                let r = general_purpose::STANDARD.decode(response.to_string()).unwrap();
                let end = r.len();
                let offset = AES256_NONCE_LENGTH + AssociatedData::SIZE;
                let nonce = *array_ref!(r, 0, AES256_NONCE_LENGTH);
                let aad = AssociatedData::try_from(array_ref!(r, AES256_NONCE_LENGTH, AssociatedData::SIZE)).expect("Failed to parse associated data");
                let enc_response = &r[offset..end];
                let response = dk.decrypt(enc_response, &nonce, &aad).expect("Failed to decrypt response");
                println!("Decrypted: {}", String::from_utf8(response).unwrap());
            }

            let req = json!({
                "action" : "get_prekey_bundle",
                "user" : "Luc"
            });

            let enc_req = if let Some(ek) = enc_k {
                ek.encrypt(&req.to_string().into_bytes(), &aad).unwrap()
            } else {
                panic!("Not encryption key found!");
            };

            write.send(Message::Text(Utf8Bytes::from(enc_req))).await.expect("Failed to send message");

            if let Some(Ok(Message::Text(response))) = StreamExt::next(&mut read).await {
                println!("Received bundle response: {}", response.to_string());
                if let Some(dk) = dec_k.clone() {
                    let r = general_purpose::STANDARD.decode(response.to_string()).unwrap();

                    let end = r.len();
                    let offset = AES256_NONCE_LENGTH + AssociatedData::SIZE;
                    let nonce = *array_ref!(r, 0, AES256_NONCE_LENGTH);
                    let aad = AssociatedData::try_from(array_ref!(r, AES256_NONCE_LENGTH, AssociatedData::SIZE)).expect("Failed to parse associated data");
                    let enc_response = &r[offset..end];
                    let response = dk.decrypt(enc_response, &nonce, &aad).expect("Failed to decrypt response");
                    let pb_string = String::from_utf8(response).unwrap();
                    let json = serde_json::from_str::<Value>(&pb_string).expect("Failed to parse json");
                    println!("json: {:?}", json);
                    let mut pb_string = json.get("text").expect("Failed to get bundle").to_string();
                    println!("bundle with quotes: {}", &pb_string);
                    pb_string.retain(|c| !c.eq(&("\"".parse::<char>().unwrap())));
                    println!("bundle: {}", &pb_string);
                    let pb = PreKeyBundle::try_from(pb_string).expect("Failed to parse prekey bundle");
                    println!("bundle: {}", pb.clone().to_base64());
                }
            }
        } else {
            panic!("Did not receive registration response");
        }
    } else {
        panic!("Did not receive connection establishment acknowledgment");
    }



}

