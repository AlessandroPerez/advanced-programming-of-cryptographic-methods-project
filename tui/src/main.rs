use arrayref::array_ref;
use base64::engine::general_purpose;
use base64::Engine;
use common::ServerResponse;
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use log::error;
use protocol::constants::AES256_NONCE_LENGTH;
use protocol::utils::{
    AssociatedData, DecryptionKey, EncryptionKey, InitialMessage, PreKeyBundle, PrivateKey,
    SessionKeys,
};
use protocol::x3dh::{generate_prekey_bundle, process_initial_message};
use serde_json::{json, Value};
use tokio::{net::TcpStream, sync::broadcast::error};
use tokio_tungstenite::{
    tungstenite::{Message, Utf8Bytes},
    MaybeTlsStream, WebSocketStream,
};

const SERVER_URL: &str = "ws://127.0.0.1:3333";
type Sender = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type Receiver = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

fn decrypt_server_request(req: String, dk: &DecryptionKey) -> Result<(Value, AssociatedData), ()> {
    common::decrypt_request(&req, dk)
}

async fn establish_connection(
    bundle: PreKeyBundle,
    write: &mut SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    read: &mut SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    ik: PrivateKey,
    spk: PrivateKey,
) -> Result<(EncryptionKey, DecryptionKey, InitialMessage), String> {
    let msg = json!({
        "request_type": "EstablishConnection",
        "bundle": bundle.to_base64()
    });

    write
        .send(Message::Text(Utf8Bytes::from(msg.to_string())))
        .await
        .expect("Failed to send message");

    // Wait for server response
    if let Some(Ok(Message::Text(initial_msg))) = StreamExt::next(read).await {
        if let Ok(im) = InitialMessage::try_from(initial_msg.to_string()) {
            if let Ok((ek, dk)) = process_initial_message(ik, spk, None, im.clone()) {
                Ok((ek, dk, im))
            } else {
                error!("Invalid server prekey bundle");
                Err("Establishing connection failed, invalid server prekey bundle".to_string())
            }
        } else {
            error!("Invalid server initial msg.");
            Err("Establishing connection failed, invalid server initial msg".to_string())
        }
    } else {
        Err("Did not receive connection establishment acknowledgment".to_string())
    }
}

async fn register_user(
    dk: &DecryptionKey,
    username: &str,
    pb: PreKeyBundle,
    write: &mut Sender,
    read: &mut Receiver,
    session: &mut SessionKeys,
) -> Result<(), String> {
    let req = json!({
            "action" : "register",
            "username" : username,
            "bundle": pb.clone().to_base64()
    });

    let enc_req = session
        .get_encryption_key()
        .unwrap()
        .encrypt(
            req.to_string().as_ref(),
            &session.get_associated_data().unwrap(),
        )
        .expect("Failed to encrypt request");

    write
        .send(Message::Text(Utf8Bytes::from(enc_req)))
        .await
        .expect("Failed to send message");

    if let Some(Ok(Message::Text(response))) = StreamExt::next(read).await {
        match decrypt_server_request(response.to_string(), dk) {
            Ok((res, aad)) => ServerResponse::try_from(res),
            Err(_) => todo!(),
        }
    } else {
        panic!("Did not receive connection establishment acknowledgment");
    }
}

#[tokio::main]
async fn main() {
    let (ws_stream, _) = tokio_tungstenite::connect_async(SERVER_URL)
        .await
        .expect("Failed to connect");
    let (mut write, mut read) = ws_stream.split();
    let mut session = SessionKeys::new();

    let (pb, ik, spk) = generate_prekey_bundle();

    if let Ok((ek, dk, im)) =
        establish_connection(pb, &mut write, &mut read, ik.clone(), spk.clone()).await
    {
        session.set_encryption_key(ek);
        session.set_decryption_key(dk);
        session.set_associated_data(im.associated_data);
    }
}
