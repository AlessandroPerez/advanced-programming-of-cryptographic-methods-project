use std::{collections::HashMap, env::set_var, hash::Hash, process::exit};

use common::ServerResponse;
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use log::{error, info};
use protocol::x3dh::{generate_prekey_bundle, process_initial_message};
use protocol::{
    utils::{
        AssociatedData, DecryptionKey, EncryptionKey, InitialMessage, PreKeyBundle, PrivateKey,
        SessionKeys,
    },
    x3dh::process_prekey_bundle,
};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    tungstenite::{Message, Utf8Bytes},
    MaybeTlsStream, WebSocketStream,
};

const SERVER_URL: &str = "ws://127.0.0.1:3333";
type Sender = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type Receiver = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

struct Friend {
    keys: SessionKeys,
    pb: PreKeyBundle,
    im: InitialMessage,
}

impl Friend {
    fn new(keys: SessionKeys, pb: PreKeyBundle, im: InitialMessage) -> Self {
        Self { keys, pb, im }
    }

    fn get_friend_bundle(&self) -> PreKeyBundle {
        self.pb.clone()
    }

    fn get_friend_keys(&self) -> SessionKeys {
        self.keys.clone()
    }
}

fn decrypt_server_request(req: String, dk: &DecryptionKey) -> Result<(Value, AssociatedData), ()> {
    common::decrypt_request(&req, dk)
}

fn prompt(text: &str) -> String {
    print!("{} ", text);

    let mut response = String::new();
    std::io::stdin()
        .read_line(&mut response)
        .expect("Failed to get input");

    response.trim_end().to_string()
}

async fn establish_connection(
    bundle: PreKeyBundle,
    write: &mut Sender,
    read: &mut Receiver,
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
        if let Ok(resp) = ServerResponse::try_from(
            serde_json::from_str::<Value>(initial_msg.as_str()).unwrap_or(Value::Null),
        ) {
            let mut im = resp.text;
            info!("im: {}", &im);
            im.retain(|c| !c.eq(&("\"".parse::<char>().unwrap())));
            if let Ok(im) = InitialMessage::try_from(im) {
                if let Ok((ek, dk)) = process_initial_message(ik, spk, None, im.clone()) {
                    info!("Inital massage processed correctly");
                    Ok((ek, dk, im))
                } else {
                    error!("Cannot process initial massage");
                    Err("".to_string())
                }
            } else {
                error!("Cannot parse initial message");
                Err("".to_string())
            }
        } else {
            error!("Cannot parse json response");
            Err("".to_string())
        }
    } else {
        Err("Did not receive connection establishment acknowledgment".to_string())
    }
}

async fn get_user_prekeybundle(
    dk: &DecryptionKey,
    username: &str,
    write: &mut Sender,
    read: &mut Receiver,
    session: &mut SessionKeys,
) -> Result<ServerResponse, ()> {
    let req = json!({
        "action": "get_prekey_bundle",
        "who": username,
    });
    let enc = session
        .get_encryption_key()
        .unwrap()
        .encrypt(
            req.to_string().as_bytes(),
            &session.get_associated_data().unwrap(),
        )
        .expect("Failed to encrypt request");

    write
        .send(Message::Text(Utf8Bytes::from(enc)))
        .await
        .expect("Failed to send request.");

    if let Some(Ok(Message::Text(response))) = StreamExt::next(read).await {
        match decrypt_server_request(response.to_string(), dk) {
            Ok((r, _aad)) => Ok(ServerResponse::try_from(r)?),
            Err(_) => Err(()),
        }
    } else {
        panic!("Did not received any request.")
    }
}

async fn register_user(
    dk: &DecryptionKey,
    username: &str,
    pb: PreKeyBundle,
    write: &mut Sender,
    read: &mut Receiver,
    session: &mut SessionKeys,
) -> Result<ServerResponse, ()> {
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
            Ok((res, _aad)) => Ok(ServerResponse::try_from(res)?),
            Err(_) => Err(()),
        }
    } else {
        panic!("Did not receive connection establishment acknowledgment");
    }
}

async fn send_message(
    to: &str,
    session: &mut SessionKeys,
    text: &str,
    write: &mut Sender,
    read: &mut Receiver,
) {
}

#[tokio::main]
async fn main() {
    set_var("RUST_LOG", "info");
    env_logger::init();

    let (ws_stream, _) = tokio_tungstenite::connect_async(SERVER_URL)
        .await
        .expect("Failed to connect");
    let (mut write, mut read) = ws_stream.split();
    let mut session = SessionKeys::new();

    let (pb, ik, spk) = generate_prekey_bundle();

    info!("Trying establish connection with {} ...", SERVER_URL);
    let mut friends: HashMap<String, Friend> = HashMap::new();
    if let Ok((ek, dk, im)) =
        establish_connection(pb.clone(), &mut write, &mut read, ik.clone(), spk.clone()).await
    {
        info!("Secure connection with server {} established", SERVER_URL);
    } else {
        error!(
            "Cannot establish secure connection with server {}",
            SERVER_URL
        );
    }
}
