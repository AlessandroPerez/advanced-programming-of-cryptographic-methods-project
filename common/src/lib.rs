pub mod error;

use arrayref::array_ref;
use base64::{engine::general_purpose, Engine as _};
use log::{error, info};
use protocol::{
    constants::AES256_NONCE_LENGTH,
    utils::{AssociatedData, DecryptionKey, PreKeyBundle},
};
use serde_json::Value;

pub fn decrypt_request(req: &str, dk: &DecryptionKey) -> Result<(Value, AssociatedData), ()> {
    let enc_req = match general_purpose::STANDARD.decode(req.to_string()) {
        Ok(s) => s,
        Err(_e) => {
            error!("Failed to decode request");
            return Err(());
        }
    };
    let nonce = *array_ref!(enc_req, 0, AES256_NONCE_LENGTH);
    let aad = match AssociatedData::try_from(array_ref!(
        enc_req,
        AES256_NONCE_LENGTH,
        AssociatedData::SIZE
    )) {
        Ok(aad) => aad,
        Err(_) => return Err(()),
    };
    let offset = AES256_NONCE_LENGTH + AssociatedData::SIZE;
    let end = enc_req.len();
    let cipher_text = &enc_req[offset..end];
    let text = match dk.decrypt(cipher_text, &nonce, &aad) {
        Ok(dec) => dec,
        Err(_) => return Err(()),
    };

    info!(
        "Decrypted request: {}",
        String::from_utf8(text.clone()).unwrap()
    );
    match String::from_utf8(text) {
        Ok(s) => Ok((
            serde_json::from_str::<Value>(&s).unwrap_or(Value::Null),
            aad,
        )),
        Err(e) => {
            error!("Failed to parse request: {}", e);
            Err(())
        }
    }
}
