use crate::constants::AES256_SECRET_LENGTH;
use crate::errors::X3DHError;
use crate::utils::{
    AssociatedData,
    DecryptionKey,
    EncryptionKey,
    InitialMessage,
    PreKeyBundle,
    PrivateKey,
    PublicKey,
    SharedSecret,
    SignedPreKey
};
use arrayref::array_ref;
use hkdf::Hkdf;
use sha2::Sha256;

pub fn generate_prekey_bundle()
    -> (PreKeyBundle, PrivateKey, PrivateKey) {
    // generate identity key
    let identity_key = PrivateKey::new();
    // generate signed prekey
    let signed_prekey = SignedPreKey::new();
    // create prekey bundle
    (
        PreKeyBundle::new(&identity_key, signed_prekey.public_key),
        identity_key,
        signed_prekey.private_key
    )
}

pub fn generate_prekey_bundle_with_otpk(n: u32) -> (PreKeyBundle, PrivateKey, PrivateKey, Vec<PrivateKey>) {

    let mut otpk_private = Vec::new();
    let mut otpk_public = Vec::new();
    for _ in 0..n {
        let otpk_private_key = PrivateKey::new();
        otpk_public.push(PublicKey::from(&otpk_private_key));
        otpk_private.push(otpk_private_key);
    }

    let ik = PrivateKey::new();
    let spk = SignedPreKey::new();
    let pb = PreKeyBundle::new_with_otpk(
        &ik,
        spk.public_key,
        otpk_public
    );

    (pb, ik, spk.private_key, otpk_private)
}


pub fn process_prekey_bundle(ik: PrivateKey, mut bundle: PreKeyBundle)
                             -> Result<(InitialMessage, EncryptionKey, DecryptionKey), X3DHError> {
    // process the prekey bundle

    bundle.verifying_key.verify(&bundle.sig, &bundle.spk.0)?;

    // create ephemeral private key
    let ek = PrivateKey::new();
    // create ephemeral public key
    let p_ek = PublicKey::from(&ek);

    // DH1 = DH(IKA, SPKB)
    let dh1 = ik.diffie_hellman(&bundle.spk);
    // DH2 = DH(EKA, IKB)
    let dh2 = ek.diffie_hellman(&bundle.ik);
    // DH3 = DH(EKA, SPKB)
    let dh3 = ek.diffie_hellman(&bundle.spk);

    let otpk = bundle.otpk.pop();


    let (sk1, sk2) = hkdf(
        "X3DH".to_string(),
        dh1,
        dh2,
        dh3,
        if let Some(otpk) = &otpk {
            // DH4 = DH(EKA, OTPK)
            Some(ek.diffie_hellman(otpk))
        } else {
            None
        },
    )?;


    let ad = AssociatedData {
        initiator_identity_key: PublicKey::from(&ik),
        responder_identity_key: bundle.ik,
    };

    let ek = EncryptionKey::from(sk1);
    let dk = DecryptionKey::from(sk2);
    let challenge  = ek.encrypt_challenge(PublicKey::from(&ik).as_ref())?;

    Ok(
        (
            InitialMessage {
                identity_key: PublicKey::from(&ik),
                ephemeral_key: p_ek,
                prekey_hash: bundle.spk.hash(),
                one_time_key_hash: if let Some(otpk) = otpk {
                    Some(otpk.hash())
                } else {
                    None
                },
                challenge,
                associated_data: ad
            },
            ek,
            dk
        )
    )
}

// HMAC-based Key Derivation Function
fn hkdf(
    info: String,
    dh1: SharedSecret,
    dh2: SharedSecret,
    dh3: SharedSecret,
    dh4: Option<SharedSecret>,
) -> Result<(SharedSecret, SharedSecret), X3DHError> {
    // HKDF input key material = F || KM, where KM is an input byte sequence containing secret key material, and F is a byte sequence containing 32 0xFF bytes if curve is X25519, and 57 0xFF bytes if curve is X448. F is used for cryptographic domain separation with XEdDSA [2].
    let mut dhs = vec![0xFFu8; 32];
    dhs.extend_from_slice(dh1.as_ref());
    dhs.extend_from_slice(dh2.as_ref());
    dhs.extend_from_slice(dh3.as_ref());
    if let Some(dh4) = dh4 {
        dhs.extend_from_slice(dh4.as_ref());
    }
    // HKDF salt = A zero-filled byte sequence with length equal to the hash output length.
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), dhs.as_ref());
    let mut okm = [0u8; 2 * AES256_SECRET_LENGTH];
    // HKDF info = The info parameter from Section 2.1.
    hk.expand(info.as_bytes(), &mut okm)?;

    let shared_key1 = SharedSecret::from(*array_ref!(okm, 0, AES256_SECRET_LENGTH));
    let shared_key2 =
        SharedSecret::from(*array_ref!(okm, AES256_SECRET_LENGTH, AES256_SECRET_LENGTH));
    Ok((shared_key1, shared_key2))
}

pub fn process_initial_message(
    identity_key: PrivateKey,
    signed_prekey: PrivateKey,
    one_time_prekey: Option<PrivateKey>,
    msg: InitialMessage,
) -> Result<(EncryptionKey, DecryptionKey), X3DHError> {
    // DH1 = DH(SPKB, IKA)
    let dh1 = signed_prekey.diffie_hellman(&msg.identity_key);
    // DH2 = DH(IKB, EKA)
    let dh2 = identity_key.diffie_hellman(&msg.ephemeral_key);
    // DH3 = DH(SPKB, EKA)
    let dh3 = signed_prekey.diffie_hellman(&msg.ephemeral_key);

    let (sk1, sk2) = hkdf(
        "X3DH".to_string(),
        dh1,
        dh2,
        dh3,
        if msg.one_time_key_hash.is_some() {
            // DH4 = DH(OTPK, EKA)
            let dh4 = one_time_prekey.unwrap().diffie_hellman(&msg.ephemeral_key);
            Some(dh4)
        } else {
            None
        },
    )?;
    let ek = EncryptionKey::from(sk2);
    let dk = DecryptionKey::from(sk1);

    let challenge = dk.decrypt_challenge(&msg.challenge)?;
    if challenge != msg.identity_key.as_ref() {
        return Err(X3DHError::InvalidKey);
    }

    Ok((
        ek,
        dk,
    ))
}

pub fn process_server_initial_message(
    identity_key: PrivateKey,
    signed_prekey: PrivateKey,
    one_time_prekey: Option<PrivateKey>,
    server_ik: &PublicKey,
    msg: InitialMessage,
) -> Result<(EncryptionKey, DecryptionKey), X3DHError> {

    if msg.identity_key.hash() != server_ik.hash(){
        return Err(X3DHError::InvalidInitialMessage);
    }
    process_initial_message(identity_key, signed_prekey, one_time_prekey, msg)
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose;
    use base64::Engine;

    use super::*;
    use crate::constants::{AES256_NONCE_LENGTH, CURVE25519_PUBLIC_LENGTH, SHA256_HASH_LENGTH};
    use crate::utils::SignedPreKey;
    use std::convert::TryFrom;

    #[test]
    fn test_generate_prekey_bundle() {
        let identity_key = PrivateKey::new();
        let prekey = SignedPreKey::new();
        let pb1 = PreKeyBundle::new(&identity_key, prekey.public_key);
        let pb1_bytes = pb1.to_bytes();
        assert_eq!(pb1_bytes.len(), pb1.size());

        let pb1_base64 = pb1.clone().to_base64();
        let pb2 = PreKeyBundle::try_from(pb1_base64).unwrap();
        assert_eq!(pb2.spk.as_ref(), pb1.spk.as_ref());
    }

    #[test]
    fn test_process_prekey_bundle() {
        let identity_key = PrivateKey::new();
        let identity_key_pub = PublicKey::from(&identity_key);
        let prekey = SignedPreKey::new();
        let pb = PreKeyBundle::new(&identity_key, prekey.public_key);
        let (initial_message, encryption_key, decryption_key) =
            process_prekey_bundle(identity_key, pb).unwrap();
        assert_eq!(
            initial_message.identity_key.as_ref(),
            identity_key_pub.as_ref()
        );
        assert_eq!(encryption_key.as_ref().len(), AES256_SECRET_LENGTH);
        assert_eq!(decryption_key.as_ref().len(), AES256_SECRET_LENGTH);

        let im_bytes = initial_message.clone().to_bytes();
        assert_eq!(
            im_bytes.len(),
            4 * CURVE25519_PUBLIC_LENGTH + SHA256_HASH_LENGTH
        );

        assert_eq!(
            initial_message.size(),
            4 * CURVE25519_PUBLIC_LENGTH + SHA256_HASH_LENGTH
        );
    }

    #[test]
    fn test_process_initial_message() {
        // Bob creates a prekey bundle and sends it to Alice
        let bob_identity_key = PrivateKey::new();
        let bob_prekey = SignedPreKey::new();
        let pb = PreKeyBundle::new(&bob_identity_key, bob_prekey.public_key);

        // Alice processes the prekey bundle and sends an initial message to Bob
        let alice_identity_key = PrivateKey::new();
        let (initial_message, encryption_key1, decryption_key1) =
            process_prekey_bundle(alice_identity_key, pb).unwrap();

        // Bob processes the initial message and creates a shared key
        let (encryption_key2, decryption_key2) = process_initial_message(
            bob_identity_key,
            bob_prekey.private_key,
            None,
            initial_message.clone()
        ).unwrap();
        assert_eq!(encryption_key1.as_ref(), decryption_key2.as_ref());
        assert_eq!(decryption_key1.as_ref(), encryption_key2.as_ref());

        let data = b"Hello World!";
        let aad = initial_message.associated_data;
        let cipher_text = match encryption_key1.encrypt(data, &aad.clone().to_bytes()) {
            Ok(c) => c,
            Err(e) => {
                println!("Error in encryption: {}", e);
                return;
            }
        };

        let cipher_text = match general_purpose::STANDARD.decode(cipher_text) {
            Ok(v) => v,
            Err(e) => {
                println!("Error in decoding: {}", e);
                return;
            }
        };
        let end = cipher_text.len();
        let nonce = *array_ref!(cipher_text, 0, AES256_NONCE_LENGTH);
        let add = *array_ref!(cipher_text, AES256_NONCE_LENGTH, AssociatedData::SIZE);
        let cipher_text = &cipher_text[AES256_NONCE_LENGTH + AssociatedData::SIZE..end];
        let clear_text = match decryption_key2.decrypt(&cipher_text, &nonce, &aad.to_bytes()) {
            Ok(d) => d,
            Err(e) => {
                println!("Error in decryption: {}", e);
                return;
            }
        };
        assert_eq!(data.to_vec(), clear_text);
    }

    #[test]
    fn test_generate_process_key_bundle() {
        let pb = generate_prekey_bundle();
        let (pb, ik, spk) = pb;
        let pik = PublicKey::from(&ik);
        let b64 = pb.to_base64();
        let pb = PreKeyBundle::try_from(b64).unwrap();
        let (im, ek, dk) = process_prekey_bundle(ik, pb).unwrap();
        assert_eq!(im.identity_key.as_ref(), pik.as_ref());
    }

    #[test]
    fn test_process_prekey_bundle_with_otpk() {
        let (pb, ik, spk, otpk)= generate_prekey_bundle_with_otpk(5);
        let pik = PublicKey::from(&ik);
        let b64 = pb.to_base64();
        let pb = PreKeyBundle::try_from(b64).unwrap();
        let (im, ek, dk) = process_prekey_bundle(ik, pb).unwrap();
        assert_eq!(im.identity_key.as_ref(), pik.as_ref());
        assert_eq!(im.one_time_key_hash.unwrap(), PublicKey::from(&otpk[0]).hash());
    }


    #[test]
    fn test_process_initial_message_with_otpk() {
        let (pb, ik, spk, otpk)= generate_prekey_bundle_with_otpk(5);
        let pik = PublicKey::from(&ik);
        let b64 = pb.to_base64();
        let pb = PreKeyBundle::try_from(b64).unwrap();
        let (im, ek, dk) = process_prekey_bundle(ik.clone(), pb).unwrap();
        let im_b64 = im.to_base64();
        let im = InitialMessage::try_from(im_b64).unwrap();
        let (ek1, dk1) = process_initial_message(ik, spk, Some(otpk[0].clone()), im).unwrap();
        assert_eq!(ek1.as_ref(), dk.as_ref());
        assert_eq!(ek.as_ref(), dk1.as_ref());
    }
}
