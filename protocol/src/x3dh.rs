use arrayref::array_ref;
use hkdf::Hkdf;
use sha2::Sha256;
use crate::errors::X3DHError;
use crate::constants::AES256_SECRET_LENGTH;
use crate::utils::{
    AssociatedData,
    DecryptionKey,
    EncryptionKey,
    IdentityPrivateKey,
    InitialMessage,
    PreKeyBundle,
    PrivateKey,
    PublicKey,
    SharedSecret
};
pub(crate) fn generate_prekey_bundle(ik: &IdentityPrivateKey, spk: PublicKey) -> PreKeyBundle {
    PreKeyBundle::new(&ik, spk)
}

pub(crate) fn process_prekey_bundle(ik: IdentityPrivateKey, bundle: PreKeyBundle)
    -> Result<(InitialMessage, EncryptionKey, DecryptionKey), X3DHError> {
    // process the prekey bundle
    bundle.ik.verify(&bundle.sig, &bundle.spk.0)?;

    let pk = PrivateKey::from(&ik);

    let ik_b = PublicKey::from(&bundle.ik);
    // create ephemeral private key
    let ek = PrivateKey::new();
    // create ephemeral public key
    let p_ek = PublicKey::from(&ek);

    // DH1 = DH(IKA, SPKB)
    let dh1 = pk.diffie_hellman(&bundle.spk);
    // DH2 = DH(EKA, IKB)
    let dh2 = ek.diffie_hellman(&ik_b);
    // DH3 = DH(EKA, SPKB)
    let dh3 = ek.diffie_hellman(&bundle.spk);


    let (sk1, sk2) = hkdf(
        "X3DH".to_string(),
        dh1,
        dh2,
        dh3,
        if !bundle.otpk.is_empty() {
            Some(ek.diffie_hellman(&bundle.otpk[0]))
        } else {
            None
        },
    )?;

    let ad = AssociatedData {
        initiator_identity_key: PublicKey::from(&ik),
        responder_identity_key: PublicKey::from(&bundle.ik),
    };

    Ok(
        (
            InitialMessage {
                identity_key: PublicKey::from(&ik),
                ephemeral_key: p_ek,
                prekey_hash: bundle.spk.hash(),
                one_time_key_hash: if !bundle.otpk.is_empty() {Some(bundle.otpk[0].hash())} else {None},
                associated_data: ad
            },
            EncryptionKey::from(sk1),
            DecryptionKey::from(sk2)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn test_generate_prekey_bundle() {
        let identity_key = IdentityPrivateKey::new();
        let prekey = PrivateKey::new();
        let prekey_pub = PublicKey::from(prekey);
        let pb1 = generate_prekey_bundle(&identity_key, prekey_pub);
        let pb1_bytes = pb1.to_bytes();
        assert_eq!(pb1_bytes.len(), pb1.size());

        let pb1_base64 = pb1.clone().to_base64();
        let pb2 = PreKeyBundle::try_from(pb1_base64).unwrap();
        assert_eq!(pb2.spk.as_ref(), pb1.spk.as_ref());
    }

    #[test]
    fn test_process_prekey_bundle() {
        let identity_key = IdentityPrivateKey::new();
        let identity_key_pub = PublicKey::from(&identity_key);
        let prekey = PrivateKey::new();
        let prekey_pub = PublicKey::from(prekey);
        let pb = generate_prekey_bundle(&identity_key, prekey_pub);

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
            initial_message.size()
        );
    }


}