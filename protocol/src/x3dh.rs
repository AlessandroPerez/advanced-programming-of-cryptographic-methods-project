use crate::utils::{IdentityPrivateKey, PreKeyBundle, PrivateKey, PublicKey};
use crate::constants::{
    CURVE25519_PUBLIC_LENGTH,
    SIGNATURE_LENGTH,
    SHA256_HASH_LENGTH,
    AES256_SECRET_LENGTH,
    AES256_NONCE_LENGTH,
    CURVE25519_SECRET_LENGTH,
};

pub(crate) fn generate_prekey_bundle() -> PreKeyBundle {
    let ik = IdentityPrivateKey::new();
    let pk = PrivateKey::new();
    let spk = PublicKey::from(pk);
    PreKeyBundle::new(&ik, spk)
}

pub(crate) fn process_prekey_bundle(ik: IdentityPrivateKey, bundle: PreKeyBundle) {
    // process the prekey bundle
    todo!("process the prekey bundle");
}