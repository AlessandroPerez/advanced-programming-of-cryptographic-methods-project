use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::server::utils::User;

#[derive(Clone)]
pub struct ServerState {
    user_data: Arc<Mutex<HashMap<String, User>>>,
}

#[derive(Debug, Clone)]
pub struct KeyBundle {
    identity_key: [u8; 32],
    signed_prekey: [u8; 32],
    signature: [u8; 64],
    one_time_prekey: [u8; 32],
}

impl KeyBundle {
    pub fn new(
        identity_key: [u8; 32],
        signed_prekey: [u8; 32],
        signature: [u8; 64],
        one_time_prekey: [u8; 32],
    ) -> Self {
        Self {
            identity_key,
            signed_prekey,
            signature,
            one_time_prekey,
        }
    }

    pub fn get_identity_key(&self) -> [u8; 32] {
        self.identity_key
    }

    pub fn get_signed_prekey(&self) -> [u8; 32] {
        self.signed_prekey
    }

    pub fn get_signature(&self) -> [u8; 64] {
        self.signature
    }

    pub fn get_one_time_prekey(&self) -> [u8; 32] {
        self.one_time_prekey
    }
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            user_data: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn insert_user(&self, username: String, bundle: User) {
        let mut data = self.user_data.lock().unwrap();
        data.insert(username, bundle);
    }

    pub fn get_user(&self, username: &str) -> Option<User> {
        let data = self.user_data.lock().unwrap();
        data.get(username).cloned()
    }
}
