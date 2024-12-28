use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct ServerState {
    user_data: Arc<Mutex<HashMap<String, KeyBundle>>>,
}

#[derive(Debug, Clone)]
pub struct KeyBundle {
    pub identity_key: [u8; 32],
    pub signed_prekey: [u8; 32],
    pub signature: [u8; 64],
    pub one_time_prekey: [u8; 32],
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            user_data: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn insert_user(&self, username: String, bundle: KeyBundle) {
        let mut data = self.user_data.lock().unwrap();
        data.insert(username, bundle);
    }

    pub fn get_user(&self, username: &str) -> Option<KeyBundle> {
        let data = self.user_data.lock().unwrap();
        data.get(username).cloned()
    }
}
