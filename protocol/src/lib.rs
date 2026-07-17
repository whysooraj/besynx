use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct CookieEvent {
    pub id: String,
    pub event: String,
    pub domain: String,
    pub name: String,
    pub value: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub expiration_date: Option<i64>,
    pub same_site: String,
    pub timestamp: i64,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum PeerMessage {
    HandshakeInit {
        device_id: String,
        challenge_hex: String,
    },
    HandshakeResponse {
        signature_hex: String,
        challenge_hex: String,
    },
    HandshakeAck {
        signature_hex: String,
    },
    SyncRequest {
        last_timestamp: i64,
    },
    SyncData {
        visits: Vec<HistoryItem>,
    },
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct HistoryItem {
    pub uuid: String,
    pub url: String,
    pub normalized_url: String,
    pub title: String,
    pub timestamp: i64,
    pub browser: String,
    pub device: String,
    pub hash: String,
    pub visit_type: String,
}
