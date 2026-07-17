mod crypto;

use axum::{
    routing::{get, post},
    Router,
    extract::{ws::{WebSocketUpgrade, WebSocket}, State},
    response::Response,
    http::{HeaderMap, StatusCode},
};
use sqlx::sqlite::SqlitePool;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::mpsc;

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    #[allow(dead_code)]
    identity: Arc<crypto::Identity>,
    pending_challenges: Arc<Mutex<HashMap<String, Instant>>>,
    // Track connected extension ws sender channels:
    extension_txs: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<axum::extract::ws::Message>>>>,
    token: String,
}

#[derive(serde::Deserialize, serde::Serialize, Clone)]
struct CookieEvent {
    id: String,
    event: String,
    domain: String,
    name: String,
    value: String,
    path: String,
    secure: bool,
    http_only: bool,
    expiration_date: Option<i64>,
    same_site: String,
    timestamp: i64,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    
    // Initialize Database
    let db_url = "sqlite://besynx.db";
    // Create db file if it doesn't exist
    if !std::path::Path::new("besynx.db").exists() {
        std::fs::File::create("besynx.db").unwrap();
    }
    let db = SqlitePool::connect(db_url).await.unwrap();
    
    // Run migrations
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    tracing::info!("Database migrations applied");

    let identity = Arc::new(crypto::Identity::load_or_generate("besynx.key").unwrap_or_else(|e| {
        tracing::error!("Identity initialization error: {}", e);
        std::process::exit(1);
    }));
    let pending_challenges = Arc::new(Mutex::new(HashMap::new()));
    let extension_txs = Arc::new(Mutex::new(HashMap::new()));

    let token_path = "besynx.token";
    let token = if std::path::Path::new(token_path).exists() {
        std::fs::read_to_string(token_path).unwrap_or_default().trim().to_string()
    } else {
        let t = uuid::Uuid::now_v7().to_string();
        let _ = std::fs::write(token_path, &t);
        t
    };
    tracing::info!("Extension Auth Token: {}", token);

    let state = Arc::new(AppState {
        db,
        identity,
        pending_challenges,
        extension_txs,
        token,
    });


    let app = Router::new()
        .route("/", get(|| async { "besynx daemon active" }))
        .route("/sync", get(ws_handler))
        .route("/sync/peer", get(ws_peer_handler))
        .route("/pair/challenge", post(pair_challenge))
        .route("/pair/response", post(pair_response))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 9098));
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(serde::Serialize)]
struct ChallengeResponse {
    challenge: String,
}

async fn pair_challenge(
    State(state): State<Arc<AppState>>,
) -> axum::Json<ChallengeResponse> {
    use rand::RngCore;
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let challenge_hex = hex::encode(nonce);

    let mut list = state.pending_challenges.lock().unwrap();
    // Clean up old ones (> 5 minutes)
    list.retain(|_, time| time.elapsed().as_secs() < 300);
    list.insert(challenge_hex.clone(), Instant::now());

    axum::Json(ChallengeResponse { challenge: challenge_hex })
}

#[derive(serde::Deserialize)]
struct PairRequest {
    device_id: String,
    device_name: String,
    public_key_hex: String,
    challenge_hex: String,
    signature_hex: String,
}

#[derive(serde::Serialize)]
struct PairResponseData {
    public_key_hex: String,
}

async fn pair_response(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<PairRequest>,
) -> Result<axum::Json<PairResponseData>, StatusCode> {
    // Validate challenge exists
    {
        let mut list = state.pending_challenges.lock().unwrap();
        if list.remove(&req.challenge_hex).is_none() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Parse public key and signature
    let pubkey_bytes = hex::decode(&req.public_key_hex).map_err(|_| StatusCode::BAD_REQUEST)?;
    let sig_bytes = hex::decode(&req.signature_hex).map_err(|_| StatusCode::BAD_REQUEST)?;
    if pubkey_bytes.len() != 32 || sig_bytes.len() != 64 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    // Verify signature over the challenge hex string bytes
    let challenge_bound = format!("besynx-auth-v1:{}", req.challenge_hex);
    if !crypto::verify_signature(&pubkey_arr, challenge_bound.as_bytes(), &sig_arr) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Store device in SQLite
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        "INSERT OR REPLACE INTO devices (id, name, public_key, last_seen)
         VALUES (?, ?, ?, ?)"
    )
    .bind(&req.device_id)
    .bind(&req.device_name)
    .bind(&pubkey_bytes)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("Successfully paired device: {} ({})", req.device_name, req.device_id);
    let daemon_pubkey = hex::encode(state.identity.public_key().to_bytes());
    Ok(axum::Json(PairResponseData { public_key_hex: daemon_pubkey }))
}


#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct RawMessage {
    id: Option<String>,
    event: String,
    url: Option<String>,
    title: Option<String>,
    timestamp: Option<i64>,
}

async fn ws_handler(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Result<Response, StatusCode> {
    match headers.get("origin") {
        Some(origin) => {
            if let Ok(origin_str) = origin.to_str() {
                if !origin_str.starts_with("chrome-extension://") && !origin_str.starts_with("moz-extension://") {
                    tracing::warn!("Blocked WebSocket connection from invalid origin: {}", origin_str);
                    return Err(StatusCode::FORBIDDEN);
                }
            } else {
                return Err(StatusCode::FORBIDDEN);
            }
        }
        None => {
            tracing::warn!("Blocked WebSocket connection with missing origin header");
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let mut authenticated = false;
    if let Some(query) = uri.query() {
        for param in query.split('&') {
            let mut parts = param.splitn(2, '=');
            if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                if k == "token" && v == state.token {
                    authenticated = true;
                    break;
                }
            }
        }
    }
    if !authenticated {
        tracing::warn!("Unauthenticated extension connection attempt rejected");
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state)))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    tracing::info!("client connected");
    if let Err(e) = handle_socket_inner(socket, state).await {
        tracing::error!("Error handling socket connection: {:?}", e);
    }
    tracing::info!("client disconnected");
}

async fn handle_socket_inner(socket: WebSocket, state: Arc<AppState>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::{SinkExt, StreamExt};
    
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let conn_id = uuid::Uuid::now_v7().to_string();
    let (tx, mut rx) = mpsc::unbounded_channel();
    
    state.extension_txs.lock().unwrap().insert(conn_id.clone(), tx);
    
    let write_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    while let Some(msg_res) = ws_receiver.next().await {
        let msg = match msg_res {
            Ok(m) => m,
            Err(_) => break,
        };
        if let Ok(text) = msg.to_text() {
            if let Ok(raw) = serde_json::from_str::<serde_json::Value>(text) {
                let event = raw.get("event").and_then(|v| v.as_str()).unwrap_or("");
                if event == "hello" {
                    tracing::info!("client hello handshake received");
                    continue;
                }
                if event == "visited" {
                    if let Ok(raw_visited) = serde_json::from_value::<RawMessage>(raw.clone()) {
                        let id = raw_visited.id.unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
                        let url = raw_visited.url.unwrap_or_default();
                        let title = raw_visited.title.unwrap_or_default();
                        let timestamp = raw_visited.timestamp.unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
                        let normalized_url = url.trim().to_lowercase();
                        
                        let db_result = async {
                            let mut tx = state.db.begin().await?;
                            sqlx::query(
                                "INSERT OR REPLACE INTO history (uuid, url, normalized_url, title, timestamp, browser, device, hash, visit_type)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                            )
                            .bind(&id)
                            .bind(&url)
                            .bind(&normalized_url)
                            .bind(&title)
                            .bind(&timestamp)
                            .bind("extension")
                            .bind("local")
                            .bind("")
                            .bind("visited")
                            .execute(&mut *tx)
                            .await?;

                            sqlx::query(
                                "INSERT OR REPLACE INTO event_log (uuid, operation, timestamp, vector_clock, device)
                                 VALUES (?, ?, ?, ?, ?)"
                            )
                            .bind(&id)
                            .bind("VisitedAdded")
                            .bind(&timestamp)
                            .bind("{}")
                            .bind("local")
                            .execute(&mut *tx)
                            .await?;

                            tx.commit().await?;
                            Ok::<(), sqlx::Error>(())
                        }.await;

                        if let Err(e) = db_result {
                            tracing::error!("Failed to store visit item {}: {:?}", id, e);
                        }

                        let ack_resp = serde_json::to_string(&serde_json::json!({ "ack": id })).unwrap();
                        let _ = state.extension_txs.lock().unwrap().get(&conn_id).map(|tx| {
                            let _ = tx.send(axum::extract::ws::Message::Text(ack_resp.into()));
                        });
                    }
                } else if event == "cookie_changed" {
                    if let Ok(cookie_evt) = serde_json::from_value::<CookieEvent>(raw.clone()) {
                        let db_res = sqlx::query(
                            "INSERT OR REPLACE INTO cookies (domain, name, value, path, secure, http_only, expiration_date, same_site, device, timestamp)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                        )
                        .bind(&cookie_evt.domain)
                        .bind(&cookie_evt.name)
                        .bind(&cookie_evt.value)
                        .bind(&cookie_evt.path)
                        .bind(cookie_evt.secure)
                        .bind(cookie_evt.http_only)
                        .bind(cookie_evt.expiration_date)
                        .bind(&cookie_evt.same_site)
                        .bind("local")
                        .bind(cookie_evt.timestamp)
                        .execute(&state.db)
                        .await;

                        if let Err(e) = db_res {
                            tracing::error!("Failed to store cookie {}: {:?}", cookie_evt.name, e);
                        } else {
                            let broadcast_msg = axum::extract::ws::Message::Text(text.to_string().into());
                            let txs = state.extension_txs.lock().unwrap();
                            for (cid, tx) in txs.iter() {
                                if cid != &conn_id {
                                    let _ = tx.send(broadcast_msg.clone());
                                }
                            }
                        }
                    }
                } else if event == "cookie_deleted" {
                    if let (Some(domain), Some(name), Some(path)) = (
                        raw.get("domain").and_then(|v| v.as_str()),
                        raw.get("name").and_then(|v| v.as_str()),
                        raw.get("path").and_then(|v| v.as_str()),
                    ) {
                        let db_res = sqlx::query(
                            "DELETE FROM cookies WHERE domain = ? AND name = ? AND path = ?"
                        )
                        .bind(domain)
                        .bind(name)
                        .bind(path)
                        .execute(&state.db)
                        .await;

                        if let Err(e) = db_res {
                            tracing::error!("Failed to delete cookie {}: {:?}", name, e);
                        } else {
                            let broadcast_msg = axum::extract::ws::Message::Text(text.to_string().into());
                            let txs = state.extension_txs.lock().unwrap();
                            for (cid, tx) in txs.iter() {
                                if cid != &conn_id {
                                    let _ = tx.send(broadcast_msg.clone());
                                }
                            }
                        }
                    }
                }
            } else {
                tracing::warn!("Failed to parse sync message: {}", text);
            }
        }
    }

    state.extension_txs.lock().unwrap().remove(&conn_id);
    write_task.abort();
    Ok(())
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(tag = "type")]
enum PeerMessage {
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

#[derive(serde::Deserialize, serde::Serialize)]
struct HistoryItem {
    uuid: String,
    url: String,
    normalized_url: String,
    title: String,
    timestamp: i64,
    browser: String,
    device: String,
    hash: String,
    visit_type: String,
}

async fn ws_peer_handler(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_peer_socket(socket, state))
}

async fn handle_peer_socket(mut socket: WebSocket, state: Arc<AppState>) {
    tracing::info!("peer connecting");
    if let Err(e) = handle_peer_socket_inner(&mut socket, state).await {
        tracing::error!("Error handling peer socket connection: {:?}", e);
    }
    tracing::info!("peer disconnected");
}

async fn handle_peer_socket_inner(socket: &mut WebSocket, state: Arc<AppState>) -> Result<(), Box<dyn std::error::Error>> {
    let msg = match socket.recv().await {
        Some(Ok(msg)) => msg,
        _ => return Ok(()),
    };
    let text = msg.to_text()?;
    let init: PeerMessage = serde_json::from_str(text)?;
    let (peer_device_id, peer_challenge) = match init {
        PeerMessage::HandshakeInit { device_id, challenge_hex } => (device_id, challenge_hex),
        _ => {
            tracing::warn!("Unexpected first message, expected HandshakeInit");
            return Ok(());
        }
    };

    let row = sqlx::query("SELECT public_key FROM devices WHERE id = ?")
        .bind(&peer_device_id)
        .fetch_optional(&state.db)
        .await?;
    let peer_pubkey_bytes: Vec<u8> = match row {
        Some(r) => {
            use sqlx::Row;
            r.get("public_key")
        }
        None => {
            tracing::warn!("Peer device {} not paired", peer_device_id);
            return Ok(());
        }
    };
    if peer_pubkey_bytes.len() != 32 {
        return Ok(());
    }
    let mut peer_pubkey = [0u8; 32];
    peer_pubkey.copy_from_slice(&peer_pubkey_bytes);

    use rand::RngCore;
    let mut challenge_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);
    let local_challenge = hex::encode(challenge_bytes);

    let peer_challenge_bound = format!("besynx-auth-v1:{}", peer_challenge);
    let signature = state.identity.sign(peer_challenge_bound.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    let resp = PeerMessage::HandshakeResponse {
        signature_hex,
        challenge_hex: local_challenge.clone(),
    };
    socket.send(axum::extract::ws::Message::Text(serde_json::to_string(&resp)?.into())).await?;

    let msg = match socket.recv().await {
        Some(Ok(msg)) => msg,
        _ => return Ok(()),
    };
    let text = msg.to_text()?;
    let ack: PeerMessage = serde_json::from_str(text)?;
    let ack_signature_hex = match ack {
        PeerMessage::HandshakeAck { signature_hex } => signature_hex,
        _ => {
            tracing::warn!("Unexpected message, expected HandshakeAck");
            return Ok(());
        }
    };

    let ack_sig_bytes = hex::decode(&ack_signature_hex)?;
    if ack_sig_bytes.len() != 64 {
        tracing::warn!("Invalid signature length from peer");
        return Ok(());
    }
    let mut ack_sig = [0u8; 64];
    ack_sig.copy_from_slice(&ack_sig_bytes);

    let local_challenge_bound = format!("besynx-auth-v1:{}", local_challenge);
    if !crypto::verify_signature(&peer_pubkey, local_challenge_bound.as_bytes(), &ack_sig) {
        tracing::warn!("Peer handshake verification failed");
        return Ok(());
    }

    tracing::info!("Peer {} authenticated successfully", peer_device_id);

    let last_ts: i64 = sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(timestamp) FROM history WHERE device = ?")
        .bind(&peer_device_id)
        .fetch_one(&state.db)
        .await?
        .unwrap_or(0);

    let sync_req = PeerMessage::SyncRequest { last_timestamp: last_ts };
    socket.send(axum::extract::ws::Message::Text(serde_json::to_string(&sync_req)?.into())).await?;

    while let Some(Ok(msg)) = socket.recv().await {
        if let Ok(text) = msg.to_text() {
            if let Ok(peer_msg) = serde_json::from_str::<PeerMessage>(text) {
                match peer_msg {
                    PeerMessage::SyncRequest { last_timestamp } => {
                        let rows = sqlx::query("SELECT uuid, url, normalized_url, title, timestamp, browser, device, hash, visit_type FROM history WHERE timestamp > ?")
                            .bind(last_timestamp)
                            .fetch_all(&state.db)
                            .await?;
                        let visits: Vec<HistoryItem> = rows.into_iter().map(|row| {
                            use sqlx::Row;
                            HistoryItem {
                                uuid: row.get("uuid"),
                                url: row.get("url"),
                                normalized_url: row.get("normalized_url"),
                                title: row.get("title"),
                                timestamp: row.get("timestamp"),
                                browser: row.get("browser"),
                                device: row.get("device"),
                                hash: row.get("hash"),
                                visit_type: row.get("visit_type"),
                            }
                        }).collect();
                        let resp = PeerMessage::SyncData { visits };
                        let _ = socket.send(axum::extract::ws::Message::Text(serde_json::to_string(&resp)?.into())).await;
                    }
                    PeerMessage::SyncData { visits } => {
                        let mut tx = state.db.begin().await?;
                        for visit in visits {
                            sqlx::query(
                                "INSERT OR REPLACE INTO history (uuid, url, normalized_url, title, timestamp, browser, device, hash, visit_type)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                            )
                            .bind(&visit.uuid)
                            .bind(&visit.url)
                            .bind(&visit.normalized_url)
                            .bind(&visit.title)
                            .bind(visit.timestamp)
                            .bind(&visit.browser)
                            .bind(&visit.device)
                            .bind(&visit.hash)
                            .bind(&visit.visit_type)
                            .execute(&mut *tx)
                            .await?;

                            sqlx::query(
                                "INSERT OR REPLACE INTO event_log (uuid, operation, timestamp, vector_clock, device)
                                 VALUES (?, ?, ?, ?, ?)"
                            )
                            .bind(&visit.uuid)
                            .bind("VisitedAdded")
                            .bind(visit.timestamp)
                            .bind("{}")
                            .bind(&visit.device)
                            .execute(&mut *tx)
                            .await?;
                        }
                        tx.commit().await?;
                    }
                    _ => {
                        tracing::warn!("Unexpected message in authenticated state");
                    }
                }
            }
        }
    }

    Ok(())
}


