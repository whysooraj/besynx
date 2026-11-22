use axum::{
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{get, post},
    Router,
};
use protocol::{get_config_dir, CookieEvent, HistoryItem, PeerMessage, TabItem};
use sqlx::sqlite::SqlitePool;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
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
    allowed_extension_ids: Arc<Vec<String>>,
}

/// Enforces WebExtension origin validation.
/// Restricts origins to standard Chrome extension IDs (32 chars in 'a'..='p')
/// or Firefox extension UUIDs. If `allowed_ids` is non-empty, checks against allowed IDs.
pub fn validate_extension_origin(origin: &str, allowed_ids: &[String]) -> bool {
    let (scheme_rest, is_chrome) = if let Some(rest) = origin.strip_prefix("chrome-extension://") {
        (rest, true)
    } else if let Some(rest) = origin.strip_prefix("moz-extension://") {
        (rest, false)
    } else {
        return false;
    };

    let id = scheme_rest.split(['/', '?']).next().unwrap_or("").trim();
    if id.is_empty() {
        return false;
    }

    if is_chrome {
        if id.len() != 32 || !id.chars().all(|c| ('a'..='p').contains(&c)) {
            return false;
        }
    } else if uuid::Uuid::parse_str(id).is_err() {
        return false;
    }

    if !allowed_ids.is_empty() && !allowed_ids.iter().any(|allowed| allowed == id) {
        return false;
    }

    true
}

/// Authenticates request against daemon local token via Authorization header,
/// X-Besynx-Token header, or ?token= query parameter.
pub fn authenticate_request(headers: &HeaderMap, uri: &axum::http::Uri, expected_token: &str) -> bool {
    if expected_token.is_empty() {
        return false;
    }

    // 1. Authorization header: "Bearer <token>" or raw "<token>"
    if let Some(auth_val) = headers.get("authorization").and_then(|h| h.to_str().ok()) {
        let token = if let Some(stripped) = auth_val.strip_prefix("Bearer ") {
            stripped.trim()
        } else if let Some(stripped) = auth_val.strip_prefix("bearer ") {
            stripped.trim()
        } else {
            auth_val.trim()
        };
        if token == expected_token {
            return true;
        }
    }

    // 2. X-Besynx-Token header
    if let Some(token_val) = headers.get("x-besynx-token").and_then(|h| h.to_str().ok()) {
        if token_val.trim() == expected_token {
            return true;
        }
    }

    // 3. Query parameter: ?token=<token>
    if let Some(query) = uri.query() {
        for param in query.split('&') {
            let mut parts = param.splitn(2, '=');
            if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                if k == "token" && v == expected_token {
                    return true;
                }
            }
        }
    }

    false
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Initialize Database
    let config_dir = get_config_dir();
    std::fs::create_dir_all(&config_dir).unwrap();
    let db_path = config_dir.join("besynx.db");

    // Create db file if it doesn't exist
    if !db_path.exists() {
        std::fs::File::create(&db_path).unwrap();
    }
    let db_url = format!("sqlite://{}", db_path.to_str().unwrap());
    let db = SqlitePool::connect(&db_url).await.unwrap();

    // Run migrations
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    tracing::info!("Database migrations applied");

    let key_path = config_dir.join("besynx.key");
    let identity = Arc::new(
        crypto::Identity::load_or_generate(&key_path).unwrap_or_else(|e| {
            tracing::error!("Identity initialization error: {}", e);
            std::process::exit(1);
        }),
    );
    let pending_challenges = Arc::new(Mutex::new(HashMap::new()));
    let extension_txs = Arc::new(Mutex::new(HashMap::new()));

    let token_path = config_dir.join("besynx.token");
    let token = if token_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::read_to_string(&token_path)
            .unwrap_or_default()
            .trim()
            .to_string()
    } else {
        let t = uuid::Uuid::now_v7().to_string();
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&token_path)
            {
                let _ = f.write_all(t.as_bytes());
            }
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600));
        }
        #[cfg(not(unix))]
        {
            let _ = std::fs::write(&token_path, &t);
        }
        t
    };
    tracing::info!("Extension Auth Token: {}", token);

    let allowed_extensions_path = config_dir.join("allowed_extensions");
    let mut allowed_extension_ids = Vec::new();
    if allowed_extensions_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&allowed_extensions_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    allowed_extension_ids.push(trimmed.to_string());
                }
            }
        }
    }
    if let Ok(env_allowed) = std::env::var("BESYNX_ALLOWED_EXTENSION_IDS") {
        for id in env_allowed.split(',') {
            let trimmed = id.trim();
            if !trimmed.is_empty() {
                allowed_extension_ids.push(trimmed.to_string());
            }
        }
    }

    let state = Arc::new(AppState {
        db,
        identity,
        pending_challenges,
        extension_txs,
        token,
        allowed_extension_ids: Arc::new(allowed_extension_ids),
    });

    let app = Router::new()
        .route("/", get(|| async { "besynx daemon active" }))
        .route("/sync", get(ws_handler))
        .route("/sync/peer", get(ws_peer_handler))
        .route("/pair/challenge", post(pair_challenge))
        .route("/pair/response", post(pair_response))
        .route(
            "/v1/tabs/register",
            post(register_tabs_handler).get(get_tabs_handler),
        )
        .route("/v1/tabs", get(get_tabs_handler))
        .route("/tabs", get(get_tabs_handler).post(register_tabs_handler))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 9098));
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(serde::Serialize, Debug)]
struct ChallengeResponse {
    challenge: String,
}

async fn pair_challenge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Result<axum::Json<ChallengeResponse>, StatusCode> {
    if !authenticate_request(&headers, &uri, &state.token) {
        tracing::warn!("Unauthorized attempt to initiate pair challenge");
        return Err(StatusCode::UNAUTHORIZED);
    }

    use rand::RngCore;
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let challenge_hex = hex::encode(nonce);

    let mut list = state.pending_challenges.lock().unwrap();
    // Clean up old ones (> 5 minutes)
    list.retain(|_, time| time.elapsed().as_secs() < 300);
    list.insert(challenge_hex.clone(), Instant::now());

    Ok(axum::Json(ChallengeResponse {
        challenge: challenge_hex,
    }))
}

#[derive(serde::Deserialize)]
struct PairRequest {
    device_id: String,
    device_name: String,
    public_key_hex: String,
    challenge_hex: String,
    signature_hex: String,
}

#[derive(serde::Serialize, Debug)]
struct PairResponseData {
    public_key_hex: String,
}

async fn pair_response(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    axum::Json(req): axum::Json<PairRequest>,
) -> Result<axum::Json<PairResponseData>, StatusCode> {
    if !authenticate_request(&headers, &uri, &state.token) {
        tracing::warn!("Unauthorized attempt to submit pair response");
        return Err(StatusCode::UNAUTHORIZED);
    }

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
         VALUES (?, ?, ?, ?)",
    )
    .bind(&req.device_id)
    .bind(&req.device_name)
    .bind(&pubkey_bytes)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!(
        "Successfully paired device: {} ({})",
        req.device_name,
        req.device_id
    );
    let daemon_pubkey = hex::encode(state.identity.public_key().to_bytes());
    Ok(axum::Json(PairResponseData {
        public_key_hex: daemon_pubkey,
    }))
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

// Tab models for storage and serialization
#[derive(serde::Deserialize, Clone, Debug)]
pub struct TabInput {
    #[serde(default)]
    pub tab_id: Option<i64>,
    #[serde(default)]
    pub id: Option<i64>,
    pub url: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub favicon: Option<String>,
    #[serde(default)]
    pub window_id: Option<i64>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub pinned: Option<bool>,
    #[serde(default)]
    pub last_active_at: Option<i64>,
}

#[derive(serde::Deserialize, Clone, Debug)]
pub struct TabsRegisterRequest {
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub tabs: Vec<TabInput>,
}

#[derive(serde::Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum RegisterTabsPayload {
    Object(TabsRegisterRequest),
    List(Vec<TabInput>),
}

#[derive(serde::Deserialize, Default)]
struct TabsFilterQuery {
    device_id: Option<String>,
    q: Option<String>,
}

#[derive(serde::Serialize)]
struct TabsResponseData {
    tabs: Vec<TabItem>,
}

async fn store_tabs_snapshot(
    db: &SqlitePool,
    device_id: &str,
    tabs: &[TabInput],
) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;

    sqlx::query("DELETE FROM tabs WHERE device_id = ?")
        .bind(device_id)
        .execute(&mut *tx)
        .await?;

    let now = chrono::Utc::now().timestamp_millis();
    for (idx, tab) in tabs.iter().enumerate() {
        let tab_id = tab.tab_id.or(tab.id).unwrap_or(idx as i64);
        let title = tab.title.as_deref().unwrap_or(&tab.url);
        let active = tab.active.unwrap_or(false);
        let pinned = tab.pinned.unwrap_or(false);
        let last_active = tab.last_active_at.unwrap_or(now);

        sqlx::query(
            "INSERT OR REPLACE INTO tabs (device_id, tab_id, url, title, favicon, window_id, active, pinned, last_active_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(device_id)
        .bind(tab_id)
        .bind(&tab.url)
        .bind(title)
        .bind(&tab.favicon)
        .bind(tab.window_id)
        .bind(active)
        .bind(pinned)
        .bind(last_active)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

async fn fetch_all_tabs(
    db: &SqlitePool,
    device_id: Option<&str>,
    q: Option<&str>,
) -> Result<Vec<TabItem>, sqlx::Error> {
    let rows = match (device_id, q) {
        (Some(dev), Some(query)) => {
            let pattern = format!("%{}%", query);
            sqlx::query(
                "SELECT device_id, tab_id, url, title, favicon, window_id, active, pinned, last_active_at
                 FROM tabs WHERE device_id = ? AND (url LIKE ? OR title LIKE ?)
                 ORDER BY last_active_at DESC",
            )
            .bind(dev)
            .bind(&pattern)
            .bind(&pattern)
            .fetch_all(db)
            .await?
        }
        (Some(dev), None) => {
            sqlx::query(
                "SELECT device_id, tab_id, url, title, favicon, window_id, active, pinned, last_active_at
                 FROM tabs WHERE device_id = ?
                 ORDER BY last_active_at DESC",
            )
            .bind(dev)
            .fetch_all(db)
            .await?
        }
        (None, Some(query)) => {
            let pattern = format!("%{}%", query);
            sqlx::query(
                "SELECT device_id, tab_id, url, title, favicon, window_id, active, pinned, last_active_at
                 FROM tabs WHERE (url LIKE ? OR title LIKE ?)
                 ORDER BY last_active_at DESC",
            )
            .bind(&pattern)
            .bind(&pattern)
            .fetch_all(db)
            .await?
        }
        (None, None) => {
            sqlx::query(
                "SELECT device_id, tab_id, url, title, favicon, window_id, active, pinned, last_active_at
                 FROM tabs ORDER BY last_active_at DESC",
            )
            .fetch_all(db)
            .await?
        }
    };

    let tabs = rows
        .into_iter()
        .map(|row| {
            use sqlx::Row;
            TabItem {
                device_id: row.get("device_id"),
                tab_id: row.get("tab_id"),
                url: row.get("url"),
                title: row.get("title"),
                favicon: row.get("favicon"),
                window_id: row.get("window_id"),
                active: row.get("active"),
                pinned: row.get("pinned"),
                last_active_at: row.get("last_active_at"),
            }
        })
        .collect();

    Ok(tabs)
}

async fn register_tabs_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    axum::Json(payload): axum::Json<RegisterTabsPayload>,
) -> Result<axum::Json<serde_json::Value>, StatusCode> {
    if !authenticate_request(&headers, &uri, &state.token) {
        tracing::warn!("Unauthorized attempt to register tabs");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let (device_id, tabs) = match payload {
        RegisterTabsPayload::Object(req) => (
            req.device_id.unwrap_or_else(|| "local".to_string()),
            req.tabs,
        ),
        RegisterTabsPayload::List(tabs) => ("local".to_string(), tabs),
    };

    let count = tabs.len();
    store_tabs_snapshot(&state.db, &device_id, &tabs)
        .await
        .map_err(|e| {
            tracing::error!("Failed to register tabs for device {}: {:?}", device_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!("Registered {} tabs for device {}", count, device_id);
    Ok(axum::Json(serde_json::json!({
        "status": "ok",
        "device_id": device_id,
        "count": count
    })))
}

async fn get_tabs_handler(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<TabsFilterQuery>,
) -> Result<axum::Json<TabsResponseData>, StatusCode> {
    let tabs = fetch_all_tabs(
        &state.db,
        filter.device_id.as_deref(),
        filter.q.as_deref(),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch tabs: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(axum::Json(TabsResponseData { tabs }))
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
                if !validate_extension_origin(origin_str, &state.allowed_extension_ids) {
                    tracing::warn!(
                        "Blocked WebSocket connection from invalid or unauthorized origin: {}",
                        origin_str
                    );
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

    if !authenticate_request(&headers, &uri, &state.token) {
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

async fn handle_socket_inner(
    socket: WebSocket,
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::{SinkExt, StreamExt};

    let (mut ws_sender, mut ws_receiver) = socket.split();
    let conn_id = uuid::Uuid::now_v7().to_string();
    let (tx, mut rx) = mpsc::unbounded_channel();

    state
        .extension_txs
        .lock()
        .unwrap()
        .insert(conn_id.clone(), tx);

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
                        let id = raw_visited
                            .id
                            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
                        let url = raw_visited.url.unwrap_or_default();
                        let title = raw_visited.title.unwrap_or_default();
                        let timestamp = raw_visited
                            .timestamp
                            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
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

                        match db_result {
                            Ok(()) => {
                                let ack_resp =
                                    serde_json::to_string(&serde_json::json!({ "ack": id }))
                                        .unwrap();
                                let _ =
                                    state.extension_txs.lock().unwrap().get(&conn_id).map(|tx| {
                                        let _ = tx.send(axum::extract::ws::Message::Text(
                                            ack_resp.into(),
                                        ));
                                    });
                            }
                            Err(e) => {
                                tracing::error!("Failed to store visit item {}: {:?}", id, e);
                                let nack_resp = serde_json::to_string(
                                    &serde_json::json!({ "nack": id, "error": e.to_string() }),
                                )
                                .unwrap();
                                let _ =
                                    state.extension_txs.lock().unwrap().get(&conn_id).map(|tx| {
                                        let _ = tx.send(axum::extract::ws::Message::Text(
                                            nack_resp.into(),
                                        ));
                                    });
                            }
                        }
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
                            let broadcast_msg =
                                axum::extract::ws::Message::Text(text.to_string().into());
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
                            "DELETE FROM cookies WHERE domain = ? AND name = ? AND path = ?",
                        )
                        .bind(domain)
                        .bind(name)
                        .bind(path)
                        .execute(&state.db)
                        .await;

                        if let Err(e) = db_res {
                            tracing::error!("Failed to delete cookie {}: {:?}", name, e);
                        } else {
                            let broadcast_msg =
                                axum::extract::ws::Message::Text(text.to_string().into());
                            let txs = state.extension_txs.lock().unwrap();
                            for (cid, tx) in txs.iter() {
                                if cid != &conn_id {
                                    let _ = tx.send(broadcast_msg.clone());
                                }
                            }
                        }
                    }
                } else if event == "tabs_snapshot"
                    || event == "tabs_register"
                    || event == "register_tabs"
                {
                    let device_id = raw
                        .get("device_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("local")
                        .to_string();
                    let tabs_val = raw.get("tabs").unwrap_or(&serde_json::Value::Null);
                    if let Ok(tabs_input) =
                        serde_json::from_value::<Vec<TabInput>>(tabs_val.clone())
                    {
                        let _ = store_tabs_snapshot(&state.db, &device_id, &tabs_input).await;
                        let ack_resp = serde_json::to_string(&serde_json::json!({
                            "ack": "tabs_snapshot",
                            "count": tabs_input.len()
                        }))
                        .unwrap();
                        let _ = state.extension_txs.lock().unwrap().get(&conn_id).map(|tx| {
                            let _ = tx.send(axum::extract::ws::Message::Text(ack_resp.into()));
                        });
                    }
                } else if event == "get_tabs" {
                    if let Ok(tabs) = fetch_all_tabs(&state.db, None, None).await {
                        let resp = serde_json::to_string(&serde_json::json!({
                            "event": "tabs_sync",
                            "tabs": tabs
                        }))
                        .unwrap();
                        let _ = state.extension_txs.lock().unwrap().get(&conn_id).map(|tx| {
                            let _ = tx.send(axum::extract::ws::Message::Text(resp.into()));
                        });
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

async fn ws_peer_handler(State(state): State<Arc<AppState>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| handle_peer_socket(socket, state))
}

async fn handle_peer_socket(mut socket: WebSocket, state: Arc<AppState>) {
    tracing::info!("peer connecting");
    if let Err(e) = handle_peer_socket_inner(&mut socket, state).await {
        tracing::error!("Error handling peer socket connection: {:?}", e);
    }
    tracing::info!("peer disconnected");
}

async fn handle_peer_socket_inner(
    socket: &mut WebSocket,
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let msg = match socket.recv().await {
        Some(Ok(msg)) => msg,
        _ => return Ok(()),
    };
    let text = msg.to_text()?;
    let init: PeerMessage = serde_json::from_str(text)?;
    let (peer_device_id, peer_challenge) = match init {
        PeerMessage::HandshakeInit {
            device_id,
            challenge_hex,
        } => (device_id, challenge_hex),
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
    socket
        .send(axum::extract::ws::Message::Text(
            serde_json::to_string(&resp)?.into(),
        ))
        .await?;

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

    let last_ts: i64 =
        sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(timestamp) FROM history WHERE device = ?")
            .bind(&peer_device_id)
            .fetch_one(&state.db)
            .await?
            .unwrap_or(0);

    let sync_req = PeerMessage::SyncRequest {
        last_timestamp: last_ts,
    };
    socket
        .send(axum::extract::ws::Message::Text(
            serde_json::to_string(&sync_req)?.into(),
        ))
        .await?;

    let tabs_sync_req = PeerMessage::TabsSyncRequest;
    socket
        .send(axum::extract::ws::Message::Text(
            serde_json::to_string(&tabs_sync_req)?.into(),
        ))
        .await?;

    while let Some(Ok(msg)) = socket.recv().await {
        if let Ok(text) = msg.to_text() {
            if let Ok(peer_msg) = serde_json::from_str::<PeerMessage>(text) {
                match peer_msg {
                    PeerMessage::SyncRequest { last_timestamp } => {
                        let rows = sqlx::query("SELECT uuid, url, normalized_url, title, timestamp, browser, device, hash, visit_type FROM history WHERE timestamp > ?")
                            .bind(last_timestamp)
                            .fetch_all(&state.db)
                            .await?;
                        let visits: Vec<HistoryItem> = rows
                            .into_iter()
                            .map(|row| {
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
                            })
                            .collect();
                        let resp = PeerMessage::SyncData { visits };
                        let _ = socket
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(&resp)?.into(),
                            ))
                            .await;
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
                    PeerMessage::TabsSyncRequest => {
                        let tabs = fetch_all_tabs(&state.db, None, None).await.unwrap_or_default();
                        let resp = PeerMessage::TabsSyncData { tabs };
                        let _ = socket
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(&resp)?.into(),
                            ))
                            .await;
                    }
                    PeerMessage::TabsSyncData { tabs } => {
                        let mut tx = state.db.begin().await?;
                        for tab in tabs {
                            sqlx::query(
                                "INSERT OR REPLACE INTO tabs (device_id, tab_id, url, title, favicon, window_id, active, pinned, last_active_at)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                            )
                            .bind(&tab.device_id)
                            .bind(tab.tab_id)
                            .bind(&tab.url)
                            .bind(&tab.title)
                            .bind(&tab.favicon)
                            .bind(tab.window_id)
                            .bind(tab.active)
                            .bind(tab.pinned)
                            .bind(tab.last_active_at)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn test_token_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let temp_dir =
            std::env::temp_dir().join(format!("besynx_token_test_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let token_path = temp_dir.join("besynx.token");

        // Creation test
        let token = if token_path.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600));
            }
            std::fs::read_to_string(&token_path)
                .unwrap_or_default()
                .trim()
                .to_string()
        } else {
            let t = uuid::Uuid::now_v7().to_string();
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&token_path)
                {
                    let _ = f.write_all(t.as_bytes());
                }
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600));
            }
            #[cfg(not(unix))]
            {
                let _ = std::fs::write(&token_path, &t);
            }
            t
        };

        assert!(!token.is_empty());
        let meta = std::fs::metadata(&token_path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        // Pre-existing file with 0644 should be reset to 0600
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            std::fs::metadata(&token_path).unwrap().permissions().mode() & 0o777,
            0o644
        );

        let read_token = if token_path.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600));
            }
            std::fs::read_to_string(&token_path)
                .unwrap_or_default()
                .trim()
                .to_string()
        } else {
            let t = uuid::Uuid::now_v7().to_string();
            t
        };

        assert_eq!(read_token, token);
        let meta_after = std::fs::metadata(&token_path).unwrap();
        assert_eq!(meta_after.permissions().mode() & 0o777, 0o600);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_validate_extension_origin() {
        let empty_allowed: Vec<String> = vec![];

        // Valid Chrome extension origin (32 chars in 'a'..='p')
        let valid_chrome = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
        assert!(validate_extension_origin(valid_chrome, &empty_allowed));

        // Chrome extension origin with trailing slash
        let valid_chrome_slash = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
        assert!(validate_extension_origin(valid_chrome_slash, &empty_allowed));

        // Invalid Chrome: wrong length
        assert!(!validate_extension_origin(
            "chrome-extension://abcdef",
            &empty_allowed
        ));
        assert!(!validate_extension_origin("chrome-extension://", &empty_allowed));

        // Invalid Chrome: contains characters outside 'a'..='p'
        let invalid_chars = "chrome-extension://abcdefghijklmnopabcdefghijklmnoz";
        assert!(!validate_extension_origin(invalid_chars, &empty_allowed));

        // Valid Firefox extension origin (valid UUID)
        let valid_firefox = "moz-extension://c3b2f56e-69bc-4ef1-8f5c-897db6422d35";
        assert!(validate_extension_origin(valid_firefox, &empty_allowed));

        // Invalid Firefox: not a UUID
        assert!(!validate_extension_origin("moz-extension://not-a-uuid", &empty_allowed));
        assert!(!validate_extension_origin("moz-extension://", &empty_allowed));

        // Non-extension origins blocked
        assert!(!validate_extension_origin("http://malicious.site", &empty_allowed));
        assert!(!validate_extension_origin("https://example.com", &empty_allowed));

        // Enforce configured allowed extension IDs
        let allowed = vec![
            "abcdefghijklmnopabcdefghijklmnop".to_string(),
            "c3b2f56e-69bc-4ef1-8f5c-897db6422d35".to_string(),
        ];
        assert!(validate_extension_origin(valid_chrome, &allowed));
        assert!(validate_extension_origin(valid_firefox, &allowed));

        // Disallowed valid extension ID
        let other_valid_chrome = "chrome-extension://pppppppppppppppppppppppppppppppp";
        assert!(!validate_extension_origin(other_valid_chrome, &allowed));
    }

    #[test]
    fn test_authenticate_request() {
        let expected = "secret-token-123";

        // 1. Authorization: Bearer <token>
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer secret-token-123".parse().unwrap());
        let uri = "/pair/challenge".parse().unwrap();
        assert!(authenticate_request(&headers, &uri, expected));

        // Bearer lowercase
        headers.insert("authorization", "bearer secret-token-123".parse().unwrap());
        assert!(authenticate_request(&headers, &uri, expected));

        // Raw token in authorization header
        headers.insert("authorization", "secret-token-123".parse().unwrap());
        assert!(authenticate_request(&headers, &uri, expected));

        // Wrong token in authorization
        headers.insert("authorization", "Bearer wrong".parse().unwrap());
        assert!(!authenticate_request(&headers, &uri, expected));

        // 2. X-Besynx-Token header
        headers.clear();
        headers.insert("x-besynx-token", "secret-token-123".parse().unwrap());
        assert!(authenticate_request(&headers, &uri, expected));

        headers.insert("x-besynx-token", "invalid".parse().unwrap());
        assert!(!authenticate_request(&headers, &uri, expected));

        // 3. Query parameter ?token=secret-token-123
        headers.clear();
        let uri_with_token = "/pair/challenge?token=secret-token-123".parse().unwrap();
        assert!(authenticate_request(&headers, &uri_with_token, expected));

        let uri_wrong_token = "/pair/challenge?token=wrong".parse().unwrap();
        assert!(!authenticate_request(&headers, &uri_wrong_token, expected));

        // Empty token / missing auth
        assert!(!authenticate_request(&headers, &uri, expected));
        assert!(!authenticate_request(&headers, &uri_with_token, ""));
    }

    #[tokio::test]
    async fn test_tabs_sqlite_lifecycle() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();

        // 1. Register tabs for Device A
        let tabs_a = vec![
            TabInput {
                tab_id: Some(1),
                id: None,
                url: "https://github.com/rust-lang/rust".to_string(),
                title: Some("Rust Repo".to_string()),
                favicon: Some("https://github.com/favicon.ico".to_string()),
                window_id: Some(1),
                active: Some(true),
                pinned: Some(false),
                last_active_at: Some(1000),
            },
            TabInput {
                tab_id: Some(2),
                id: None,
                url: "https://docs.rs/tokio".to_string(),
                title: Some("Tokio Docs".to_string()),
                favicon: None,
                window_id: Some(1),
                active: Some(false),
                pinned: Some(true),
                last_active_at: Some(900),
            },
        ];
        store_tabs_snapshot(&db, "device-a", &tabs_a)
            .await
            .unwrap();

        // 2. Register tabs for Device B
        let tabs_b = vec![TabInput {
            tab_id: Some(10),
            id: None,
            url: "https://sqlite.org/wal.html".to_string(),
            title: Some("SQLite WAL Mode".to_string()),
            favicon: None,
            window_id: Some(2),
            active: Some(true),
            pinned: Some(false),
            last_active_at: Some(1200),
        }];
        store_tabs_snapshot(&db, "device-b", &tabs_b)
            .await
            .unwrap();

        // 3. Query all tabs (synchronized across devices)
        let all_tabs = fetch_all_tabs(&db, None, None).await.unwrap();
        assert_eq!(all_tabs.len(), 3);
        assert_eq!(all_tabs[0].url, "https://sqlite.org/wal.html"); // highest last_active_at (1200)

        // 4. Query filtered by device
        let dev_a_tabs = fetch_all_tabs(&db, Some("device-a"), None).await.unwrap();
        assert_eq!(dev_a_tabs.len(), 2);

        // 5. Query filtered by search keyword
        let search_rust = fetch_all_tabs(&db, None, Some("rust")).await.unwrap();
        assert_eq!(search_rust.len(), 1);
        assert_eq!(search_rust[0].title, "Rust Repo");

        // 6. Update snapshot for Device A: replaces old tabs for device A
        let tabs_a_updated = vec![TabInput {
            tab_id: Some(3),
            id: None,
            url: "https://crates.io".to_string(),
            title: Some("Crates.io".to_string()),
            favicon: None,
            window_id: Some(1),
            active: Some(true),
            pinned: Some(false),
            last_active_at: Some(1500),
        }];
        store_tabs_snapshot(&db, "device-a", &tabs_a_updated)
            .await
            .unwrap();

        let dev_a_updated = fetch_all_tabs(&db, Some("device-a"), None).await.unwrap();
        assert_eq!(dev_a_updated.len(), 1);
        assert_eq!(dev_a_updated[0].url, "https://crates.io");

        // Device B tabs remain intact
        let dev_b_check = fetch_all_tabs(&db, Some("device-b"), None).await.unwrap();
        assert_eq!(dev_b_check.len(), 1);
    }

    #[tokio::test]
    async fn test_pair_endpoints_auth() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();

        let temp_key = std::env::temp_dir().join(format!("besynx_key_{}", uuid::Uuid::now_v7()));
        let identity = Arc::new(crypto::Identity::load_or_generate(&temp_key).unwrap());
        let _ = std::fs::remove_file(&temp_key);

        let state = Arc::new(AppState {
            db,
            identity,
            pending_challenges: Arc::new(Mutex::new(HashMap::new())),
            extension_txs: Arc::new(Mutex::new(HashMap::new())),
            token: "daemon-secret-test-token".to_string(),
            allowed_extension_ids: Arc::new(vec![]),
        });

        // 1. /pair/challenge without auth -> 401
        let no_headers = HeaderMap::new();
        let uri = "/pair/challenge".parse().unwrap();
        let res = pair_challenge(State(state.clone()), no_headers, uri).await;
        assert_eq!(res.unwrap_err(), StatusCode::UNAUTHORIZED);

        // 2. /pair/challenge with wrong token -> 401
        let mut bad_headers = HeaderMap::new();
        bad_headers.insert("authorization", "Bearer wrong-token".parse().unwrap());
        let uri = "/pair/challenge".parse().unwrap();
        let res = pair_challenge(State(state.clone()), bad_headers, uri).await;
        assert_eq!(res.unwrap_err(), StatusCode::UNAUTHORIZED);

        // 3. /pair/challenge with valid token -> 200 with challenge
        let mut good_headers = HeaderMap::new();
        good_headers.insert("authorization", "Bearer daemon-secret-test-token".parse().unwrap());
        let uri = "/pair/challenge".parse().unwrap();
        let res = pair_challenge(State(state.clone()), good_headers, uri).await;
        assert!(res.is_ok());
        let challenge = res.unwrap().0.challenge;
        assert!(!challenge.is_empty());

        // 4. /pair/response without auth -> 401
        let req = PairRequest {
            device_id: "test-dev".to_string(),
            device_name: "Test Dev".to_string(),
            public_key_hex: "aa".repeat(32),
            challenge_hex: challenge,
            signature_hex: "bb".repeat(64),
        };
        let no_headers = HeaderMap::new();
        let uri = "/pair/response".parse().unwrap();
        let res = pair_response(State(state.clone()), no_headers, uri, axum::Json(req)).await;
        assert_eq!(res.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_register_tabs_handler_auth() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();

        let temp_key = std::env::temp_dir().join(format!("besynx_key_{}", uuid::Uuid::now_v7()));
        let identity = Arc::new(crypto::Identity::load_or_generate(&temp_key).unwrap());
        let _ = std::fs::remove_file(&temp_key);

        let state = Arc::new(AppState {
            db,
            identity,
            pending_challenges: Arc::new(Mutex::new(HashMap::new())),
            extension_txs: Arc::new(Mutex::new(HashMap::new())),
            token: "tabs-secret-token".to_string(),
            allowed_extension_ids: Arc::new(vec![]),
        });

        let payload = RegisterTabsPayload::Object(TabsRegisterRequest {
            device_id: Some("laptop".to_string()),
            tabs: vec![TabInput {
                tab_id: Some(101),
                id: None,
                url: "https://besynx.local/test".to_string(),
                title: Some("BeSynx Test".to_string()),
                favicon: None,
                window_id: Some(1),
                active: Some(true),
                pinned: Some(false),
                last_active_at: Some(2000),
            }],
        });

        // 1. Unauthorized register -> 401
        let no_headers = HeaderMap::new();
        let uri = "/v1/tabs/register".parse().unwrap();
        let res = register_tabs_handler(
            State(state.clone()),
            no_headers,
            uri,
            axum::Json(payload.clone()),
        )
        .await;
        assert_eq!(res.unwrap_err(), StatusCode::UNAUTHORIZED);

        // 2. Authorized register -> 200
        let mut good_headers = HeaderMap::new();
        good_headers.insert("x-besynx-token", "tabs-secret-token".parse().unwrap());
        let uri = "/v1/tabs/register".parse().unwrap();
        let res = register_tabs_handler(
            State(state.clone()),
            good_headers,
            uri,
            axum::Json(payload),
        )
        .await;
        assert!(res.is_ok());

        // 3. Query tabs -> 200 with registered tab
        let query_res = get_tabs_handler(
            State(state.clone()),
            Query(TabsFilterQuery {
                device_id: None,
                q: None,
            }),
        )
        .await;
        assert!(query_res.is_ok());
        let fetched = query_res.unwrap().0.tabs;
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].device_id, "laptop");
        assert_eq!(fetched[0].url, "https://besynx.local/test");
    }
}
