use std::sync::{Arc, Mutex};
use std::process::Child;
use std::io::{BufRead, BufReader};
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    Manager,
};

struct DaemonState {
    child: Arc<Mutex<Option<Child>>>,
    logs: Arc<Mutex<Vec<String>>>,
}

struct AppDbState {
    pool: sqlx::SqlitePool,
}

impl Drop for DaemonState {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
        }
    }
}

#[derive(serde::Serialize)]
struct DashboardStats {
    daemon_status: String,
    browser_count: i64,
    last_sync: Option<i64>,
    history_count: i64,
    devices: Vec<DeviceEntry>,
}

#[derive(serde::Serialize, sqlx::FromRow)]
struct DeviceEntry {
    id: String,
    name: String,
    last_seen: i64,
}

#[tauri::command]
async fn get_stats(
    daemon_state: tauri::State<'_, DaemonState>,
    db_state: tauri::State<'_, AppDbState>,
) -> Result<DashboardStats, String> {
    let daemon_status = {
        let mut lock = daemon_state.child.lock().unwrap();
        if let Some(child) = lock.as_mut() {
            match child.try_wait() {
                Ok(None) => "Running".to_string(),
                _ => {
                    *lock = None;
                    "Stopped".to_string()
                }
            }
        } else {
            "Stopped".to_string()
        }
    };

    let pool = &db_state.pool;

    let browser_count: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT browser) FROM history")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    let last_sync: Option<i64> = sqlx::query_scalar("SELECT MAX(timestamp) FROM history")
        .fetch_one(pool)
        .await
        .unwrap_or(None);

    let history_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM history WHERE deleted = 0")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    let devices: Vec<DeviceEntry> = sqlx::query_as("SELECT id, name, last_seen FROM devices")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    Ok(DashboardStats {
        daemon_status,
        browser_count,
        last_sync,
        history_count,
        devices,
    })
}

#[tauri::command]
fn get_daemon_logs(state: tauri::State<'_, DaemonState>) -> Vec<String> {
    state.logs.lock().unwrap().clone()
}

fn get_daemon_path() -> std::path::PathBuf {
    let mut daemon_path = std::env::current_exe().unwrap();
    daemon_path.pop(); // Remove app binary name
    daemon_path.push(if cfg!(target_os = "windows") { "besynx-daemon.exe" } else { "besynx-daemon" });
    if !daemon_path.exists() {
        daemon_path = std::path::PathBuf::from(if cfg!(target_os = "windows") { "besynx-daemon.exe" } else { "besynx-daemon" });
    }
    daemon_path
}

#[tauri::command]
fn control_daemon(state: tauri::State<'_, DaemonState>, action: String) -> Result<String, String> {
    let mut lock = state.child.lock().unwrap();
    if action == "start" {
        if lock.is_none() {
            let daemon_path = get_daemon_path();
            let mut child = std::process::Command::new(daemon_path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?;
            
            let logs = state.logs.clone();
            if let Some(stdout) = child.stdout.take() {
                let logs = logs.clone();
                std::thread::spawn(move || {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines() {
                        if let Ok(line) = line {
                            let mut l = logs.lock().unwrap();
                            l.push(line);
                            if l.len() > 100 {
                                l.remove(0);
                            }
                        }
                    }
                });
            }
            if let Some(stderr) = child.stderr.take() {
                let logs = logs.clone();
                std::thread::spawn(move || {
                    let reader = BufReader::new(stderr);
                    for line in reader.lines() {
                        if let Ok(line) = line {
                            let mut l = logs.lock().unwrap();
                            l.push(line);
                            if l.len() > 100 {
                                l.remove(0);
                            }
                        }
                    }
                });
            }
            *lock = Some(child);
            Ok("Daemon started".to_string())
        } else {
            Err("Daemon already running".to_string())
        }
    } else if action == "stop" {
        if let Some(mut child) = lock.take() {
            let _ = child.kill();
            Ok("Daemon stopped".to_string())
        } else {
            Err("Daemon not running".to_string())
        }
    } else {
        Err("Invalid action".to_string())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let db_path = protocol::get_config_dir().join("besynx.db");
    if !db_path.exists() {
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::File::create(&db_path);
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    let pool = rt.block_on(async {
        let p = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path.to_string_lossy()))
            .await
            .expect("Failed to connect to SQLite database");
        let _ = sqlx::migrate!("../../daemon/migrations").run(&p).await;
        p
    });

    let daemon_state = DaemonState {
        child: Arc::new(Mutex::new(None)),
        logs: Arc::new(Mutex::new(Vec::new())),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(daemon_state)
        .manage(AppDbState { pool })
        .invoke_handler(tauri::generate_handler![get_stats, get_daemon_logs, control_daemon])
        .setup(|app| {
            let daemon_path = get_daemon_path();
            let child = std::process::Command::new(daemon_path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn();
            
            match child {
                Ok(mut c) => {
                    let state = app.state::<DaemonState>();
                    let logs = state.logs.clone();
                    if let Some(stdout) = c.stdout.take() {
                        let logs = logs.clone();
                        std::thread::spawn(move || {
                            let reader = BufReader::new(stdout);
                            for line in reader.lines() {
                                if let Ok(line) = line {
                                    let mut l = logs.lock().unwrap();
                                    l.push(line);
                                    if l.len() > 100 {
                                        l.remove(0);
                                    }
                                }
                            }
                        });
                    }
                    if let Some(stderr) = c.stderr.take() {
                        let logs = logs.clone();
                        std::thread::spawn(move || {
                            let reader = BufReader::new(stderr);
                            for line in reader.lines() {
                                if let Ok(line) = line {
                                    let mut l = logs.lock().unwrap();
                                    l.push(line);
                                    if l.len() > 100 {
                                        l.remove(0);
                                    }
                                }
                            }
                        });
                    }
                    *state.child.lock().unwrap() = Some(c);
                    println!("Daemon started successfully");
                }
                Err(e) => {
                    eprintln!("Failed to start daemon: {}", e);
                }
            }

            let status_i = MenuItem::with_id(app, "status", "Status: Daemon Running", false, None::<&str>)?;
            let stats_i = MenuItem::with_id(app, "stats", "Last Sync: N/A", false, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let show_i = MenuItem::with_id(app, "show", "Open Dashboard", true, None::<&str>)?;
            let hide_i = MenuItem::with_id(app, "hide", "Hide Dashboard", true, None::<&str>)?;
            let sep1 = PredefinedMenuItem::separator(app)?;
            let sep2 = PredefinedMenuItem::separator(app)?;

            let menu = Menu::with_items(
                app,
                &[
                    &status_i,
                    &stats_i,
                    &sep1,
                    &show_i,
                    &hide_i,
                    &sep2,
                    &quit_i,
                ],
            )?;

            let status_clone = status_i.clone();
            let stats_clone = stats_i.clone();
            let state = app.state::<DaemonState>();
            let child_lock = state.child.clone();
            let pool_clone = app.state::<AppDbState>().pool.clone();

            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(2));

                    let is_running = {
                        let mut lock = child_lock.lock().unwrap();
                        if let Some(child) = lock.as_mut() {
                            match child.try_wait() {
                                Ok(None) => true,
                                _ => {
                                    *lock = None;
                                    false
                                }
                            }
                        } else {
                            false
                        }
                    };

                    let status_text = if is_running { "Status: Daemon Running" } else { "Status: Daemon Stopped" };
                    let _ = status_clone.set_text(status_text);

                    let rt = tokio::runtime::Runtime::new().unwrap();
                    let last_sync: Option<i64> = rt.block_on(async {
                        sqlx::query_scalar("SELECT MAX(timestamp) FROM history")
                            .fetch_one(&pool_clone)
                            .await
                            .unwrap_or(None)
                    });

                    let stats_text = match last_sync {
                        Some(ts) => {
                            if let Some(dt) = chrono::DateTime::from_timestamp_millis(ts) {
                                format!("Last Sync: {}", dt.format("%Y-%m-%d %H:%M:%S"))
                            } else {
                                "Last Sync: Invalid timestamp".to_string()
                            }
                        }
                        None => "Last Sync: N/A".to_string(),
                    };
                    let _ = stats_clone.set_text(stats_text);
                }
            });

            let icon = app.default_window_icon().cloned().expect("failed to get default window icon");

            let _tray = TrayIconBuilder::new()
                .icon(icon)
                .menu(&menu)
                .on_menu_event(|app, event| {
                    match event.id.as_ref() {
                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "hide" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.hide();
                            }
                        }
                        "quit" => {
                            let state = app.state::<DaemonState>();
                            if let Some(mut child) = state.child.lock().unwrap().take() {
                                let _ = child.kill();
                            }
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
