use std::sync::Mutex;
use std::process::Child;
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    Manager,
};

struct DaemonState {
    child: Mutex<Option<Child>>,
}

impl Drop for DaemonState {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
        }
    }
}

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(DaemonState {
            child: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![greet])
        .setup(|app| {
            // Start the daemon process
            let daemon_path = std::path::Path::new("/home/whysooraj/Documents/besynx/target/debug/besynx-daemon");
            let child = std::process::Command::new(daemon_path)
                .spawn();
            
            match child {
                Ok(c) => {
                    let state = app.state::<DaemonState>();
                    *state.child.lock().unwrap() = Some(c);
                    println!("Daemon started successfully");
                }
                Err(e) => {
                    eprintln!("Failed to start daemon: {}", e);
                }
            }

            // Create tray menu
            let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let show_i = MenuItem::with_id(app, "show", "Open Dashboard", true, None::<&str>)?;
            let hide_i = MenuItem::with_id(app, "hide", "Hide Dashboard", true, None::<&str>)?;
            let status_i = MenuItem::with_id(app, "status", "Status: Daemon Running", false, None::<&str>)?;
            let stats_i = MenuItem::with_id(app, "stats", "Last Sync: N/A", false, None::<&str>)?;
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
