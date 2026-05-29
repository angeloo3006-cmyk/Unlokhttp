//! lib.rs — Tauri application entry-point.

mod commands;
mod db;
mod sniffer;

use std::sync::Arc;

use commands::AppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // ── Plugins ──────────────────────────────────────────────────────
        .plugin(tauri_plugin_shell::init())
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .build(),
        )
        // ── Setup: DB init before state is managed ────────────────────────
        .setup(|app| {
            // Resolve the platform app-data directory.
            // On Linux  : ~/.local/share/com.netscope.app/
            // On Windows: %APPDATA%\com.netscope.app\
            // On macOS  : ~/Library/Application Support/com.netscope.app/
            let data_dir = app
                .path()
                .app_data_dir()
                .expect("cannot resolve app data dir");

            let db = Arc::new(
                db::DbManager::new(data_dir)
                    .expect("failed to open/create netscope.db"),
            );

            // Register combined state (sniffer + db + active session)
            app.manage(AppState::new(db));

            // Show the main window (it starts hidden so there's no flash)
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
            }

            Ok(())
        })
        // ── Commands ──────────────────────────────────────────────────────
        .invoke_handler(tauri::generate_handler![
            // Capture lifecycle
            commands::start_capture,
            commands::stop_capture,
            commands::set_interface,
            commands::capture_status,
            // BPF
            commands::set_bpf_filter,
            // Interfaces
            commands::list_interfaces,
            // Live stats
            commands::get_stats,
            // Session management
            commands::list_sessions,
            commands::delete_session,
            // Packet write
            commands::persist_packet,
            // Packet read
            commands::query_packets,
            // Diagnostics / analytics
            commands::get_diagnostics_data,
            commands::record_diagnostic,
            commands::export_packets_json,
        ])
        .run(tauri::generate_context!())
        .expect("error while running netscope application");
}
