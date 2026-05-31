mod commands;
mod db;
mod sniffer;

use std::sync::Arc;

use commands::AppState;
use tauri::Manager;
#[cfg(target_os = "windows")]
use window_vibrancy::apply_acrylic;
#[cfg(target_os = "macos")]
use window_vibrancy::{apply_vibrancy, NSVisualEffectMaterial};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .setup(|app| {
            // ES: Inicializa SQLite antes de registrar el estado compartido.
            // EN: Initialize SQLite before registering shared state.
            let data_dir = app
                .path()
                .app_data_dir()
                .expect("cannot resolve app data dir");

            let db =
                Arc::new(db::DbManager::new(data_dir).expect("failed to open/create netscope.db"));

            app.manage(AppState::new(db));

            // ES: Aplica blur nativo y muestra la ventana tras completar setup.
            // EN: Apply native blur and reveal the window after setup completes.
            if let Some(win) = app.get_webview_window("main") {
                #[cfg(target_os = "windows")]
                let _ = apply_acrylic(&win, Some((18, 18, 18, 125)));
                #[cfg(target_os = "macos")]
                let _ = apply_vibrancy(&win, NSVisualEffectMaterial::HudWindow, None, None);
                let _ = win.show();
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::start_capture,
            commands::stop_capture,
            commands::set_interface,
            commands::capture_status,
            commands::set_bpf_filter,
            commands::list_interfaces,
            commands::get_stats,
            commands::list_sessions,
            commands::delete_session,
            commands::persist_packet,
            commands::query_packets,
            commands::get_diagnostics_data,
            commands::record_diagnostic,
            commands::export_packets_json,
        ])
        .run(tauri::generate_context!())
        .expect("error while running netscope application");
}
