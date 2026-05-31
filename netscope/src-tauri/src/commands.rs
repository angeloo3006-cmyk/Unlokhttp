use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};

use crate::db::{DbManager, DiagnosticsData, PacketFilters, PacketRow, PaginatedResult, Session};
use crate::sniffer::{Interface, SidecarManager, Stats};

// ES: Estado global compartido por todos los comandos Tauri. / EN: Global state shared by all Tauri commands.
pub struct AppState {
    pub sniffer: Mutex<SidecarManager>,
    pub db: Arc<DbManager>,
    pub active_session_id: Arc<Mutex<Option<i64>>>,
}

impl AppState {
    pub fn new(db: Arc<DbManager>) -> Self {
        Self {
            sniffer: Mutex::new(SidecarManager::new()),
            db,
            active_session_id: Arc::new(Mutex::new(None)),
        }
    }
}

macro_rules! lock {
    ($mutex:expr) => {
        $mutex.lock().map_err(|e| format!("mutex poisoned: {e}"))
    };
}

#[derive(Debug, Deserialize)]
pub struct StartCaptureArgs {
    pub interface_id: u32,
    pub session_name: Option<String>,
    pub interface_name: Option<String>,
}

#[tauri::command]
pub fn start_capture(
    args: StartCaptureArgs,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<i64, String> {
    let mut sniffer = lock!(state.sniffer)?;

    if sniffer.is_running() {
        return Err("Capture already running. Call stop_capture first.".into());
    }

    // ES: Crea primero la sesion para asociar los paquetes desde el primer evento.
    // EN: Create the session first so packets are associated from the first event.
    let session_id = state
        .db
        .create_session(args.session_name.as_deref(), args.interface_name.as_deref())
        .map_err(|e| format!("create_session failed: {e}"))?;

    *lock!(state.active_session_id)? = Some(session_id);

    if let Err(error) = sniffer.start(
        app,
        args.interface_id,
        Arc::clone(&state.db),
        Arc::clone(&state.active_session_id),
    ) {
        *lock!(state.active_session_id)? = None;
        let _ = state.db.delete_session(session_id);
        return Err(format!("start_capture failed: {error}"));
    }

    Ok(session_id)
}

#[tauri::command]
pub fn stop_capture(state: State<'_, AppState>) -> Result<(), String> {
    let mut sniffer = lock!(state.sniffer)?;

    if sniffer.is_running() {
        sniffer
            .stop()
            .map_err(|e| format!("stop_capture failed: {e}"))?;
    }

    let session_id = lock!(state.active_session_id)?.take();
    if let Some(sid) = session_id {
        let total = state
            .db
            .get_session_summary(sid)
            .map(|(n, _, _)| n)
            .unwrap_or(0);
        state
            .db
            .close_session(sid, total)
            .map_err(|e| format!("close_session failed: {e}"))?;
    }

    Ok(())
}

#[tauri::command]
pub fn set_interface(interface_id: u32, state: State<'_, AppState>) -> Result<(), String> {
    let sniffer = lock!(state.sniffer)?;
    if sniffer.is_running() {
        return Err("Stop capture before changing the interface.".into());
    }
    let _ = interface_id;
    Ok(())
}

#[tauri::command]
pub fn set_bpf_filter(filter: String, state: State<'_, AppState>) -> Result<(), String> {
    let sniffer = lock!(state.sniffer)?;

    if !sniffer.is_running() {
        return Err("No active capture. Call start_capture first.".into());
    }

    sniffer
        .set_filter(&filter)
        .map_err(|e| format!("set_bpf_filter: {e}"))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListInterfacesResponse {
    pub interfaces: Vec<Interface>,
    pub refreshed: bool,
}

#[tauri::command]
pub fn list_interfaces(state: State<'_, AppState>) -> Result<ListInterfacesResponse, String> {
    let sniffer = lock!(state.sniffer)?;

    let refreshed = if sniffer.is_running() {
        sniffer
            .list_interfaces()
            .map_err(|e| format!("list_interfaces send: {e}"))?;
        true
    } else {
        false
    };

    Ok(ListInterfacesResponse {
        interfaces: sniffer.get_interfaces(),
        refreshed,
    })
}

#[tauri::command]
pub fn get_stats(state: State<'_, AppState>) -> Result<Stats, String> {
    let sniffer = lock!(state.sniffer)?;
    Ok(sniffer.get_stats())
}

#[derive(Debug, Serialize)]
pub struct CaptureStatusResponse {
    pub running: bool,
    pub session_id: Option<i64>,
}

#[tauri::command]
pub fn capture_status(state: State<'_, AppState>) -> Result<CaptureStatusResponse, String> {
    let sniffer = lock!(state.sniffer)?;
    let session_id = lock!(state.active_session_id)?.clone();
    Ok(CaptureStatusResponse {
        running: sniffer.is_running(),
        session_id,
    })
}

#[tauri::command]
pub fn list_sessions(state: State<'_, AppState>) -> Result<Vec<Session>, String> {
    state.db.list_sessions()
}

#[tauri::command]
pub fn delete_session(session_id: i64, state: State<'_, AppState>) -> Result<(), String> {
    let active = lock!(state.active_session_id)?.clone();
    if active == Some(session_id) {
        return Err("Cannot delete the active capture session.".into());
    }
    state.db.delete_session(session_id)
}

#[tauri::command]
pub fn persist_packet(packet: PacketRow, state: State<'_, AppState>) -> Result<(), String> {
    let session_id =
        lock!(state.active_session_id)?.ok_or_else(|| "No active session".to_string())?;

    state
        .db
        .insert_packet(session_id, &packet)
        .map_err(|e| format!("persist_packet: {e}"))
}

#[derive(Debug, Deserialize)]
pub struct QueryPacketsArgs {
    pub session_id: i64,
    pub filters: PacketFilters,
    pub page: u32,
    pub page_size: u32,
}

#[tauri::command]
pub fn query_packets(
    args: QueryPacketsArgs,
    state: State<'_, AppState>,
) -> Result<PaginatedResult<PacketRow>, String> {
    state
        .db
        .get_packets_paginated(args.session_id, &args.filters, args.page, args.page_size)
}

#[tauri::command]
pub fn get_diagnostics_data(
    session_id: i64,
    state: State<'_, AppState>,
) -> Result<DiagnosticsData, String> {
    state
        .db
        .build_diagnostics_data(session_id)
        .map_err(|e| format!("get_diagnostics_data: {e}"))
}

#[tauri::command]
pub fn record_diagnostic(
    session_id: i64,
    metric: String,
    value: f64,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .db
        .insert_diagnostic(session_id, &metric, value)
        .map_err(|e| format!("record_diagnostic: {e}"))
}

#[tauri::command]
pub fn export_packets_json(
    session_id: i64,
    filters: Option<PacketFilters>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let f = filters.unwrap_or_default();
    let rows = state
        .db
        .get_packets(session_id, &f)
        .map_err(|e| format!("export_packets_json/get: {e}"))?;

    serde_json::to_string(&rows).map_err(|e| format!("export_packets_json/serialize: {e}"))
}
