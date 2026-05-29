//! commands.rs
//!
//! All `#[tauri::command]` handlers exposed to the frontend.
//!
//! AppState now holds both the SidecarManager and a DbManager so every
//! command has access to live capture control AND persistent storage.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};

use crate::db::{
    DbManager, DiagnosticsData, PacketFilters, PacketRow,
    PaginatedResult, Session,
};
use crate::sniffer::{Interface, SidecarManager, Stats};

// ─────────────────────────────────────────────────────────────────────────────
// Application-wide state
// ─────────────────────────────────────────────────────────────────────────────

pub struct AppState {
    pub sniffer:            Mutex<SidecarManager>,
    pub db:                 Arc<DbManager>,
    /// Active session id (set on start_capture, cleared on stop_capture).
    pub active_session_id:  Mutex<Option<i64>>,
}

impl AppState {
    pub fn new(db: Arc<DbManager>) -> Self {
        Self {
            sniffer:           Mutex::new(SidecarManager::new()),
            db,
            active_session_id: Mutex::new(None),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal lock helpers
// ─────────────────────────────────────────────────────────────────────────────

macro_rules! lock {
    ($mutex:expr) => {
        $mutex
            .lock()
            .map_err(|e| format!("mutex poisoned: {e}"))
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Capture lifecycle
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters accepted by `start_capture`.
#[derive(Debug, Deserialize)]
pub struct StartCaptureArgs {
    pub interface_id:   u32,
    /// Human-readable session label (optional, defaults to interface name).
    pub session_name:   Option<String>,
    /// Interface name string for DB storage (e.g. "eth0").
    pub interface_name: Option<String>,
}

/// Start packet capture and open a new DB session.
///
/// ```ts
/// await invoke('start_capture', {
///   interfaceId: 0,
///   sessionName: 'Morning traffic',
///   interfaceName: 'eth0',
/// });
/// ```
#[tauri::command]
pub fn start_capture(
    args:  StartCaptureArgs,
    app:   AppHandle,
    state: State<'_, AppState>,
) -> Result<i64, String> {
    let mut sniffer = lock!(state.sniffer)?;

    if sniffer.is_running() {
        return Err("Capture already running. Call stop_capture first.".into());
    }

    // Create a DB session before spawning so the session_id is known.
    let session_id = state
        .db
        .create_session(
            args.session_name.as_deref(),
            args.interface_name.as_deref(),
        )
        .map_err(|e| format!("create_session failed: {e}"))?;

    *lock!(state.active_session_id)? = Some(session_id);

    sniffer
        .start(app, args.interface_id)
        .map_err(|e| format!("start_capture failed: {e}"))?;

    Ok(session_id)
}

/// Stop the active capture and close the DB session.
///
/// ```ts
/// await invoke('stop_capture');
/// ```
#[tauri::command]
pub fn stop_capture(state: State<'_, AppState>) -> Result<(), String> {
    let mut sniffer = lock!(state.sniffer)?;

    if !sniffer.is_running() {
        return Ok(());
    }

    sniffer
        .stop()
        .map_err(|e| format!("stop_capture failed: {e}"))?;

    // Close DB session
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

/// Restart capture on a different interface.
///
/// ```ts
/// await invoke('set_interface', { interfaceId: 2 });
/// ```
#[tauri::command]
pub fn set_interface(
    interface_id: u32,
    app:   AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut sniffer = lock!(state.sniffer)?;

    if sniffer.is_running() {
        sniffer
            .stop()
            .map_err(|e| format!("set_interface/stop: {e}"))?;
    }

    sniffer
        .start(app, interface_id)
        .map_err(|e| format!("set_interface/start: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// BPF filter
// ─────────────────────────────────────────────────────────────────────────────

/// Apply a BPF filter expression to the running capture.
///
/// ```ts
/// await invoke('set_bpf_filter', { filter: 'tcp port 443' });
/// ```
#[tauri::command]
pub fn set_bpf_filter(
    filter: String,
    state:  State<'_, AppState>,
) -> Result<(), String> {
    let sniffer = lock!(state.sniffer)?;

    if !sniffer.is_running() {
        return Err("No active capture. Call start_capture first.".into());
    }

    sniffer
        .set_filter(&filter)
        .map_err(|e| format!("set_bpf_filter: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Interfaces
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ListInterfacesResponse {
    pub interfaces: Vec<Interface>,
    pub refreshed:  bool,
}

/// Return available network interfaces (cached + async refresh if running).
///
/// ```ts
/// const { interfaces } = await invoke<ListInterfacesResponse>('list_interfaces');
/// ```
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

// ─────────────────────────────────────────────────────────────────────────────
// Live stats
// ─────────────────────────────────────────────────────────────────────────────

/// Pull-based stats snapshot (also pushed via "net_stats" event every 1 s).
///
/// ```ts
/// const stats = await invoke<Stats>('get_stats');
/// ```
#[tauri::command]
pub fn get_stats(state: State<'_, AppState>) -> Result<Stats, String> {
    let sniffer = lock!(state.sniffer)?;
    Ok(sniffer.get_stats())
}

/// Whether the sidecar is currently capturing.
///
/// ```ts
/// const { running } = await invoke<CaptureStatusResponse>('capture_status');
/// ```
#[derive(Debug, Serialize)]
pub struct CaptureStatusResponse {
    pub running:    bool,
    pub session_id: Option<i64>,
}

#[tauri::command]
pub fn capture_status(state: State<'_, AppState>) -> Result<CaptureStatusResponse, String> {
    let sniffer    = lock!(state.sniffer)?;
    let session_id = lock!(state.active_session_id)?.clone();
    Ok(CaptureStatusResponse {
        running: sniffer.is_running(),
        session_id,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Session management commands
// ─────────────────────────────────────────────────────────────────────────────

/// List all recorded sessions (newest first).
///
/// ```ts
/// const sessions = await invoke<Session[]>('list_sessions');
/// ```
#[tauri::command]
pub fn list_sessions(state: State<'_, AppState>) -> Result<Vec<Session>, String> {
    state.db.list_sessions()
}

/// Delete a session and all its packets.
///
/// ```ts
/// await invoke('delete_session', { sessionId: 3 });
/// ```
#[tauri::command]
pub fn delete_session(
    session_id: i64,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // Refuse to delete the currently active session
    let active = lock!(state.active_session_id)?.clone();
    if active == Some(session_id) {
        return Err("Cannot delete the active capture session.".into());
    }
    state.db.delete_session(session_id)
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet persistence — write path
// ─────────────────────────────────────────────────────────────────────────────

/// Persist a single packet into the current session.
///
/// Intended to be called from the Rust event handler inside `sniffer.rs`
/// rather than from the frontend directly, but exposed as a command for
/// testing / replay scenarios.
///
/// ```ts
/// await invoke('persist_packet', { packet: { ... } });
/// ```
#[tauri::command]
pub fn persist_packet(
    packet: PacketRow,
    state:  State<'_, AppState>,
) -> Result<(), String> {
    let session_id = lock!(state.active_session_id)?
        .ok_or_else(|| "No active session".to_string())?;

    state
        .db
        .insert_packet(session_id, &packet)
        .map_err(|e| format!("persist_packet: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet query — paginated read path
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `query_packets`.
#[derive(Debug, Deserialize)]
pub struct QueryPacketsArgs {
    pub session_id: i64,
    pub filters:    PacketFilters,
    pub page:       u32,
    pub page_size:  u32,
}

/// Paginated, filtered packet query.
///
/// ```ts
/// const result = await invoke<PaginatedResult<PacketRow>>('query_packets', {
///   sessionId: 1,
///   filters: { protocol: 'HTTPS', minLength: 100 },
///   page: 1,
///   pageSize: 100,
/// });
/// // result.items   — packets on this page
/// // result.total   — total matching rows
/// // result.totalPages
/// ```
#[tauri::command]
pub fn query_packets(
    args:  QueryPacketsArgs,
    state: State<'_, AppState>,
) -> Result<PaginatedResult<PacketRow>, String> {
    state.db.get_packets_paginated(
        args.session_id,
        &args.filters,
        args.page,
        args.page_size,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Diagnostics & analytics
// ─────────────────────────────────────────────────────────────────────────────

/// Return the full analytics bundle for a session.
///
/// Includes protocol distribution, traffic timeline (5-second buckets),
/// top source and destination IPs, byte totals, and recent error rows.
///
/// ```ts
/// const data = await invoke<DiagnosticsData>('get_diagnostics_data', {
///   sessionId: 1,
/// });
/// ```
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

/// Record a named metric in the diagnostics table.
///
/// ```ts
/// await invoke('record_diagnostic', {
///   sessionId: 1, metric: 'drop_rate', value: 0.03,
/// });
/// ```
#[tauri::command]
pub fn record_diagnostic(
    session_id: i64,
    metric:     String,
    value:      f64,
    state:      State<'_, AppState>,
) -> Result<(), String> {
    state
        .db
        .insert_diagnostic(session_id, &metric, value)
        .map_err(|e| format!("record_diagnostic: {e}"))
}

/// Export all packets for a session as a JSON array string.
///
/// Intended for "Save capture" / CSV-export workflows in the frontend.
///
/// ```ts
/// const json = await invoke<string>('export_packets_json', { sessionId: 1 });
/// ```
#[tauri::command]
pub fn export_packets_json(
    session_id: i64,
    filters:    Option<PacketFilters>,
    state:      State<'_, AppState>,
) -> Result<String, String> {
    let f = filters.unwrap_or_default();
    let rows = state
        .db
        .get_packets(session_id, &f)
        .map_err(|e| format!("export_packets_json/get: {e}"))?;

    serde_json::to_string(&rows)
        .map_err(|e| format!("export_packets_json/serialize: {e}"))
}
