use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;
use tokio::sync::mpsc::{self, UnboundedSender};

use crate::db::{DbManager, PacketRow};

// ES: Tipos compartidos con los comandos Tauri. / EN: Types shared with Tauri commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub id: u32,
    pub name: String,
    pub desc: String,
    pub loopback: bool,
    pub up: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Stats {
    pub captured: u64,
    pub dropped: u64,
    pub rate_pps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub id: u64,
    pub ts: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub length: u32,
    pub ttl: Option<u8>,
    pub flags: String,
    pub payload_hex: String,
    pub raw_ascii: String,
}

#[derive(Debug, Default)]
struct Snapshot {
    stats: Stats,
    interfaces: Vec<Interface>,
}

// ES: Administra el proceso C++ y su estado compartido. / EN: Manages the C++ process and its shared state.
pub struct SidecarManager {
    child: Arc<Mutex<Option<CommandChild>>>,

    tx_cmd: Option<UnboundedSender<String>>,

    pub running: Arc<AtomicBool>,

    stopping: Arc<AtomicBool>,

    snapshot: Arc<Mutex<Snapshot>>,
}

impl SidecarManager {
    pub fn new() -> Self {
        Self {
            child: Arc::new(Mutex::new(None)),
            tx_cmd: None,
            running: Arc::new(AtomicBool::new(false)),
            stopping: Arc::new(AtomicBool::new(false)),
            snapshot: Arc::new(Mutex::new(Snapshot::default())),
        }
    }

    pub fn get_stats(&self) -> Stats {
        self.snapshot
            .lock()
            .map(|s| s.stats.clone())
            .unwrap_or_default()
    }

    pub fn get_interfaces(&self) -> Vec<Interface> {
        self.snapshot
            .lock()
            .map(|s| s.interfaces.clone())
            .unwrap_or_default()
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn start(
        &mut self,
        app: AppHandle,
        interface_id: u32,
        db: Arc<DbManager>,
        active_session_id: Arc<Mutex<Option<i64>>>,
    ) -> Result<(), String> {
        if self.is_running() {
            self.stop_inner()?;
        }

        let (mut rx_evt, child) = app
            .shell()
            .sidecar("sniffer_core")
            .map_err(|e| format!("sidecar lookup failed: {e}"))?
            .spawn()
            .map_err(|e| format!("sidecar spawn failed: {e}"))?;

        let (tx_cmd, mut rx_cmd) = mpsc::unbounded_channel::<String>();

        *self.child.lock().map_err(|e| e.to_string())? = Some(child);
        self.tx_cmd = Some(tx_cmd.clone());
        self.running.store(true, Ordering::SeqCst);
        self.stopping.store(false, Ordering::SeqCst);

        let running_r = Arc::clone(&self.running);
        let running_w = Arc::clone(&self.running);
        let stopping_r = Arc::clone(&self.stopping);
        let snapshot = Arc::clone(&self.snapshot);
        let db_r = Arc::clone(&db);
        let session_r = Arc::clone(&active_session_id);
        let app_r = app.clone();

        // ES: Convierte stdout JSONL en eventos Tauri y persistencia SQLite.
        // EN: Converts JSONL stdout into Tauri events and SQLite persistence.
        tauri::async_runtime::spawn(async move {
            while let Some(event) = rx_evt.recv().await {
                match event {
                    CommandEvent::Stdout(line) => {
                        let text = match String::from_utf8(line) {
                            Ok(t) => t.trim().to_owned(),
                            Err(_) => continue,
                        };
                        if text.is_empty() {
                            continue;
                        }

                        handle_stdout_line(&text, &app_r, &snapshot, &db_r, &session_r);
                    }

                    CommandEvent::Stderr(line) => {
                        let msg = String::from_utf8_lossy(&line).to_string();
                        eprintln!("[sniffer_core stderr] {msg}");
                        let _ = app_r.emit("sniffer_error", json!({ "msg": msg }));
                    }

                    CommandEvent::Error(e) => {
                        eprintln!("[sniffer_core error] {e}");
                        let _ = app_r.emit("sniffer_error", json!({ "msg": e }));
                        break;
                    }

                    CommandEvent::Terminated(status) => {
                        eprintln!(
                            "[sniffer_core] process terminated: code={:?} signal={:?}",
                            status.code, status.signal
                        );
                        if !stopping_r.swap(false, Ordering::SeqCst) {
                            let _ = app_r.emit(
                                "sniffer_error",
                                json!({ "msg": "sniffer_core process terminated unexpectedly" }),
                            );
                        }
                        break;
                    }

                    _ => {}
                }
            }
            running_r.store(false, Ordering::SeqCst);
            close_active_session(&db_r, &session_r);
            let _ = app_r.emit("capture_state", json!({ "running": false }));
        });
        let child_ref_w = Arc::clone(&self.child);

        // ES: write() es sincrono; spawn_blocking evita bloquear el ejecutor asincrono.
        // EN: write() is synchronous; spawn_blocking keeps the async executor responsive.
        tauri::async_runtime::spawn(async move {
            while let Some(cmd_str) = rx_cmd.recv().await {
                let mut line = cmd_str;
                if !line.ends_with('\n') {
                    line.push('\n');
                }

                let child_clone = Arc::clone(&child_ref_w);
                let result = tauri::async_runtime::spawn_blocking(move || {
                    let mut guard = child_clone.lock().map_err(|e| e.to_string())?;
                    let child = guard
                        .as_mut()
                        .ok_or_else(|| "sidecar child missing".to_string())?;
                    child.write(line.as_bytes()).map_err(|e| e.to_string())
                })
                .await;

                if let Err(e) = result {
                    eprintln!("[sniffer_core writer] join error: {e}");
                    break;
                }
                if let Ok(Err(e)) = result {
                    eprintln!("[sniffer_core writer] write error: {e}");
                    break;
                }
            }
            running_w.store(false, Ordering::SeqCst);
        });

        let start_cmd = json!({ "cmd": "start", "interface_id": interface_id });
        self.send_json(&start_cmd)?;

        Ok(())
    }

    pub fn send_json(&self, value: &Value) -> Result<(), String> {
        let tx = self
            .tx_cmd
            .as_ref()
            .ok_or_else(|| "sidecar not running".to_string())?;
        let line = value.to_string();
        tx.send(line)
            .map_err(|e| format!("send_json channel error: {e}"))
    }

    pub fn set_filter(&self, bpf: &str) -> Result<(), String> {
        self.send_json(&json!({ "cmd": "set_filter", "bpf": bpf }))
    }

    pub fn list_interfaces(&self) -> Result<(), String> {
        self.send_json(&json!({ "cmd": "list_interfaces" }))
    }

    pub fn stop(&mut self) -> Result<(), String> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<(), String> {
        if !self.is_running() {
            return Ok(());
        }

        self.stopping.store(true, Ordering::SeqCst);

        let _ = self.send_json(&json!({ "cmd": "stop" }));

        self.tx_cmd = None;

        std::thread::sleep(Duration::from_millis(500));
        if let Some(child) = self.child.lock().map_err(|e| e.to_string())?.take() {
            let _ = child.kill();
        }
        self.running.store(false, Ordering::SeqCst);

        Ok(())
    }
}
// ES: Cierra la sesion aunque el sidecar termine inesperadamente. / EN: Closes the session even if the sidecar exits unexpectedly.
fn close_active_session(db: &DbManager, active_session_id: &Mutex<Option<i64>>) {
    let session_id = active_session_id.lock().ok().and_then(|mut id| id.take());
    if let Some(session_id) = session_id {
        let total = db
            .get_session_summary(session_id)
            .map(|(count, _, _)| count)
            .unwrap_or(0);
        if let Err(error) = db.close_session(session_id, total) {
            eprintln!("[sniffer_core] close session error: {error}");
        }
    }
}

// ES: Distribuye cada linea JSONL segun su tipo. / EN: Dispatches each JSONL line according to its type.
fn handle_stdout_line(
    text: &str,
    app: &AppHandle,
    snapshot: &Arc<Mutex<Snapshot>>,
    db: &Arc<DbManager>,
    active_session_id: &Arc<Mutex<Option<i64>>>,
) {
    let value: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[sniffer_core] JSON parse error ({e}): {text}");
            return;
        }
    };

    let msg_type = value.get("type").and_then(Value::as_str).unwrap_or("");

    match msg_type {
        "" | "packet" => emit_packet(app, &value, db, active_session_id),
        "ready" | "interfaces" => {
            if let Some(arr) = value.get("interfaces").and_then(Value::as_array) {
                let ifaces: Vec<Interface> = arr
                    .iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect();

                if let Ok(mut snap) = snapshot.lock() {
                    snap.interfaces = ifaces.clone();
                }
                let _ = app.emit("interfaces", &ifaces);
            }
        }
        "stats" => {
            if let Ok(stats) = serde_json::from_value::<Stats>(value.clone()) {
                if let Ok(mut snap) = snapshot.lock() {
                    snap.stats = stats.clone();
                }
                let _ = app.emit("net_stats", &stats);
            }
        }
        "error" => {
            let msg = value
                .get("msg")
                .and_then(Value::as_str)
                .unwrap_or("unknown sidecar error");
            eprintln!("[sniffer_core error] {msg}");
            let _ = app.emit("sniffer_error", json!({ "msg": msg }));
        }
        "info" => {
            let msg = value.get("msg").and_then(Value::as_str).unwrap_or("");
            eprintln!("[sniffer_core info] {msg}");
        }

        other => {
            eprintln!("[sniffer_core] unhandled message type: {other}");
        }
    }
}

fn emit_packet(
    app: &AppHandle,
    value: &Value,
    db: &Arc<DbManager>,
    active_session_id: &Arc<Mutex<Option<i64>>>,
) {
    if value.get("id").is_none() {
        return;
    }

    match serde_json::from_value::<Packet>(value.clone()) {
        Ok(pkt) => {
            let _ = app.emit("packet", &pkt);
            let session_id = active_session_id.lock().ok().and_then(|id| *id);
            if let Some(session_id) = session_id {
                let row = PacketRow {
                    id: pkt.id as i64,
                    session_id,
                    ts: pkt.ts.clone(),
                    src_ip: pkt.src_ip.clone(),
                    dst_ip: pkt.dst_ip.clone(),
                    src_port: pkt.src_port.map(i32::from),
                    dst_port: pkt.dst_port.map(i32::from),
                    protocol: Some(pkt.protocol.clone()),
                    length: i32::try_from(pkt.length).ok(),
                    ttl: pkt.ttl.map(i32::from),
                    flags: Some(pkt.flags.clone()),
                    payload_hex: Some(pkt.payload_hex.clone()),
                    raw_ascii: Some(pkt.raw_ascii.clone()),
                };
                if let Err(e) = db.insert_packet(session_id, &row) {
                    eprintln!("[sniffer_core] packet persistence error: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("[sniffer_core] packet deserialize error: {e}");
            let _ = app.emit("packet_raw", value);
        }
    }
}
