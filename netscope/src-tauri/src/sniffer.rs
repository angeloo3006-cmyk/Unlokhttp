//! sniffer.rs
//!
//! Manages the `sniffer_core` C++ sidecar process.
//!
//! Responsibilities:
//!  • Spawn / kill the sidecar via `tauri_plugin_shell`.
//!  • Forward JSON commands to the sidecar's stdin.
//!  • Parse every stdout line and emit typed Tauri events to the frontend.
//!  • Maintain an in-memory snapshot of the last stats and interface list.

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;
use tokio::sync::mpsc::{self, UnboundedSender};

// ─────────────────────────────────────────────────────────────────────────────
// Public data types (also used in commands.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// One network interface returned by the sidecar on startup or `list_interfaces`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub id:       u32,
    pub name:     String,
    pub desc:     String,
    pub loopback: bool,
    pub up:       bool,
}

/// Throughput / drop statistics snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Stats {
    pub captured: u64,
    pub dropped:  u64,
    pub rate_pps: f64,
}

/// A single captured packet as forwarded to the frontend.
/// All fields mirror the sidecar's JSON schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub id:          u64,
    pub ts:          String,
    pub src_ip:      Option<String>,
    pub dst_ip:      Option<String>,
    pub src_port:    Option<u16>,
    pub dst_port:    Option<u16>,
    pub protocol:    String,
    pub length:      u32,
    pub ttl:         Option<u8>,
    pub flags:       String,
    pub payload_hex: String,
    pub raw_ascii:   String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal state
// ─────────────────────────────────────────────────────────────────────────────

/// Shared snapshot kept inside `SidecarManager`.
#[derive(Debug, Default)]
struct Snapshot {
    stats:      Stats,
    interfaces: Vec<Interface>,
}

// ─────────────────────────────────────────────────────────────────────────────
// SidecarManager
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level manager held in Tauri's `State<Mutex<SidecarManager>>`.
pub struct SidecarManager {
    /// Handle to the running child process (None when stopped).
    child: Option<CommandChild>,

    /// Channel sender for forwarding JSON command strings to the writer task.
    tx_cmd: Option<UnboundedSender<String>>,

    /// `true` while the background reader/writer tasks are alive.
    pub running: Arc<AtomicBool>,

    /// Latest stats + interface list, updated from the reader task.
    snapshot: Arc<Mutex<Snapshot>>,
}

impl SidecarManager {
    pub fn new() -> Self {
        Self {
            child:    None,
            tx_cmd:   None,
            running:  Arc::new(AtomicBool::new(false)),
            snapshot: Arc::new(Mutex::new(Snapshot::default())),
        }
    }

    // ── Accessors used by commands.rs ─────────────────────────────────────

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

    // ── Spawn ─────────────────────────────────────────────────────────────

    /// Spawn `sniffer_core` and start background tasks.
    /// If the sidecar is already running it is stopped first.
    pub fn start(
        &mut self,
        app: AppHandle,
        interface_id: u32,
    ) -> Result<(), String> {
        // Stop any existing session
        if self.is_running() {
            self.stop_inner()?;
        }

        // Spawn the sidecar binary
        let (mut rx_evt, child) = app
            .shell()
            .sidecar("sniffer_core")
            .map_err(|e| format!("sidecar lookup failed: {e}"))?
            .spawn()
            .map_err(|e| format!("sidecar spawn failed: {e}"))?;

        // Unbounded channel: commands → stdin writer task
        let (tx_cmd, mut rx_cmd) = mpsc::unbounded_channel::<String>();

        self.child   = Some(child);
        self.tx_cmd  = Some(tx_cmd.clone());
        self.running.store(true, Ordering::SeqCst);

        let running_r   = Arc::clone(&self.running);
        let running_w   = Arc::clone(&self.running);
        let snapshot    = Arc::clone(&self.snapshot);
        let app_r       = app.clone();

        // ── Reader task: stdout lines → Tauri events ─────────────────────
        tokio::spawn(async move {
            while let Some(event) = rx_evt.recv().await {
                match event {
                    CommandEvent::Stdout(line) => {
                        let text = match String::from_utf8(line) {
                            Ok(t)  => t.trim().to_owned(),
                            Err(_) => continue,
                        };
                        if text.is_empty() { continue; }

                        handle_stdout_line(&text, &app_r, &snapshot);
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
                        let _ = app_r.emit(
                            "sniffer_error",
                            json!({ "msg": "sniffer_core process terminated unexpectedly" }),
                        );
                        break;
                    }

                    // Exhaustive match — tauri_plugin_shell may add variants
                    _ => {}
                }
            }
            running_r.store(false, Ordering::SeqCst);
        });

        // ── Writer task: rx_cmd → stdin ───────────────────────────────────
        // `tauri_plugin_shell` CommandChild is not Send, so we write via
        // the channel on the same thread that owns the child.  We use a
        // dedicated blocking thread for this.
        //
        // NOTE: `write()` on CommandChild is synchronous; we run it in a
        // `spawn_blocking` wrapper so we don't block the async executor.
        let child_ref = Arc::new(Mutex::new(
            self.child.take().expect("child just set above"),
        ));
        let child_ref_w = Arc::clone(&child_ref);

        tokio::spawn(async move {
            while let Some(cmd_str) = rx_cmd.recv().await {
                let mut line = cmd_str;
                if !line.ends_with('\n') { line.push('\n'); }

                let child_clone = Arc::clone(&child_ref_w);
                let result = tokio::task::spawn_blocking(move || {
                    let mut guard = child_clone.lock().map_err(|e| e.to_string())?;
                    guard.write(line.as_bytes()).map_err(|e| e.to_string())
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

        // Send the initial "start" command
        let start_cmd = json!({ "cmd": "start", "interface_id": interface_id });
        self.send_json(&start_cmd)?;

        Ok(())
    }

    // ── Command helpers ───────────────────────────────────────────────────

    /// Serialize `value` and push it through the stdin channel.
    pub fn send_json(&self, value: &Value) -> Result<(), String> {
        let tx = self
            .tx_cmd
            .as_ref()
            .ok_or_else(|| "sidecar not running".to_string())?;
        let line = value.to_string();
        tx.send(line).map_err(|e| format!("send_json channel error: {e}"))
    }

    /// Ask the sidecar to apply a BPF filter.
    pub fn set_filter(&self, bpf: &str) -> Result<(), String> {
        self.send_json(&json!({ "cmd": "set_filter", "bpf": bpf }))
    }

    /// Ask the sidecar to list interfaces (response comes as an event).
    pub fn list_interfaces(&self) -> Result<(), String> {
        self.send_json(&json!({ "cmd": "list_interfaces" }))
    }

    // ── Stop ──────────────────────────────────────────────────────────────

    /// Graceful stop: send `{"cmd":"stop"}`, wait 500 ms, then the
    /// background tasks clean up when they detect the process exited.
    pub fn stop(&mut self) -> Result<(), String> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<(), String> {
        if !self.is_running() {
            return Ok(());
        }

        // Best-effort: send stop command
        let _ = self.send_json(&json!({ "cmd": "stop" }));

        // Drop the sender; this closes the stdin pipe and causes the
        // writer task to exit, which in turn terminates the process.
        self.tx_cmd = None;

        // Give the process a moment to exit gracefully before we return.
        // The reader task will flip `running` to false when it detects
        // the Terminated event.
        std::thread::sleep(Duration::from_millis(500));
        self.running.store(false, Ordering::SeqCst);

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// stdout line dispatcher
// ─────────────────────────────────────────────────────────────────────────────

fn handle_stdout_line(
    text:     &str,
    app:      &AppHandle,
    snapshot: &Arc<Mutex<Snapshot>>,
) {
    let value: Value = match serde_json::from_str(text) {
        Ok(v)  => v,
        Err(e) => {
            eprintln!("[sniffer_core] JSON parse error ({e}): {text}");
            return;
        }
    };

    let msg_type = value.get("type").and_then(Value::as_str).unwrap_or("");

    match msg_type {
        // ── Packet (no "type" field) ──────────────────────────────────
        "" => emit_packet(app, &value),

        // ── Ready / interface list ────────────────────────────────────
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

        // ── Stats ─────────────────────────────────────────────────────
        "stats" => {
            if let Ok(stats) = serde_json::from_value::<Stats>(value.clone()) {
                if let Ok(mut snap) = snapshot.lock() {
                    snap.stats = stats.clone();
                }
                let _ = app.emit("net_stats", &stats);
            }
        }

        // ── Error ─────────────────────────────────────────────────────
        "error" => {
            let msg = value
                .get("msg")
                .and_then(Value::as_str)
                .unwrap_or("unknown sidecar error");
            eprintln!("[sniffer_core error] {msg}");
            let _ = app.emit("sniffer_error", json!({ "msg": msg }));
        }

        // ── Info / ack (ignored or logged) ────────────────────────────
        "info" => {
            let msg = value
                .get("msg")
                .and_then(Value::as_str)
                .unwrap_or("");
            eprintln!("[sniffer_core info] {msg}");
        }

        other => {
            eprintln!("[sniffer_core] unhandled message type: {other}");
        }
    }
}

/// Parse a raw JSON value as a `Packet` and emit it.
/// Packets have no `"type"` field — they are identified by having `"id"`.
fn emit_packet(app: &AppHandle, value: &Value) {
    // Must have an "id" to be considered a packet
    if value.get("id").is_none() {
        return;
    }

    match serde_json::from_value::<Packet>(value.clone()) {
        Ok(pkt)  => { let _ = app.emit("packet", &pkt); }
        Err(e)   => {
            eprintln!("[sniffer_core] packet deserialize error: {e}");
            // Fallback: emit raw value so the frontend at least receives it
            let _ = app.emit("packet_raw", value);
        }
    }
}
