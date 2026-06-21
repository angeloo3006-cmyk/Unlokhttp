use std::env;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

#[derive(Debug, Default)]
struct CliArgs {
    command: CliCommand,
    interface_id: Option<u32>,
    filter: Option<String>,
    limit: Option<u64>,
    json: bool,
    show_stats: bool,
    sniffer_path: Option<PathBuf>,
}

#[derive(Debug, Default, PartialEq, Eq)]
enum CliCommand {
    #[default]
    Help,
    Interfaces,
    Capture,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("netscope-cli error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = parse_args(env::args().skip(1).collect())?;

    match args.command {
        CliCommand::Help => {
            print_help();
            Ok(())
        }
        CliCommand::Interfaces => list_interfaces(&args),
        CliCommand::Capture => capture(args),
    }
}

fn parse_args(tokens: Vec<String>) -> Result<CliArgs, String> {
    if tokens.is_empty() {
        return Ok(CliArgs::default());
    }

    let mut args = CliArgs::default();
    let mut index = 0;

    args.command = match tokens[index].as_str() {
        "interfaces" | "list-interfaces" | "list" => CliCommand::Interfaces,
        "capture" | "start" => CliCommand::Capture,
        "help" | "--help" | "-h" => CliCommand::Help,
        other => return Err(format!("unknown command: {other}")),
    };
    index += 1;

    while index < tokens.len() {
        match tokens[index].as_str() {
            "--interface" | "-i" => {
                index += 1;
                let value = tokens
                    .get(index)
                    .ok_or_else(|| "--interface requires a value".to_string())?;
                args.interface_id = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid interface id: {value}"))?,
                );
            }
            "--filter" | "-f" => {
                index += 1;
                args.filter = Some(
                    tokens
                        .get(index)
                        .ok_or_else(|| "--filter requires a BPF string".to_string())?
                        .clone(),
                );
            }
            "--limit" | "-n" => {
                index += 1;
                let value = tokens
                    .get(index)
                    .ok_or_else(|| "--limit requires a value".to_string())?;
                args.limit = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid packet limit: {value}"))?,
                );
            }
            "--json" => args.json = true,
            "--stats" => args.show_stats = true,
            "--sniffer" => {
                index += 1;
                args.sniffer_path = Some(PathBuf::from(
                    tokens
                        .get(index)
                        .ok_or_else(|| "--sniffer requires a path".to_string())?,
                ));
            }
            "--help" | "-h" => args.command = CliCommand::Help,
            other => return Err(format!("unknown option: {other}")),
        }
        index += 1;
    }

    Ok(args)
}

fn list_interfaces(args: &CliArgs) -> Result<(), String> {
    let mut child = spawn_sniffer(args.sniffer_path.as_deref())?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "sniffer stdin unavailable".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "sniffer stdout unavailable".to_string())?;
    spawn_stderr_reader(&mut child);

    send_cmd(&mut stdin, json!({ "cmd": "list_interfaces" }))?;

    let deadline = Instant::now() + Duration::from_secs(5);
    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(&line).map_err(|e| format!("invalid JSON: {e}"))?;
        if value.get("type").and_then(Value::as_str) == Some("ready") {
            print_interfaces(&value);
            let _ = send_cmd(&mut stdin, json!({ "cmd": "stop" }));
            let _ = child.kill();
            return Ok(());
        }
        if Instant::now() > deadline {
            break;
        }
    }

    let _ = child.kill();
    Err("timeout waiting for interfaces".to_string())
}

fn capture(args: CliArgs) -> Result<(), String> {
    let interface_id = args
        .interface_id
        .ok_or_else(|| "capture requires --interface <id>".to_string())?;

    let mut child = spawn_sniffer(args.sniffer_path.as_deref())?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "sniffer stdin unavailable".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "sniffer stdout unavailable".to_string())?;
    spawn_stderr_reader(&mut child);

    send_cmd(&mut stdin, json!({ "cmd": "start", "interface_id": interface_id }))?;
    if let Some(filter) = &args.filter {
        send_cmd(&mut stdin, json!({ "cmd": "set_filter", "bpf": filter }))?;
    }

    println!("NetScope CLI capture started on interface {interface_id}. Press Ctrl+C to stop.");
    if let Some(filter) = &args.filter {
        println!("BPF filter: {filter}");
    }

    let mut packet_count = 0_u64;
    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }

        let value: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("invalid JSON from sniffer_core: {error}");
                continue;
            }
        };

        match value.get("type").and_then(Value::as_str) {
            Some("ready") => {
                if args.show_stats {
                    print_interfaces(&value);
                }
            }
            Some("stats") => {
                if args.show_stats {
                    println!(
                        "stats captured={} dropped={} rate_pps={:.2}",
                        value.get("captured").and_then(Value::as_u64).unwrap_or(0),
                        value.get("dropped").and_then(Value::as_u64).unwrap_or(0),
                        value.get("rate_pps").and_then(Value::as_f64).unwrap_or(0.0),
                    );
                }
            }
            Some("error") => {
                eprintln!(
                    "sniffer error: {}",
                    value.get("msg").and_then(Value::as_str).unwrap_or("unknown")
                );
            }
            _ => {
                packet_count += 1;
                if args.json {
                    println!("{value}");
                } else {
                    print_packet(&value);
                }

                if args.limit.is_some_and(|limit| packet_count >= limit) {
                    let _ = send_cmd(&mut stdin, json!({ "cmd": "stop" }));
                    let _ = child.kill();
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

fn spawn_sniffer(explicit_path: Option<&Path>) -> Result<Child, String> {
    let path = explicit_path
        .map(Path::to_path_buf)
        .or_else(|| env::var_os("NETSCOPE_SNIFFER_CORE").map(PathBuf::from))
        .or_else(find_sniffer_core)
        .ok_or_else(|| {
            "cannot locate sniffer_core. Use --sniffer <path> or NETSCOPE_SNIFFER_CORE".to_string()
        })?;

    Command::new(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn {}: {e}", path.display()))
}

fn find_sniffer_core() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let exe_suffix = env::consts::EXE_SUFFIX;
    let target = format!("sniffer_core{exe_suffix}");
    let tauri_sidecar = format!("sniffer_core-{}{}", target_triple(), exe_suffix);

    let candidates = [
        manifest_dir.join("binaries").join(&tauri_sidecar),
        manifest_dir.join("binaries").join(&target),
        manifest_dir.join("target").join("debug").join(&target),
        manifest_dir
            .parent()
            .and_then(Path::parent)
            .map(|root| root.join("sniffer_core").join("build").join(&target))
            .unwrap_or_default(),
    ];

    candidates.into_iter().find(|path| path.exists())
}

fn target_triple() -> &'static str {
    option_env!("TARGET").unwrap_or_else(|| {
        if cfg!(target_os = "windows") {
            "x86_64-pc-windows-msvc"
        } else if cfg!(target_os = "macos") {
            "x86_64-apple-darwin"
        } else {
            "x86_64-unknown-linux-gnu"
        }
    })
}

fn spawn_stderr_reader(child: &mut Child) {
    let Some(stderr) = child.stderr.take() else {
        return;
    };
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if !line.trim().is_empty() {
                eprintln!("[sniffer_core] {line}");
            }
        }
    });
}

fn send_cmd(stdin: &mut ChildStdin, value: Value) -> Result<(), String> {
    writeln!(stdin, "{value}").map_err(|e| e.to_string())?;
    stdin.flush().map_err(|e| e.to_string())
}

fn print_interfaces(value: &Value) {
    println!("Available interfaces:");
    println!("{:<5} {:<5} {:<5} {}", "ID", "UP", "LOOP", "NAME / DESCRIPTION");
    for iface in value
        .get("interfaces")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        println!(
            "{:<5} {:<5} {:<5} {}",
            iface.get("id").and_then(Value::as_u64).unwrap_or(0),
            yes_no(iface.get("up").and_then(Value::as_bool).unwrap_or(false)),
            yes_no(iface.get("loopback").and_then(Value::as_bool).unwrap_or(false)),
            format_interface_name(iface),
        );
    }
}

fn print_packet(value: &Value) {
    let id = value.get("id").and_then(Value::as_u64).unwrap_or(0);
    let ts = value.get("ts").and_then(Value::as_str).unwrap_or("-");
    let protocol = value.get("protocol").and_then(Value::as_str).unwrap_or("OTHER");
    let src = endpoint(value, "src_ip", "src_port");
    let dst = endpoint(value, "dst_ip", "dst_port");
    let length = value.get("length").and_then(Value::as_u64).unwrap_or(0);
    let flags = value.get("flags").and_then(Value::as_str).unwrap_or("");

    println!("{id:<8} {ts:<24} {protocol:<6} {src:<28} -> {dst:<28} len={length:<6} {flags}");
}

fn endpoint(value: &Value, ip_key: &str, port_key: &str) -> String {
    let ip = value.get(ip_key).and_then(Value::as_str).unwrap_or("-");
    match value.get(port_key).and_then(Value::as_u64) {
        Some(port) => format!("{ip}:{port}"),
        None => ip.to_string(),
    }
}

fn format_interface_name(value: &Value) -> String {
    let name = value.get("name").and_then(Value::as_str).unwrap_or("-");
    let desc = value.get("desc").and_then(Value::as_str).unwrap_or("");
    if desc.is_empty() || desc == name {
        name.to_string()
    } else {
        format!("{desc} ({name})")
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn print_help() {
    println!(
        r#"NetScope CLI

Usage:
  netscope-cli interfaces [--sniffer <path>]
  netscope-cli capture --interface <id> [--filter <bpf>] [--limit <n>] [--json] [--stats] [--sniffer <path>]

Examples:
  netscope-cli interfaces
  netscope-cli capture --interface 0 --limit 20
  netscope-cli capture -i 2 --filter "tcp port 80" --json

Notes:
  - Requires Npcap on Windows or libpcap on Linux/macOS.
  - Uses the same sniffer_core sidecar as the Tauri app.
  - Use NETSCOPE_SNIFFER_CORE or --sniffer if the sidecar is not found automatically.
"#
    );
}
