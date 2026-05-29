# sniffer_core

Packet-capture sidecar for **Netscope / Tauri**.
Communicates exclusively via **stdin / stdout** using newline-delimited JSON.

---

## Prerequisites

### All platforms
- CMake ≥ 3.20
- C++17 compiler (MSVC 2019+, GCC 11+, Clang 14+)
- **nlohmann/json** single-header (`json.hpp`) — fetch with the helper script below

### Windows
- [Npcap](https://npcap.com/#download) installed (runtime + SDK)
- Npcap SDK extracted (e.g. `C:\npcap-sdk`)
- Visual Studio 2022 or Build Tools

### Linux
```bash
# Debian/Ubuntu
sudo apt install libpcap-dev build-essential cmake

# Fedora/RHEL
sudo dnf install libpcap-devel gcc-c++ cmake

# Arch
sudo pacman -S libpcap cmake base-devel
```

### macOS
```bash
xcode-select --install    # ships libpcap
brew install cmake        # or use the macOS CMake installer
```

---

## Build

### 1. Fetch nlohmann/json

```bash
# Linux / macOS
bash fetch_deps.sh

# Windows (PowerShell)
.\fetch_deps.ps1
```

Or manually download
`https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp`
and place it next to `main.cpp`.

---

### 2. Linux / macOS

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Grant capabilities so the binary works without root (Linux):
sudo setcap cap_net_raw,cap_net_admin=eip build/sniffer_core
```

---

### 3. Windows (MSVC)

```powershell
# Developer PowerShell for VS 2022
cmake -B build `
      -DCMAKE_BUILD_TYPE=Release `
      -DNPCAP_SDK_DIR="C:\npcap-sdk"
cmake --build build --config Release
# Binary: build\Release\sniffer_core.exe
```

---

### 4. Copy to Tauri (optional, automatic)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCOPY_TO_TAURI=ON
cmake --build build -j$(nproc)
# → binary ends up in ../src-tauri/binaries/sniffer_core-<triple>
```

Then reference it in `tauri.conf.json`:

```json
"bundle": {
  "externalBin": ["binaries/sniffer_core"]
}
```

And in Rust:

```rust
use tauri_plugin_shell::ShellExt;

let sidecar = app.shell()
    .sidecar("sniffer_core")
    .unwrap()
    .spawn()
    .unwrap();
```

---

## Protocol reference

### Events → stdout (newline-delimited JSON)

| `type` | Fields | Emitted when |
|--------|--------|--------------|
| `ready` | `interfaces[]` | Startup |
| `stats` | `captured`, `dropped`, `rate_pps` | Every 1 s |
| `error` | `msg` | On error |
| `info` | `msg` | Command acknowledgement |
| `interfaces` | `interfaces[]` | Response to `list_interfaces` |
| *(no type)* | Packet object (see below) | For every captured packet |

#### Packet JSON fields

```json
{
  "id":          1,
  "ts":          "2025-05-25T14:30:01.123Z",
  "src_ip":      "192.168.1.10",
  "dst_ip":      "1.1.1.1",
  "src_port":    54321,
  "dst_port":    443,
  "protocol":    "HTTPS",
  "length":      74,
  "ttl":         64,
  "flags":       "SYN",
  "payload_hex": "474554202f20485454502f312e310d0a...",
  "raw_ascii":   "GET / HTTP/1.1.."
}
```

`protocol` values: `TCP` | `UDP` | `ICMP` | `ARP` | `DNS` | `HTTP` | `HTTPS` | `OTHER`

`flags` values: `SYN` | `ACK` | `FIN` | `RST` | `PSH` | `SYN-ACK` | `""`

---

### Commands ← stdin (newline-delimited JSON)

```jsonc
// Start capture on interface 0
{"cmd":"start","interface_id":0}

// Stop capture
{"cmd":"stop"}

// Apply BPF filter (while running or before next start)
{"cmd":"set_filter","bpf":"tcp port 443"}

// Pre-select interface (effective on next start)
{"cmd":"set_interface","interface_id":1}

// List interfaces
{"cmd":"list_interfaces"}
```

---

## Notes

- The binary **must run with elevated privileges** (root/admin) or have
  `cap_net_raw` granted (Linux) / Npcap with standard user access (Windows).
- `payload_hex` is capped at 256 bytes; `raw_ascii` at 128 bytes.
- Stats are emitted every 1 second regardless of capture state.
- Sending EOF (closing stdin) or killing the process gracefully stops capture.
