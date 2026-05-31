# sniffer_core

`sniffer_core` is the C++ packet-capture sidecar used by NetScope. It exchanges
newline-delimited JSON through stdin and stdout only.

## Windows prerequisites

1. Install [Npcap](https://npcap.com/#download).
2. Choose the Npcap installation policy that fits the machine. NetScope runs
   the sidecar as the current user and does not request administrator elevation.
3. The build script downloads the public Npcap SDK `1.16` into the workspace
   cache when no global SDK is found. You may instead extract it to
   `C:\npcap-sdk`, set `NPCAP_SDK_DIR`, or pass `-NpcapSdkDir` to `build.ps1`.
4. Install CMake and a C++17 compiler.

If Npcap was installed with capture restricted to administrators, Windows may
deny opening an interface for a standard user. Reconfigure Npcap if standard
users should be allowed to capture traffic.

## Build

From this directory:

```powershell
.\build.ps1
```

The script downloads `json.hpp` when needed, compiles the binary, and copies it
to:

```text
../netscope/src-tauri/binaries/sniffer_core-x86_64-pc-windows-msvc.exe
```

On Linux or macOS:

```bash
./build.sh
```

Linux users should grant packet capture capabilities after compiling:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip build/sniffer_core
```

## Commands

```json
{"cmd":"start","interface_id":0}
{"cmd":"stop"}
{"cmd":"set_filter","bpf":"tcp port 80"}
{"cmd":"set_interface","interface_id":1}
{"cmd":"list_interfaces"}
```

The process emits `ready`, `stats`, `error`, `info`, and packet JSON lines.
