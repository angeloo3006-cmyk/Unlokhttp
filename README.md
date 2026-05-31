# NetScope

Desktop network diagnostics application built with Tauri v2, Rust, React,
TypeScript, SQLite, Npcap or libpcap, and a C++ sidecar.

## Repository layout

```text
netscope/
  netscope/       Tauri and React application
  sniffer_core/   C++ packet-capture sidecar
```

## Windows setup

1. Install Node.js, Rust stable, CMake, and a C++17 compiler.
2. Install [Npcap](https://npcap.com/#download).
3. The build script caches the public Npcap SDK inside the workspace when
   needed. A global SDK at `C:\npcap-sdk` or `NPCAP_SDK_DIR` also works.
4. Install dependencies and compile the sidecar:

```powershell
cd .\netscope
npm install
npm run sidecar:build
```

5. Start the desktop application:

```powershell
npm run tauri dev
```

NetScope does not force administrator elevation. Whether a standard user may
capture packets depends on the selected Npcap installation settings.

## Frontend-only validation

The UI can be compiled before the Npcap SDK is available:

```powershell
cd .\netscope
npm run build
```
