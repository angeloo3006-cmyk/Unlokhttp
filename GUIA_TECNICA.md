# Guia tecnica de NetScope

## 1. Descripcion general

NetScope es una aplicacion de escritorio para capturar, visualizar y analizar
trafico de red. Su interfaz se inspira en herramientas como Wireshark, pero
presenta una experiencia mas visual: tabla de paquetes, filtros, detalle
binario, graficas y diagnosticos heuristicos.

La aplicacion divide responsabilidades entre tres capas:

Npcap o libpcap
      |
      v
sniffer_core.exe (C++)
      | stdout: JSONL
      | stdin: comandos JSONL
      v
Backend Tauri (Rust)
      | eventos y comandos Tauri
      | persistencia SQLite
      v
Frontend (React + TypeScript)
      |
      v
Ventana de escritorio con efecto acrylic

Esta separacion permite usar cada tecnologia donde aporta mas valor:

- **C++** accede directamente a Npcap o libpcap y procesa bytes de red.
- **Rust** coordina procesos, hilos, eventos, SQLite y la ventana nativa.
- **React + TypeScript** construyen la interfaz interactiva.

## 2. Estructura principal del repositorio

Proyecto m/
|-- .gitignore
|-- README.md
|-- GUIA_TECNICA.md
|-- netscope/
|   |-- src/
|   |-- src-tauri/
|   |-- package.json
|   |-- vite.config.ts
|   |-- tailwind.config.js
|   |-- postcss.config.js
|   |-- tsconfig.json
|   |-- tsconfig.node.json
|   |-- components.json
|   `-- index.html
`-- sniffer_core/
    |-- main.cpp
    |-- CMakeLists.txt
    |-- build.ps1
    |-- build.sh
    |-- fetch_deps.ps1
    |-- fetch_deps.sh
    |-- fetch_npcap_sdk.ps1
    |-- json.hpp
    |-- sniffer_core.manifest
    |-- build/
    `-- vendor/

### `netscope/`

Contiene la aplicacion Tauri y el frontend React. Es la carpeta desde la cual
se ejecutan los comandos `npm`.

### `sniffer_core/`

Contiene el sidecar C++. Un sidecar es un programa externo que la aplicacion
principal inicia cuando necesita una tarea especializada. En este proyecto,
su tarea es capturar paquetes.

### `.gitignore`

Excluye artefactos locales:

```text
sniffer_core/build/
sniffer_core/vendor/
```

Estas carpetas se regeneran automáticamente y no deben editarse manualmente.

## 3. Lenguajes utilizados

### C++

Archivo principal:

sniffer_core/main.cpp
```

Se utiliza porque Npcap y libpcap exponen APIs de bajo nivel para leer paquetes
de red. C++ permite interpretar estructuras binarias con poco costo adicional.

Responsabilidades:

- listar interfaces de red;
- iniciar y detener capturas;
- aplicar filtros BPF;
- interpretar Ethernet, IPv4, TCP, UDP, ICMP y ARP;
- detectar DNS, HTTP y HTTPS por puerto;
- emitir una linea JSON por paquete.

### Rust

Carpeta:

```text
netscope/src-tauri/src/
```

Rust es el backend nativo. Tiene rendimiento cercano a C++, pero agrega
seguridad de memoria, tipado fuerte y herramientas utiles para concurrencia.

Responsabilidades:

- iniciar el sidecar C++;
- leer su salida JSON;
- enviar comandos al sidecar;
- guardar paquetes y sesiones en SQLite;
- exponer comandos al frontend;
- emitir eventos en tiempo real;
- aplicar el efecto visual nativo de la ventana.

### TypeScript y React

Carpeta:

netscope/src/

React construye la interfaz. TypeScript agrega tipos para detectar errores antes
de ejecutar la aplicacion.

Responsabilidades:

- tabla virtualizada de paquetes;
- filtros rapidos y avanzados;
- panel de detalle;
- visor hexadecimal;
- graficas de diagnostico;
- barra personalizada de ventana;
- estado visual de captura.

### SQL

SQLite se utiliza desde Rust mediante `rusqlite`. No necesita un servidor
separado: la base de datos se guarda como un archivo local `netscope.db`.

## 4. Captura de red con C++

### Archivo `sniffer_core/main.cpp`

El capturador incluye estructuras binarias que representan cabeceras reales de
red:

```cpp
struct EtherHeader;
struct IpHeader;
struct TcpHeader;
struct UdpHeader;
struct IcmpHeader;
struct ArpHeader;
```

Npcap entrega un bloque de bytes. El programa lo interpreta por capas:

Ethernet -> IPv4 o ARP -> TCP, UDP o ICMP -> payload

El sidecar se comunica exclusivamente mediante texto JSON delimitado por
saltos de linea, tambien llamado JSONL o NDJSON.

Comandos recibidos por `stdin`:

```json
{"cmd":"start","interface_id":0}
{"cmd":"stop"}
{"cmd":"set_filter","bpf":"tcp port 443"}
{"cmd":"set_interface","interface_id":1}
{"cmd":"list_interfaces"}
```

Ejemplo de paquete emitido por `stdout`:

```json
{
  "id": 42,
  "ts": "2026-05-31T12:00:00.123Z",
  "src_ip": "192.168.1.10",
  "dst_ip": "8.8.8.8",
  "src_port": 53122,
  "dst_port": 443,
  "protocol": "HTTPS",
  "length": 74,
  "ttl": 128,
  "flags": "ACK",
  "payload_hex": "160301...",
  "raw_ascii": "..."
}
```

Eventos especiales:

```json
{"type":"ready","interfaces":[]}
{"type":"stats","captured":120,"dropped":0,"rate_pps":34.0}
{"type":"error","msg":"mensaje"}
{"type":"info","msg":"mensaje"}
```

### Archivo `sniffer_core/CMakeLists.txt`

CMake describe como construir el ejecutable C++. No es el compilador: genera
instrucciones para una herramienta de compilacion, como Ninja o Make.

Flujo:

```text
CMakeLists.txt
      |
      v
CMake detecta plataforma, compilador y SDK
      |
      v
build.ninja
      |
      v
Ninja llama al compilador C++
      |
      v
sniffer_core.exe
```

En Windows enlaza:

```text
wpcap   -> API de captura proporcionada por Npcap
Packet  -> biblioteca de bajo nivel incluida en Npcap
ws2_32  -> sockets y utilidades de red de Windows
```

En Linux y macOS enlaza `libpcap`.

### Carpeta `sniffer_core/build/`

Se genera automaticamente al compilar. Puede contener:

```text
CMakeFiles/
.ninja_deps
.ninja_log
build.ninja
cmake_install.cmake
CMakeCache.txt
sniffer_core.exe
```

No se edita manualmente. Si el repositorio cambia de ubicacion y CMake conserva
rutas antiguas, puede borrarse y regenerarse con:

```powershell
npm run sidecar:build
```

### Carpeta `sniffer_core/vendor/`

Es una cache local de dependencias descargadas. Incluye normalmente:

```text
vendor/npcap-sdk/
```

El SDK se descarga automaticamente si no se encuentra en otra ubicacion.

## 5. Diferencia entre Npcap y el SDK de Npcap

Son elementos distintos:

| Elemento | Proposito | Instalacion |
|---|---|---|
| Driver de Npcap | Permite capturar trafico real en Windows | Se instala en Windows |
| SDK de Npcap | Incluye cabeceras y bibliotecas para compilar | Se descarga automaticamente |

El script busca el SDK en este orden:

```text
1. Variable NPCAP_SDK_DIR
2. C:\npcap-sdk
3. %ProgramFiles%\Npcap\sdk
4. sniffer_core/vendor/npcap-sdk
```

Si no existe, `fetch_npcap_sdk.ps1` descarga la version publica configurada.

La aplicacion no fuerza elevacion de administrador. La posibilidad de capturar
como usuario normal depende de las opciones elegidas al instalar Npcap.

## 6. Backend Rust y Tauri

### `netscope/src-tauri/src/lib.rs`

Es el punto de configuracion principal:

- registra plugins Tauri;
- abre la base de datos;
- registra estado compartido;
- aplica acrylic en Windows o vibrancy en macOS;
- registra comandos invocables desde React;
- muestra la ventana cuando termina la inicializacion.

### `netscope/src-tauri/src/main.rs`

Es un punto de entrada pequeño:

```rust
fn main() {
    netscope_lib::run()
}
```

Tambien evita que Windows abra una consola adicional en compilaciones release.

### `netscope/src-tauri/src/sniffer.rs`

Define `SidecarManager`, que coordina `sniffer_core.exe`.

Estado importante:

```rust
pub struct SidecarManager {
    child: Arc<Mutex<Option<CommandChild>>>,
    tx_cmd: Option<UnboundedSender<String>>,
    pub running: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    snapshot: Arc<Mutex<Snapshot>>,
}
```

Flujo:

```text
SidecarManager.start()
      |
      v
inicia sniffer_core.exe
      |
      +--> tarea lectora: stdout JSONL -> eventos Tauri -> SQLite
      |
      `--> tarea escritora: canal Rust -> stdin del sidecar
```

Eventos enviados al frontend:

```text
packet
packet_raw
net_stats
interfaces
sniffer_error
capture_state
```

### `netscope/src-tauri/src/commands.rs`

Expone funciones Rust que React puede invocar:

```text
start_capture
stop_capture
set_interface
capture_status
set_bpf_filter
list_interfaces
get_stats
list_sessions
delete_session
persist_packet
query_packets
get_diagnostics_data
record_diagnostic
export_packets_json
```

Ejemplo desde TypeScript:

```ts
await invoke("set_bpf_filter", { filter: "tcp port 443" });
```

### `netscope/src-tauri/src/db.rs`

Administra SQLite mediante `DbManager`.

Tablas:

```sql
sessions (
  id,
  name,
  interface,
  started_at,
  ended_at,
  total_packets
)

packets (
  id,
  session_id,
  ts,
  src_ip,
  dst_ip,
  src_port,
  dst_port,
  protocol,
  length,
  ttl,
  flags,
  payload_hex,
  raw_ascii
)

diagnostics (
  id,
  session_id,
  ts,
  metric,
  value
)
```

`QueryBuilder` construye consultas dinamicas con parametros enlazados. Esto
permite aplicar filtros sin concatenar valores del usuario directamente en SQL.

## 7. Frontend React

### `netscope/src/`

Archivos principales:

src/
|-- App.tsx
|-- main.tsx
|-- index.css
|-- components/
|-- hooks/
|-- views/
|-- store/
|-- types/
|-- utils/
`-- lib/

### Componentes importantes

| Archivo | Proposito |
|---|---|
| `components/Layout.tsx` | Organiza menu lateral, toolbar y paneles |
| `components/TitleBar.tsx` | Barra personalizada para mover y controlar la ventana |
| `components/Sidebar.tsx` | Navegacion e interfaces disponibles |
| `components/Toolbar.tsx` | Start, Stop, BPF, exportacion y filtros |
| `components/PacketList.tsx` | Tabla compacta y virtualizada |
| `components/PacketDetail.tsx` | Inspeccion estructurada del paquete |
| `components/HexViewer.tsx` | Bytes en hexadecimal y ASCII |
| `components/FilterModal.tsx` | Filtros avanzados |
| `views/DiagnosticsView.tsx` | Graficas y analisis automatico |

### Hooks y estado

| Archivo | Proposito |
|---|---|
| `hooks/usePacketCapture.tsx` | Escucha eventos de Tauri y mantiene paquetes recientes |
| `hooks/useFilteredPackets.ts` | Filtra paquetes en memoria |
| `hooks/useDiagnostics.ts` | Calcula metricas y datos para graficas |
| `store/filters.ts` | Estado global de filtros con Zustand |
| `utils/diagnostics.ts` | Reglas heuristicas de diagnostico |
| `lib/tauri.ts` | Wrappers TypeScript tipados para comandos y eventos Rust |

## 8. Archivos de configuracion del frontend

| Archivo | Proposito |
|---|---|
| `package.json` | Dependencias y scripts npm |
| `package-lock.json` | Versiones exactas de dependencias |
| `vite.config.ts` | Servidor y compilacion del frontend |
| `tailwind.config.js` | Tema y rutas escaneadas por Tailwind |
| `postcss.config.js` | Integracion de Tailwind y Autoprefixer |
| `tsconfig.json` | Reglas TypeScript para la app |
| `tsconfig.node.json` | Reglas TypeScript para herramientas Node |
| `components.json` | Configuracion de shadcn/ui |
| `index.html` | HTML minimo donde React monta la aplicacion |

## 9. Dependencias principales

### Requisitos del sistema en Windows

Instalar:

Node.js y npm
Rust estable y Cargo
CMake
Ninja o una herramienta de compilacion compatible
Compilador C++17
Npcap

### Dependencias del frontend

Las instala `npm install`:

React
TypeScript
Vite
Tailwind CSS
Radix UI
TanStack Table
TanStack Virtual
Recharts
Zustand
Lucide React

### Dependencias Rust

Cargo las descarga al compilar:

tauri
tauri-plugin-shell
tauri-plugin-log
serde
serde_json
rusqlite
chrono
tokio
window-vibrancy

### Dependencias C++

Npcap SDK o libpcap
nlohmann/json en json.hpp


`json.hpp` es una biblioteca de una sola cabecera. Facilita crear y leer JSON
sin enlazar otra biblioteca.

## 10. Instalacion y ejecucion en Windows

Desde la raiz del repositorio:

```powershell
cd .\netscope
npm install
npm run sidecar:build
npm run tauri dev
```

`npm run sidecar:build` realiza:

```text
1. Busca o descarga el SDK de Npcap.
2. Descarga json.hpp si falta.
3. Ejecuta CMake.
4. CMake genera archivos Ninja.
5. Ninja compila sniffer_core.exe.
6. Copia el binario a src-tauri/binaries/.
```

Binario copiado:

```text
netscope/src-tauri/binaries/sniffer_core-x86_64-pc-windows-msvc.exe
```

Tauri usa el binario como sidecar porque `tauri.conf.json` declara:

```json
{
  "bundle": {
    "externalBin": [
      "binaries/sniffer_core"
    ]
  }
}
```

## 11. Comandos utiles

Ejecutar frontend sin abrir Tauri:

```powershell
cd .\netscope
npm run dev
```

Validar frontend:

```powershell
npm run build
```

Compilar sidecar:

```powershell
npm run sidecar:build
```

Validar backend Rust:

```powershell
cd .\src-tauri
cargo fmt -- --check
cargo check
```

Ejecutar aplicacion completa:

```powershell
cd .\netscope
npm run tauri dev
```

Generar build debug sin instalador:

```powershell
npm run tauri build -- --debug --no-bundle
```

## 12. Linux y macOS

El sidecar tambien contempla `libpcap`.

Compilar:

```bash
cd sniffer_core
./build.sh
```

En Linux puede ser necesario otorgar capacidades:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip build/sniffer_core
```

Para distribuir la aplicacion en Linux o macOS deben compilarse binarios del
sidecar especificos para cada plataforma.

## 13. Flujo al pulsar Start

1. React llama start_capture.
2. Rust crea una sesion SQLite.
3. Rust inicia sniffer_core.exe.
4. Rust envia {"cmd":"start","interface_id":...}.
5. C++ abre la interfaz con Npcap.
6. C++ analiza paquetes y emite JSONL.
7. Rust guarda cada paquete en SQLite.
8. Rust emite el evento packet.
9. React actualiza tabla y diagnosticos.
10. Stop cierra captura y sesion.

## 14. Que se debe editar y que no

### Editar normalmente

sniffer_core/main.cpp
sniffer_core/CMakeLists.txt
netscope/src/
netscope/src-tauri/src/
netscope/package.json
netscope/src-tauri/Cargo.toml
netscope/src-tauri/tauri.conf.json

### No editar manualmente

sniffer_core/build/
sniffer_core/vendor/
netscope/node_modules/
netscope/dist/
netscope/src-tauri/target/
netscope/package-lock.json, salvo cambios de dependencias
netscope/src-tauri/Cargo.lock, salvo cambios de dependencias

## 15. Diagnosticos heuristicos

NetScope no utiliza actualmente un modelo de inteligencia artificial externo.
Los diagnosticos son reglas locales y deterministas. Por ejemplo:

RST elevado        -> posibles rechazos, escaneo o firewall
IP dominante       -> posible fuente de trafico anormal
DNS elevado        -> revisar resolucion de nombres
ARP excesivo       -> posible flooding o spoofing
sin alertas        -> parametros normales

Esto tiene dos ventajas:

- funciona sin conexion a servicios externos;
- los resultados son explicables y reproducibles.

## 16. Resumen conceptual

NetScope sigue una arquitectura modular:

C++ captura bytes.
Rust controla, persiste y comunica.
React presenta los datos.
CMake construye el sidecar.
Cargo construye Rust.
Vite construye React.
Tauri empaqueta todo como aplicacion de escritorio.

Cada carpeta existe para mantener separadas las responsabilidades y facilitar
el mantenimiento, las pruebas y la futura distribucion multiplataforma.
