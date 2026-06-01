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

Git
Node.js LTS y npm
Rust estable y Cargo mediante rustup
CMake
Ninja
Compilador C++17
Microsoft Edge WebView2 Runtime
Npcap: controlador de captura instalado en Windows

El SDK de Npcap no se instala manualmente en el caso normal. El script
`sniffer_core/build.ps1` lo descarga cuando falta. El instalador de Npcap si
es necesario porque agrega al sistema el controlador que permite capturar
paquetes reales.

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

## 10. Instalacion en Windows

### Opcion recomendada: instalar herramientas con winget

`winget` es el administrador de paquetes oficial incluido con versiones
modernas de Windows mediante App Installer. Abrir una terminal PowerShell
normal y comprobar si esta disponible:

```powershell
winget --version
```

Si el comando existe, instalar las herramientas generales:

```powershell
winget install --id Git.Git -e --source winget
winget install --id OpenJS.NodeJS.LTS -e --source winget
winget install --id Rustlang.Rustup -e --source winget
winget install --id Kitware.CMake -e --source winget
winget install --id Ninja-build.Ninja -e --source winget
winget install --id Microsoft.EdgeWebView2Runtime -e --source winget
```

NetScope compila el sidecar C++ con CMake. La opcion mas sencilla en Windows
es instalar Visual Studio Build Tools con la carga de trabajo de C++:

```powershell
winget install --id Microsoft.VisualStudio.2022.BuildTools -e --source winget --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

Despues de instalar Build Tools conviene abrir Visual Studio Installer y
confirmar que este instalada la carga de trabajo `Desktop development with
C++`. Cerrar y abrir PowerShell nuevamente para refrescar `PATH`.

Los identificadores anteriores fueron comprobados con `winget` el 1 de junio
de 2026. Las versiones concretas cambian con el tiempo, por eso no se fijan
numeros de version en los comandos.

### Instalar Npcap manualmente

Npcap no tenia un paquete oficial disponible mediante `winget` al verificar
esta guia el 1 de junio de 2026. Debe instalarse manualmente:

1. Abrir [Npcap Downloads](https://npcap.com/#download).
2. Descargar el instalador estable mas reciente. Al verificar esta guia era
   Npcap `1.88`.
3. Ejecutar el instalador.
4. Si usuarios sin privilegios de administrador deben capturar trafico, no
   activar la restriccion que limita Npcap solo a administradores.

El SDK publico de Npcap se descarga automaticamente al ejecutar
`npm run sidecar:build`. Al verificar esta guia, la version publicada del SDK
era `1.16`.

### Si winget no esta disponible

Descargar los instaladores desde sus sitios oficiales:

| Herramienta | Sitio oficial | Para que se usa |
|---|---|---|
| Git | [git-scm.com/install/windows](https://git-scm.com/install/windows) | Clonar y versionar el proyecto |
| Node.js LTS | [nodejs.org/en/download](https://nodejs.org/en/download) | Ejecutar npm, Vite y React |
| Rustup | [rustup.rs](https://rustup.rs/) | Instalar Rust y Cargo |
| Visual Studio Build Tools | [visualstudio.microsoft.com/downloads](https://visualstudio.microsoft.com/downloads/) | Compilar C++ en Windows |
| CMake | [cmake.org/download](https://cmake.org/download/) | Generar la compilacion del sidecar |
| Ninja | [github.com/ninja-build/ninja/releases](https://github.com/ninja-build/ninja/releases) | Ejecutar la compilacion generada por CMake |
| WebView2 Runtime | [developer.microsoft.com/microsoft-edge/webview2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) | Renderizar la interfaz de Tauri |
| Npcap | [npcap.com/#download](https://npcap.com/#download) | Capturar paquetes de red |

Si Windows no incluye `winget`, Microsoft documenta App Installer en
[learn.microsoft.com/windows/package-manager/winget/install](https://learn.microsoft.com/en-us/windows/package-manager/winget/install).

### Verificar las herramientas

Abrir una terminal nueva y ejecutar:

```powershell
git --version
node --version
npm --version
rustc --version
cargo --version
cmake --version
ninja --version
```

WebView2 y Npcap no exponen necesariamente un comando de terminal. Se pueden
comprobar en `Configuracion > Aplicaciones > Aplicaciones instaladas`.

### Descargar y ejecutar NetScope

Clonar la rama de trabajo y entrar al frontend:

```powershell
git clone -b codex/netscope-scaffold https://github.com/angeloo3006-cmyk/Unlokhttp.git
cd .\Unlokhttp
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

### Problemas comunes en Windows

- Si un comando instalado no aparece, cerrar la terminal y abrir una nueva.
- Si CMake conserva una configuracion antigua, borrar manualmente
  `sniffer_core/build` y volver a ejecutar `npm run sidecar:build`.
- Si la aplicacion abre pero no captura, revisar que Npcap este instalado y
  que su politica permita capturar con el usuario actual.
- Si falta un compilador C++, abrir Visual Studio Installer y agregar
  `Desktop development with C++`.

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

## 12. Instalacion en Linux

Tauri usa dependencias nativas del sistema en Linux. Ademas, el sidecar de
NetScope necesita `libpcap` para capturar paquetes y `libcap` para otorgar
capacidades al binario sin ejecutar toda la aplicacion como `root`.

### Ubuntu y Debian

```bash
sudo apt update
sudo apt install -y \
  libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev \
  libpcap-dev pkg-config libcap2-bin \
  git nodejs npm cmake ninja-build
```

### Fedora

```bash
sudo dnf install -y \
  webkit2gtk4.1-devel openssl-devel curl wget file \
  libappindicator-gtk3-devel librsvg2-devel libxdo-devel \
  libpcap-devel pkgconf-pkg-config libcap \
  git nodejs npm cmake ninja-build gcc-c++
```

### Arch Linux

```bash
sudo pacman -Syu --needed \
  webkit2gtk-4.1 base-devel curl wget file openssl \
  appmenu-gtk-module libappindicator-gtk3 librsvg xdotool \
  libpcap pkgconf libcap \
  git nodejs npm cmake ninja
```

### Instalar Rust

En las tres distribuciones, instalar Rust con `rustup`:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup default stable
```

Los repositorios de algunas distribuciones conservan versiones antiguas de
Node.js. Este proyecto usa Vite `8`, que requiere Node.js `^20.19.0` o
`>=22.12.0`. Si `node --version` muestra una version inferior, instalar una
version LTS reciente siguiendo la opcion para Linux de
[nodejs.org/en/download](https://nodejs.org/en/download).

La lista base de paquetes de interfaz proviene de los
[prerrequisitos oficiales de Tauri v2](https://v2.tauri.app/start/prerequisites/).
`libpcap`, `libcap`, CMake y Ninja se agregan porque los necesita el sidecar.

### Verificar las herramientas

```bash
git --version
node --version
npm --version
rustc --version
cargo --version
cmake --version
ninja --version
pkg-config --modversion libpcap
```

### Descargar y ejecutar NetScope

En Linux no se usa `npm run sidecar:build`, porque ese comando llama al script
PowerShell de Windows. Usar `build.sh`:

```bash
git clone -b codex/netscope-scaffold https://github.com/angeloo3006-cmyk/Unlokhttp.git
cd Unlokhttp
chmod +x sniffer_core/build.sh sniffer_core/fetch_deps.sh

cd sniffer_core
./build.sh

sudo setcap cap_net_raw,cap_net_admin=eip build/sniffer_core

cd ../netscope
npm install
npm run tauri dev
```

El comando `setcap` permite capturar paquetes sin iniciar toda la interfaz con
`sudo`. Si el binario vuelve a compilarse o reemplazarse, ejecutar `setcap`
nuevamente.

### Alternativa manual para Linux

Si la distribucion no usa `apt`, `dnf` o `pacman`, instalar:

```text
WebKitGTK 4.1 y sus cabeceras de desarrollo
Compilador C++17 y herramientas de compilacion
OpenSSL y sus cabeceras
libpcap y sus cabeceras
libcap
pkg-config
Git
Node.js LTS y npm
Rust estable mediante rustup
CMake
Ninja
```

Para distribuir la aplicacion en Linux debe compilarse el sidecar para la
arquitectura y plataforma objetivo.

## 13. Nota breve para macOS

El sidecar tambien contempla `libpcap` en macOS. Las dependencias principales
pueden instalarse con Homebrew:

```bash
brew install git node cmake ninja libpcap
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

cd sniffer_core
./build.sh

cd ../netscope
npm install
npm run tauri dev
```

Para distribuir la aplicacion en macOS debe compilarse un sidecar especifico
para la arquitectura objetivo.

## 14. Flujo al pulsar Start

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

## 15. Que se debe editar y que no

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

## 16. Diagnosticos heuristicos

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

## 17. Resumen conceptual

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
