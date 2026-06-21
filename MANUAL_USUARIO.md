# Manual de Usuario - NetScope

NetScope es una aplicacion de escritorio para capturar, revisar y diagnosticar trafico de red. La idea es que puedas ver paquetes como en una herramienta tipo Wireshark, pero con una interfaz mas directa, sesiones guardadas, filtros, graficas y diagnosticos explicados.

Este manual cubre dos formas de usar el proyecto:

- La aplicacion grafica con Tauri.
- La version por terminal `netscope-cli`.

## Requisitos

En Windows necesitas:

- Npcap instalado.
- Permisos suficientes para capturar paquetes.
- El binario `sniffer_core` incluido en `src-tauri/binaries`.

En Linux/macOS necesitas:

- `libpcap`.
- Permisos de captura, normalmente ejecutando con permisos elevados o configurando capabilities.

## Abrir la aplicacion grafica

Desde la carpeta `netscope`:

```powershell
npm run tauri dev
```

Para compilar:

```powershell
npm run build
npm run tauri build
```

## Flujo basico de captura

1. Abre NetScope.
2. Entra a la vista `Capture`.
3. Presiona `Start`.
4. Espera a que aparezcan interfaces de red en el sidebar.
5. Selecciona una interfaz que capture trafico real.
6. Vuelve a presionar `Start` si cambiaste de interfaz.
7. Observa la tabla de paquetes.

Si no aparecen paquetes, prueba otra interfaz. En Windows muchas interfaces virtuales, Bluetooth, WAN o loopback pueden no mostrar trafico util para una prueba normal. Las interfaces Realtek, Intel o Wi-Fi suelen ser mejores candidatas.

## Controles principales

### Start / Stop

Inicia o detiene la captura. Cuando esta capturando, el backend Rust mantiene vivo el sidecar `sniffer_core`, que es el proceso C++ encargado de leer paquetes con Npcap/libpcap.

### Paquetes por segundo

Muestra la velocidad actual de captura. Sirve para saber si la interfaz esta recibiendo trafico.

### Total de paquetes

Muestra cuantos paquetes se han capturado en la sesion actual visible.

### Filtro BPF rapido

Permite escribir filtros como:

```text
tcp
udp
tcp port 80
udp port 53
host 192.168.1.1
```

Este filtro se manda al sidecar C++ y se aplica desde la captura. Es diferente a los filtros avanzados del frontend.

### Export CSV

Exporta los paquetes a un archivo CSV. Sirve para abrir los datos en Excel, LibreOffice Calc o cualquier herramienta de analisis de datos.

### Clear

Limpia los paquetes visibles en la captura actual. No necesariamente borra sesiones historicas de SQLite.

## Tabla de paquetes

La tabla muestra paquetes capturados o paquetes guardados en sesiones.

Columnas principales:

- `#`: id interno del paquete.
- `Time`: hora local de captura.
- `Source`: origen, normalmente IP y puerto.
- `Destination`: destino, normalmente IP y puerto.
- `Protocol`: protocolo detectado.
- `Weight`: porcentaje del protocolo dentro de la captura.
- `Length`: longitud del paquete en bytes.
- `Traffic`: cuanto representa ese paquete dentro del total de bytes.
- `Day Hour Min`: ventana de tiempo resumida.
- `Flags`: flags TCP si existen.
- `Info`: resumen corto.

La tabla permite resize de columnas. Las columnas base son obligatorias porque sin ellas se pierde el contexto minimo para leer un paquete.

## Configuracion de columnas

En `Settings` puedes activar columnas opcionales.

Ejemplos:

- Source port.
- Destination port.
- Source MAC.
- Destination MAC.
- Source vendor.
- Destination vendor.
- TTL.
- Protocol number.
- Payload hex.
- Raw ASCII.

El preview inferior muestra como se vera la tabla con esas columnas.

## Detalle de paquete

Al seleccionar un paquete, la parte inferior muestra informacion mas profunda:

- `Frame`: tiempo, longitud y posicion visible.
- `Ethernet II`: MAC origen, MAC destino, fabricante y tipo Ethernet.
- `Internet Protocol`: IP origen, IP destino, TTL y protocolo.
- `Transport`: puertos y rol de conexion si aplica.
- `Hex / ASCII`: datos crudos del paquete.

Esto ayuda a revisar el paquete sin depender solo de la fila compacta de la tabla.

## Filtros avanzados

Los filtros avanzados filtran los paquetes ya visibles en el frontend.

Puedes filtrar por:

- IP origen.
- IP destino.
- Puerto origen.
- Puerto destino.
- Protocolos.
- Longitud minima y maxima.
- Flags TCP.

Estos filtros se combinan con logica AND, o sea, el paquete debe cumplir las condiciones activas.

## Sesiones

Cada captura crea una sesion en SQLite.

En `Sessions` puedes:

- Ver capturas anteriores.
- Abrir una sesion.
- Buscar paquetes por IP, protocolo, MAC o vendor.
- Revisar resumen de trafico.
- Ver paquetes historicos aunque ya no estes capturando.

La busqueda de sesiones consulta la base de datos, no solo la memoria actual.

## Diagnosticos

La vista `Diagnostics` analiza paquetes y genera metricas.

Puede mostrar:

- Paquetes por segundo.
- Ancho de banda estimado.
- Promedio de tamano de paquete.
- Distribucion de protocolos.
- Top IPs.
- Alertas heuristicas.

Las alertas no son una verdad absoluta. Son pistas basadas en reglas.

Ejemplos:

- Muchos SYN pueden indicar posible port scan.
- Muchos RST pueden indicar rechazos o firewall.
- DNS excesivo puede indicar mucha resolucion de nombres.
- ARP sospechoso puede indicar problemas en red local.
- Un host dominante puede indicar trafico anormal.
- Pocos paquetes con muchos bytes puede indicar transferencia pesada.

## Version CLI

La version CLI permite usar NetScope desde terminal sin abrir la interfaz grafica.

Primero compila el binario:

```powershell
cd netscope\src-tauri
cargo build --bin netscope-cli
```

El ejecutable queda en:

```text
netscope/src-tauri/target/debug/netscope-cli.exe
```

### Listar interfaces

```powershell
target\debug\netscope-cli.exe interfaces
```

Esto imprime las interfaces disponibles con su id.

### Capturar paquetes

```powershell
target\debug\netscope-cli.exe capture --interface 0
```

Capturar solo 20 paquetes:

```powershell
target\debug\netscope-cli.exe capture --interface 0 --limit 20
```

Capturar con filtro BPF:

```powershell
target\debug\netscope-cli.exe capture --interface 0 --filter "tcp port 80"
```

Imprimir JSON crudo:

```powershell
target\debug\netscope-cli.exe capture --interface 0 --json
```

Mostrar stats mientras captura:

```powershell
target\debug\netscope-cli.exe capture --interface 0 --stats
```

### Si no encuentra sniffer_core

Puedes pasar la ruta manual:

```powershell
target\debug\netscope-cli.exe interfaces --sniffer "..\binaries\sniffer_core-x86_64-pc-windows-msvc.exe"
```

O usar variable de entorno:

```powershell
$env:NETSCOPE_SNIFFER_CORE="D:\ruta\a\sniffer_core.exe"
target\debug\netscope-cli.exe interfaces
```

## Problemas comunes

### No aparecen paquetes

Prueba otra interfaz. Muchas interfaces virtuales no capturan trafico util.

### Error de permisos

En Windows revisa que Npcap este instalado. En Linux/macOS puede requerir permisos extra.

### El filtro BPF falla

Revisa la sintaxis. Ejemplos validos:

```text
tcp
udp
port 53
tcp port 443
host 192.168.1.1
```

### La app se ve rara al mover ventana

NetScope apaga temporalmente acrylic al mover o redimensionar para evitar lag visual. Luego lo restaura.

## Checklist contra el requerimiento del proyecto

Segun el PDF del proyecto, NetScope cubre lo siguiente:

- Software packet sniffer: cubierto por `sniffer_core` usando Npcap/libpcap.
- Lenguaje C/C++: cubierto en `sniffer_core/main.cpp`.
- Uso de Npcap/libpcap: cubierto por el sidecar C++.
- Interfaz basada en texto: cubierta por `netscope-cli`.
- Interfaz grafica: cubierta por la app Tauri/React.
- Captura inicio/parada: cubierta por botones `Start/Stop` y por `netscope-cli capture`.
- Filtros de captura: cubiertos por BPF rapido y filtros avanzados.
- Al menos 4 tipos de filtro: cubierto por IP origen, IP destino, puerto origen, puerto destino, protocolo, longitud y flags TCP.
- Tres areas tipo Wireshark: cubierto por Packet List, Packet Detail y Hex/ASCII viewer.
- Exportacion CSV: cubierta por `Export CSV`.
- Codigo fuente/proyecto: cubierto en el repositorio GitHub.
- Manual de usuario: cubierto por este archivo.
- Reporte/documento: cubierto por `Que es Netscope.docx`.
- Video: marcado como cubierto por el equipo.

Lo unico que se debe generar antes de entregar fisicamente es el paquete instalador final de la plataforma elegida. Para Windows se puede generar con:

```powershell
cd netscope
npm run tauri build
```

Despues de compilar, el instalador queda dentro de `netscope/src-tauri/target/release/bundle`.

## Resumen

Usa la app grafica cuando quieras explorar visualmente paquetes, sesiones y diagnosticos. Usa `netscope-cli` cuando quieras pruebas rapidas, capturas desde terminal o salida JSON para scripts.
