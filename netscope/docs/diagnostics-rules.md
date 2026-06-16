# NetScope Diagnostics Rules

Este documento describe el motor heurístico actual de NetScope.

Importante: estos diagnósticos son señales probabilísticas, no pruebas absolutas de ataque.
Cada alerta incluye fuerza de señal, evidencia, recomendación, IPs/MACs afectadas y métricas crudas.

En la UI, `confidence` se presenta como **Signal strength**. No debe comunicarse como probabilidad matemática ni como certeza de ataque.

## Principio Actual

NetScope solo muestra diagnósticos que puede sostener con los datos disponibles hoy.

Por eso están desactivados por ahora:

- DNS tunneling estructural.
- NXDOMAIN rate.
- TXT record dominance.
- Entropía de subdominios.
- ARP spoofing real.
- Conflictos IP/MAC derivados del payload ARP.

Estas reglas requieren cambios en el sidecar C++. Hasta que esos campos existan, el frontend no debe inventarlos usando `raw_ascii`, `payload_hex` o solamente la cabecera Ethernet.

## Alert Shape

Cada alerta contiene:

- `type`: categoría del diagnóstico.
- `level`: `success`, `info`, `warning` o `critical`.
- `confidence`: 0.0 a 1.0. Es una suma ponderada de señales, no un modelo entrenado.
- `evidence`: hechos legibles usados por la regla.
- `recommendation`: siguiente cosa que el usuario debería revisar.
- `affected_ips`: IPs relacionadas.
- `affected_macs`: MACs relacionadas.
- `metrics`: valores numéricos usados internamente.
- `metrics.impact_score`: alcance relativo del evento. Se usa para ordenar alertas con severidad similar.

Los score breakdowns se guardan en `metrics` como valores planos:

```ts
volume_score
dispersion_score
asymmetry_score
persistence_score
concentration_score
behavior_score
impact_score
```

## Pre-análisis: Capture Baseline

Antes de correr reglas, NetScope calcula un baseline con toda la captura:

```ts
totalPackets = packets.length
totalBytes = sum(packet.length)
captureDurationSec = lastTimestamp - firstTimestamp, mínimo 1 segundo
avgPacketsPerSec = totalPackets / captureDurationSec
tcpPackets = count(TCP, HTTP, HTTPS)
udpPackets = count(UDP, DNS)
visibleHosts = count(unique src_ip + dst_ip)
timeReliable = captureDurationSec >= 2
sampleMultiplier = 0.85 si totalPackets < 50
sampleMultiplier = 0.95 si totalPackets < 200
sampleMultiplier = 1.00 si totalPackets >= 200
```

NetScope no suprime todo el diagnóstico por muestras pequeñas. En su lugar:

- Las capturas con menos de 50 paquetes reciben una penalización ligera de confianza.
- Las capturas menores a 2 segundos desactivan o reducen señales dependientes del tiempo.
- Las reglas que no dependen de tiempo pueden seguir emitiendo alertas.

Motivo: un escaneo rápido, una ráfaga de RST o un pico ARP pueden ocurrir en una ventana corta. Apagar todo produciría falsos negativos.

## Gateway / Trusted Host Handling

NetScope detecta un gateway probable como la IP con mayor participación de paquetes cuando supera `35%` del tráfico visible.

El gateway probable no se excluye de forma absoluta. Se aplica una penalización dinámica:

```ts
35% a 50% del tráfico visible -> 0.90
50% a 65% del tráfico visible -> 0.75
más de 65%                 -> 0.55
```

Motivo: el gateway suele dominar en redes normales, pero excluirlo completamente puede ocultar casos interesantes, como un gateway comprometido, un NAS mal detectado o un host exfiltrando datos.

Actualmente `TRUSTED_HOSTS` existe como `Set` interno vacío en:

```ts
src/utils/diagnostics.ts
```

En una versión futura se puede alimentar desde Settings para excluir o penalizar manualmente DNS resolvers, gateways conocidos, servidores de backup o agentes de monitoreo.

## 1. Possible Port Scan

Función:

```ts
analyzePortScan(packets, baseline)
```

Propósito:
Detecta un host enviando TCP SYN hacia muchos puertos o destinos con un patrón compatible con reconocimiento.

La confianza se agrupa por familias para evitar doble conteo.

| Familia | Señales | Máximo |
|---|---|---:|
| Volumen | SYN/sec, proporción SYN/TCP, cantidad de SYN | 0.25 |
| Dispersión | puertos destino únicos, IPs destino únicas, secuencialidad de puertos | 0.30 |
| Asimetría | bajo ACK/SYN solo si la captura parece bidireccional | 0.18 |
| Persistencia | actividad en 3+ ventanas, puertos/seg si el tiempo es confiable | 0.15 |
| Concentración | un origen concentra >70% de todos los SYN | 0.10 |

Fórmula:

```ts
confidence = (volume + dispersion + asymmetry + persistence + concentration) * sampleMultiplier
```

Severidad:

| Confidence / Impact | Level |
|---:|---|
| Menor a 0.40 | Se suprime |
| 0.40 a 0.77 | `warning` |
| 0.78 o más, o impacto alto | `critical` |

Notas:

- El ratio ACK/SYN solo se aplica si NetScope ve respuestas desde los destinos hacia el origen.
- La secuencialidad de puertos ayuda a distinguir escaneos de tráfico moderno normal.
- Capturas pequeñas reducen el score, pero no eliminan la alerta.

## 2. Elevated TCP Reset Activity

Función:

```ts
analyzeTcpResetActivity(packets, baseline)
```

Propósito:
Detecta actividad elevada de TCP RST. El nombre es neutral a propósito: un RST puede venir de firewall, servicio cerrado, navegador, balanceador, middlebox, conexión cancelada o escaneo.

| Familia | Señales | Máximo |
|---|---|---:|
| Volumen | RST > 1% total, RST/sec > 2, RST/TCP > 8% | 0.35 |
| Concentración | un origen o destino concentra >65% de RSTs | 0.22 |
| Burst | más de 10 RSTs en 2 segundos, solo si el tiempo es confiable | 0.12 |

Severidad:

| Confidence / Ratio | Level |
|---:|---|
| Menor a 0.38 | Se suprime |
| 0.38 a 0.77 | `warning` |
| 0.78 o más, o RST/TCP > 18% | `critical` |

La recomendación evita afirmar una causa única. La UI debe presentar esto como comportamiento observado, no como “firewall confirmado”.

## 3. Elevated DNS Activity

Función:

```ts
analyzeDnsBehavior(packets, baseline)
```

Propósito:
Detecta tráfico DNS elevado. Con los datos actuales, esta regla es únicamente de volumen.

| Señal | Condición |
|---|---:|
| DNS share | DNS > 30% de todos los paquetes |
| DNS rate | Más de 20 DNS packets/sec, solo si el tiempo es confiable |
| Single-source DNS | Un origen produce >70% del DNS |

Fórmula:

```ts
confidence = volumeScore * sampleMultiplier
```

El score se limita a `0.62` para evitar que una alerta de volumen parezca análisis estructural.

Desactivado hasta cambiar el sidecar:

- query name
- record type
- response code
- NXDOMAIN
- dominios únicos reales
- entropía de subdominios
- DNS tunneling probable

Por eso la alerta no debe decir ni insinuar que detecta DNS tunneling.

## 4. Elevated ARP Volume

Función:

```ts
analyzeArpBehavior(packets, baseline)
```

Propósito:
Detecta volumen ARP elevado o broadcast ARP inusual. No detecta ARP spoofing real todavía.

| Señal | Condición |
|---|---:|
| ARP volume | ARP > max(30, totalPackets * 15%) |
| ARP broadcast volume | Broadcast ARP > max(20, totalPackets * 10%) |
| ARP/sec | ARP rate > 10/sec, solo si el tiempo es confiable |

Severidad:

| Confidence | Level |
|---:|---|
| Menor a 0.30 | Se suprime |
| 0.30 o más | `info` |

Desactivado hasta cambiar el sidecar:

- sender hardware address
- sender protocol address
- target hardware address
- target protocol address
- opcode request/reply
- misma IP anunciada por múltiples MACs
- misma MAC anunciando múltiples IPs
- gratuitous ARP bursts
- ARP spoofing más confiable

No basta con Ethernet `src_mac` / `dst_mac`. Para ARP, la identidad real viene dentro del payload ARP.

## 5. Dominant Host

Función:

```ts
analyzeDominantHosts(packets, baseline, gatewaySet)
```

Propósito:
Detecta cuando una IP o MAC concentra una parte inusual del tráfico.

La regla compara al host dominante contra el siguiente host visible:

```ts
dominanceGap = topHostShare - secondHostShare
```

También reduce confianza cuando:

- hay menos de 4 hosts visibles
- el host parece gateway probable

| Familia | Señales | Máximo |
|---|---|---:|
| Volumen relativo | packet share, byte share, gap contra segundo host | 0.45 |
| Comportamiento | persistencia, diversidad de protocolos, diversidad de puertos | 0.25 |

Severidad:

| Confidence | Level |
|---:|---|
| Menor a 0.32 | Se suprime |
| 0.32 a 0.58 | `info` |
| Mayor a 0.58 | `warning` |

Esta regla no escala a `critical` por sí sola.

## 6. Heavy Traffic Concentration

Función:

```ts
analyzeHeavyTraffic(packets, baseline, gatewaySet)
```

Propósito:
Detecta un host moviendo muchos bytes con relativamente pocos paquetes.

Prerrequisitos:

- `totalPackets >= 5`
- `totalBytes >= 32 KB`

Se eliminó el peso por “puertos conocidos” porque `443` concentra muchísimo tráfico moderno y aporta poco valor diagnóstico.

Ahora se priorizan medidas relativas:

- byte share
- packet share
- byte gap contra el segundo host
- tamaño promedio de paquete
- throughput relativo si la duración es confiable
- concentración hacia un endpoint opuesto

Severidad:

| Confidence | Level |
|---:|---|
| Menor a 0.33 | Se suprime |
| 0.33 a 0.71 | `info` |
| 0.72 o más | `warning` |

## 7. Possible Active Reconnaissance

Función:

```ts
correlateAlerts(alerts)
```

Propósito:
Crea una alerta compuesta cuando el mismo host dispara:

- Possible Port Scan
- Elevated TCP Reset Activity

Resultado:

```txt
Possible active reconnaissance
```

La alerta conserva trazabilidad explícita en evidencia:

```txt
Contributing signals: Possible Port Scan + Elevated TCP Reset Activity.
```

Motivo:
Un host que genera muchos SYN hacia puertos/destinos y además está relacionado con muchos RST cuenta una historia más fuerte que cualquiera de las dos alertas aisladas.

## Deduplicación

Si el mismo host dispara:

- Dominant Host
- Heavy Traffic Concentration

NetScope fusiona ambas en una sola alerta:

```txt
Dominant heavy-traffic host
```

La alerta combinada conserva:

- mayor severidad
- mayor confianza
- mayor `impact_score`
- evidencia combinada
- IPs/MACs combinadas
- métricas combinadas

## Ranking

Las alertas se ordenan por:

1. severidad: `critical`, `warning`, `info`, `success`
2. `impact_score`
3. fuerza de señal (`confidence`)

## Flujo de ejecución

Entrada principal:

```ts
analyzeDiagnostics(packets)
```

Pseudocódigo:

```ts
function analyzeDiagnostics(packets) {
  if packets is empty:
    return waitingForTraffic

  baseline = computeBaseline(packets)
  gatewaySet = detectLikelyGateways(packets, baseline)

  alerts = [
    analyzePortScan(packets, baseline),
    analyzeTcpResetActivity(packets, baseline),
    analyzeDnsBehavior(packets, baseline),
    analyzeArpBehavior(packets, baseline),
    analyzeDominantHosts(packets, baseline, gatewaySet),
    analyzeHeavyTraffic(packets, baseline, gatewaySet)
  ]

  alerts = deduplicateAlerts(alerts)
  alerts = correlateAlerts(alerts)
  alerts = rankAlerts(alerts)

  if alerts is empty:
    return normalNetwork

  return alerts
}
```

## Archivos relacionados

- `src/utils/diagnostics.ts`: motor puro de reglas.
- `src/hooks/useDiagnostics.ts`: calcula métricas para la vista y llama `analyzeDiagnostics`.
- `src/views/DiagnosticsView.tsx`: muestra cards, gráficas, tablas y alertas.
- `src/types/packet.ts`: shape del paquete que consume el motor.
- `src/lib/packetRows.ts`: convierte paquetes de SQLite al formato `Packet`.

## Pendiente En El Sidecar C++

Para encender las reglas avanzadas, el sidecar debe emitir campos nuevos en el JSON de cada paquete.

### DNS estructural

Campos sugeridos:

```json
{
  "dns_query": "example.com",
  "dns_record_type": "A",
  "dns_rcode": "NOERROR",
  "dns_is_response": false
}
```

Con eso se podrían activar:

- dominios únicos reales
- TXT record dominance
- NXDOMAIN rate
- entropía de subdominios
- DNS tunneling probable

### ARP payload

Campos sugeridos:

```json
{
  "arp_opcode": "reply",
  "arp_sender_ip": "192.168.1.1",
  "arp_sender_mac": "aa:bb:cc:dd:ee:ff",
  "arp_target_ip": "192.168.1.50",
  "arp_target_mac": "00:00:00:00:00:00"
}
```

Con eso se podrían activar:

- misma IP anunciada por múltiples MACs
- misma MAC anunciando múltiples IPs
- gratuitous ARP bursts
- ARP spoofing más confiable

### Dirección de captura / flujo TCP

Campos o lógica sugerida:

- flow id normalizado.
- dirección del paquete dentro del flujo.
- SYN/SYN-ACK/ACK por flujo.
- indicación de conversación bidireccional.

Con eso se reducirían falsos positivos en port scan y se mediría mejor el ratio ACK/SYN.
