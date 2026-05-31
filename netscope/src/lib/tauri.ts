/**
 * tauri.ts
 *
 * ES: Wrappers tipados para los comandos y eventos expuestos por Rust.
 * EN: Typed wrappers for commands and events exposed by Rust.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type Protocol =
  | "TCP" | "UDP" | "ICMP" | "ARP"
  | "DNS" | "HTTP" | "HTTPS" | "OTHER";

export type TcpFlags =
  | "SYN" | "ACK" | "FIN" | "RST" | "PSH" | "SYN-ACK" | "";

export interface Packet {
  id:          number;
  ts:          string;         // ES: ISO-8601 con ms. / EN: ISO-8601 with ms.
  src_ip:      string | null;
  dst_ip:      string | null;
  src_port:    number | null;
  dst_port:    number | null;
  protocol:    Protocol;
  length:      number;
  ttl:         number | null;
  flags:       TcpFlags;
  payload_hex: string;
  raw_ascii:   string;
}

export interface Interface {
  id:       number;
  name:     string;
  desc:     string;
  loopback: boolean;
  up:       boolean;
}

export interface Stats {
  captured: number;
  dropped:  number;
  rate_pps: number;
}

export interface ListInterfacesResponse {
  interfaces: Interface[];
  refreshed:  boolean;
}

export interface CaptureStatusResponse {
  running:    boolean;
  session_id: number | null;
}

export interface SnifferError {
  msg: string;
}

export interface Session {
  id:            number;
  name:          string | null;
  interface:     string | null;
  started_at:    string | null;
  ended_at:      string | null;
  total_packets: number;
}

/** ES: Refleja PacketRow para lecturas DB y persist_packet. / EN: Mirrors PacketRow for DB reads and persist_packet. */
export interface PacketRow {
  id:          number;
  session_id:  number;
  ts:          string;
  src_ip:      string | null;
  dst_ip:      string | null;
  src_port:    number | null;
  dst_port:    number | null;
  protocol:    string | null;
  length:      number | null;
  ttl:         number | null;
  flags:       string | null;
  payload_hex: string | null;
  raw_ascii:   string | null;
}

/** ES: Filtros opcionales enviados a queryPackets. / EN: Optional filters passed to queryPackets. */
export interface PacketFilters {
  src_ip?:     string;
  dst_ip?:     string;
  src_port?:   number;
  dst_port?:   number;
  protocol?:   string;
  min_length?: number;
  max_length?: number;
  /** ES: Busqueda libre por IP y protocolo. / EN: Free-text search across IPs and protocol. */
  search?:     string;
}

export interface PaginatedResult<T> {
  items:       T[];
  total:       number;
  page:        number;
  page_size:   number;
  total_pages: number;
}

export interface ProtocolStat {
  protocol: string;
  count:    number;
}

export interface TimePoint {
  bucket:  string;   // ES: Inicio del bloque ISO-8601. / EN: ISO-8601 bucket start.
  packets: number;
  bytes:   number;
}

export interface TopIp {
  ip:    string;
  count: number;
}

export interface DiagnosticRow {
  id:         number;
  session_id: number | null;
  ts:         string | null;
  metric:     string | null;
  value:      number | null;
}

export interface DiagnosticsData {
  session_id:       number;
  protocol_stats:   ProtocolStat[];
  traffic_timeline: TimePoint[];
  top_src_ips:      TopIp[];
  top_dst_ips:      TopIp[];
  total_packets:    number;
  total_bytes:      number;
  avg_packet_size:  number;
  recent_errors:    DiagnosticRow[];
}

export interface StartCaptureArgs {
  interfaceId:   number;
  sessionName?:  string;
  interfaceName?: string;
}

/**
 * ES: Inicia captura y devuelve el id de la nueva sesion DB.
 * EN: Starts capture and returns the new DB session id.
 */
export async function startCapture(args: StartCaptureArgs): Promise<number> {
  return invoke("start_capture", {
    args: {
      interface_id:   args.interfaceId,
      session_name:   args.sessionName   ?? null,
      interface_name: args.interfaceName ?? null,
    },
  });
}

/** ES: Detiene la captura activa; es idempotente. / EN: Stops active capture; idempotent. */
export async function stopCapture(): Promise<void> {
  return invoke("stop_capture");
}

/** ES: Cambia de interfaz sin crear sesion. / EN: Changes interface without creating a session. */
export async function setInterface(interfaceId: number): Promise<void> {
  return invoke("set_interface", { interfaceId });
}

/** ES: Aplica un filtro BPF. / EN: Applies a BPF filter. */
export async function setBpfFilter(filter: string): Promise<void> {
  return invoke("set_bpf_filter", { filter });
}

/** ES: Devuelve interfaces disponibles. / EN: Returns available interfaces. */
export async function listInterfaces(): Promise<ListInterfacesResponse> {
  return invoke("list_interfaces");
}

/** ES: Obtiene un snapshot de estadisticas. / EN: Retrieves a stats snapshot. */
export async function getStats(): Promise<Stats> {
  return invoke("get_stats");
}

/** ES: Comprueba si el sidecar captura. / EN: Checks whether the sidecar is capturing. */
export async function captureStatus(): Promise<CaptureStatusResponse> {
  return invoke("capture_status");
}

/** ES: Lista sesiones recientes primero. / EN: Lists sessions newest first. */
export async function listSessions(): Promise<Session[]> {
  return invoke("list_sessions");
}

/** ES: Elimina sesion y paquetes asociados. / EN: Deletes a session and its packets. */
export async function deleteSession(sessionId: number): Promise<void> {
  return invoke("delete_session", { sessionId });
}

/** ES: Guarda un paquete en la sesion actual. / EN: Persists a packet in the current session. */
export async function persistPacket(packet: PacketRow): Promise<void> {
  return invoke("persist_packet", { packet });
}

export interface QueryPacketsArgs {
  sessionId: number;
  filters:   PacketFilters;
  page:      number;
  pageSize:  number;
}

/**
 * ES: Consulta paginada con filtros. / EN: Paginated filtered query.
 *
 * @example
 * const result = await queryPackets({
 *   sessionId: 1,
 *   filters: { protocol: 'HTTPS', minLength: 100 },
 *   page: 1,
 *   pageSize: 100,
 * });
 */
export async function queryPackets(
  args: QueryPacketsArgs,
): Promise<PaginatedResult<PacketRow>> {
  return invoke("query_packets", {
    args: {
      session_id: args.sessionId,
      filters:    args.filters,
      page:       args.page,
      page_size:  args.pageSize,
    },
  });
}

/**
 * ES: Exporta paquetes filtrados como JSON para guardado o CSV.
 * EN: Exports filtered packets as JSON for save or CSV flows.
 */
export async function exportPacketsJson(
  sessionId: number,
  filters?: PacketFilters,
): Promise<string> {
  return invoke("export_packets_json", {
    sessionId,
    filters: filters ?? null,
  });
}

/**
 * ES: Devuelve analitica completa de una sesion.
 * EN: Returns the full analytics bundle for a session.
 */
export async function getDiagnosticsData(
  sessionId: number,
): Promise<DiagnosticsData> {
  return invoke("get_diagnostics_data", { sessionId });
}

/** ES: Guarda una metrica en diagnosticos. / EN: Stores a diagnostics metric. */
export async function recordDiagnostic(
  sessionId: number,
  metric:    string,
  value:     number,
): Promise<void> {
  return invoke("record_diagnostic", { sessionId, metric, value });
}

/** ES: Se ejecuta por paquete; limitar frecuencia si hace falta. / EN: Runs per packet; throttle if needed. */
export function onPacket(cb: (pkt: Packet) => void): Promise<UnlistenFn> {
  return listen<Packet>("packet", (e) => cb(e.payload));
}

/** ES: Fallback para paquetes crudos. / EN: Raw packet fallback. */
export function onPacketRaw(cb: (raw: unknown) => void): Promise<UnlistenFn> {
  return listen<unknown>("packet_raw", (e) => cb(e.payload));
}

/** ES: Recibe estadisticas cada segundo. / EN: Receives stats every second. */
export function onNetStats(cb: (stats: Stats) => void): Promise<UnlistenFn> {
  return listen<Stats>("net_stats", (e) => cb(e.payload));
}

/** ES: Recibe interfaces emitidas o actualizadas. / EN: Receives emitted or refreshed interfaces. */
export function onInterfaces(
  cb: (interfaces: Interface[]) => void,
): Promise<UnlistenFn> {
  return listen<Interface[]>("interfaces", (e) => cb(e.payload));
}

/** ES: Recibe errores del sidecar o Rust. / EN: Receives sidecar or Rust errors. */
export function onSnifferError(
  cb: (err: SnifferError) => void,
): Promise<UnlistenFn> {
  return listen<SnifferError>("sniffer_error", (e) => cb(e.payload));
}
