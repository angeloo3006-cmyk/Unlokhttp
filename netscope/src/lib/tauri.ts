/**
 * tauri.ts
 *
 * ES: Wrappers tipados para los comandos y eventos expuestos por Rust.
 * EN: Typed wrappers for commands and events exposed by Rust.
 */

import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen as tauriListen, type UnlistenFn } from "@tauri-apps/api/event";

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
  link_layer:  string | null;
  src_mac:     string | null;
  dst_mac:     string | null;
  src_vendor:  string | null;
  dst_vendor:  string | null;
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
  link_layer:  string | null;
  src_mac:     string | null;
  dst_mac:     string | null;
  src_vendor:  string | null;
  dst_vendor:  string | null;
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

function isTauriRuntime() {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function invoke<T>(cmd: string, args?: Record<string, unknown>, browserFallback?: T): Promise<T> {
  if (!isTauriRuntime()) {
    void cmd;
    void args;
    return Promise.resolve(browserFallback as T);
  }

  return tauriInvoke<T>(cmd, args);
}

function listen<T>(event: string, cb: (event: { payload: T }) => void): Promise<UnlistenFn> {
  if (!isTauriRuntime()) return Promise.resolve(() => {});
  return tauriListen<T>(event, cb);
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
  }, 0);
}

/** ES: Detiene la captura activa; es idempotente. / EN: Stops active capture; idempotent. */
export async function stopCapture(): Promise<void> {
  return invoke("stop_capture", undefined, undefined);
}

/** ES: Cambia de interfaz sin crear sesion. / EN: Changes interface without creating a session. */
export async function setInterface(interfaceId: number): Promise<void> {
  return invoke("set_interface", { interfaceId }, undefined);
}

/** ES: Aplica un filtro BPF. / EN: Applies a BPF filter. */
export async function setBpfFilter(filter: string): Promise<void> {
  return invoke("set_bpf_filter", { filter }, undefined);
}

/** ES: Devuelve interfaces disponibles. / EN: Returns available interfaces. */
export async function listInterfaces(): Promise<ListInterfacesResponse> {
  return invoke("list_interfaces", undefined, { interfaces: mockInterfaces(), refreshed: false });
}

/** ES: Obtiene un snapshot de estadisticas. / EN: Retrieves a stats snapshot. */
export async function getStats(): Promise<Stats> {
  return invoke("get_stats", undefined, { captured: 0, dropped: 0, rate_pps: 0 });
}

/** ES: Comprueba si el sidecar captura. / EN: Checks whether the sidecar is capturing. */
export async function captureStatus(): Promise<CaptureStatusResponse> {
  return invoke("capture_status", undefined, { running: false, session_id: null });
}

/** ES: Lista sesiones recientes primero. / EN: Lists sessions newest first. */
export async function listSessions(): Promise<Session[]> {
  return invoke("list_sessions", undefined, mockSessions());
}

/** ES: Elimina sesion y paquetes asociados. / EN: Deletes a session and its packets. */
export async function deleteSession(sessionId: number): Promise<void> {
  return invoke("delete_session", { sessionId }, undefined);
}

/** ES: Guarda un paquete en la sesion actual. / EN: Persists a packet in the current session. */
export async function persistPacket(packet: PacketRow): Promise<void> {
  return invoke("persist_packet", { packet }, undefined);
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
  const mockPacketPage = mockPacketsPage(args);
  return invoke("query_packets", {
    args: {
      session_id: args.sessionId,
      filters:    args.filters,
      page:       args.page,
      page_size:  args.pageSize,
    },
  }, mockPacketPage ?? {
    items: [],
    total: 0,
    page: args.page,
    page_size: args.pageSize,
    total_pages: 1,
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
  }, "[]");
}

/**
 * ES: Devuelve analitica completa de una sesion.
 * EN: Returns the full analytics bundle for a session.
 */
export async function getDiagnosticsData(
  sessionId: number,
): Promise<DiagnosticsData> {
  return invoke("get_diagnostics_data", { sessionId }, mockDiagnostics(sessionId) ?? {
    session_id: sessionId,
    protocol_stats: [],
    traffic_timeline: [],
    top_src_ips: [],
    top_dst_ips: [],
    total_packets: 0,
    total_bytes: 0,
    avg_packet_size: 0,
    recent_errors: [],
  });
}

/** ES: Guarda una metrica en diagnosticos. / EN: Stores a diagnostics metric. */
export async function recordDiagnostic(
  sessionId: number,
  metric:    string,
  value:     number,
): Promise<void> {
  return invoke("record_diagnostic", { sessionId, metric, value }, undefined);
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

/** ES: Recibe cambios de estado de captura. / EN: Receives capture state changes. */
export function onCaptureState(
  cb: (state: { running: boolean }) => void,
): Promise<UnlistenFn> {
  return listen<{ running: boolean }>("capture_state", (e) => cb(e.payload));
}

function browserMockEnabled() {
  return !isTauriRuntime()
    && typeof window !== "undefined"
    && window.location.search.includes("mockSessions=1");
}

function mockSessions(): Session[] {
  if (!browserMockEnabled()) return [];
  return [{
    id: 1,
    name: "Capture 14/6/2026, 10:26:47 p.m.",
    interface: "\\Device\\NPF_{8DB606F1-8752-4C7F-9C6A-18E4969CF24E}",
    started_at: "2026-06-15T04:26:47.744Z",
    ended_at: "2026-06-15T04:26:51.657Z",
    total_packets: 41,
  }];
}

function mockInterfaces(): Interface[] {
  if (!browserMockEnabled()) return [];
  return [{
    id: 0,
    name: "\\Device\\NPF_{8DB606F1-8752-4C7F-9C6A-18E4969CF24E}",
    desc: "Wi-Fi",
    loopback: false,
    up: true,
  }];
}

function mockPacketRows(): PacketRow[] {
  if (!browserMockEnabled()) return [];

  return Array.from({ length: 41 }, (_, index) => {
    const protocol = index % 8 === 0 ? "UDP" : "OTHER";
    const length = protocol === "UDP" ? 77 : 158;
    return {
      id: index,
      session_id: 1,
      ts: index < 2 ? "2026-06-15T04:26:47.744Z" : "2026-06-15T04:26:51.657Z",
      src_ip: protocol === "UDP" ? "192.168.1.84" : null,
      dst_ip: protocol === "UDP" ? "192.168.1.255" : null,
      src_port: protocol === "UDP" ? 56517 : null,
      dst_port: protocol === "UDP" ? 15600 : null,
      protocol,
      length,
      ttl: protocol === "UDP" ? 128 : null,
      flags: "",
      link_layer: "Ethernet",
      src_mac: protocol === "UDP" ? "00:11:22:33:44:55" : null,
      dst_mac: protocol === "UDP" ? "ff:ff:ff:ff:ff:ff" : null,
      src_vendor: protocol === "UDP" ? "Mock Vendor" : null,
      dst_vendor: protocol === "UDP" ? "Broadcast" : null,
      payload_hex: "60053f2c001406402806103e00027d65".repeat(2),
      raw_ascii: "`?.-,....@(...>}e",
    };
  });
}

function mockPacketsPage(args: QueryPacketsArgs): PaginatedResult<PacketRow> | null {
  const rows = mockPacketRows();
  if (!rows.length) return null;

  const search = args.filters.search?.trim().toLowerCase();
  const filtered = search
    ? rows.filter((row) => JSON.stringify(row).toLowerCase().includes(search))
    : rows;
  const pageSize = Math.max(1, args.pageSize);
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const page = Math.min(Math.max(1, args.page), totalPages);
  const offset = (page - 1) * pageSize;

  return {
    items: filtered.slice(offset, offset + pageSize),
    total: filtered.length,
    page,
    page_size: pageSize,
    total_pages: totalPages,
  };
}

function mockDiagnostics(sessionId: number): DiagnosticsData | null {
  const rows = mockPacketRows();
  if (!rows.length) return null;

  const totalBytes = rows.reduce((sum, row) => sum + (row.length ?? 0), 0);
  const protocolCounts = rows.reduce<Record<string, number>>((counts, row) => {
    const protocol = row.protocol ?? "OTHER";
    counts[protocol] = (counts[protocol] ?? 0) + 1;
    return counts;
  }, {});

  return {
    session_id: sessionId,
    protocol_stats: Object.entries(protocolCounts).map(([protocol, count]) => ({ protocol, count })),
    traffic_timeline: [{ bucket: "2026-06-15T04:26:47.744Z", packets: rows.length, bytes: totalBytes }],
    top_src_ips: [{ ip: "192.168.1.84", count: 5 }],
    top_dst_ips: [{ ip: "192.168.1.255", count: 5 }],
    total_packets: rows.length,
    total_bytes: totalBytes,
    avg_packet_size: totalBytes / rows.length,
    recent_errors: [],
  };
}
