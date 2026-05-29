/**
 * tauri.ts
 *
 * Strongly-typed wrappers around `invoke()` and `listen()` for every
 * Rust command and event exposed by netscope's backend.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

// ─────────────────────────────────────────────────────────────────────────────
// Primitive / shared types
// ─────────────────────────────────────────────────────────────────────────────

export type Protocol =
  | "TCP" | "UDP" | "ICMP" | "ARP"
  | "DNS" | "HTTP" | "HTTPS" | "OTHER";

export type TcpFlags =
  | "SYN" | "ACK" | "FIN" | "RST" | "PSH" | "SYN-ACK" | "";

// ─────────────────────────────────────────────────────────────────────────────
// Sniffer / live-capture types
// ─────────────────────────────────────────────────────────────────────────────

export interface Packet {
  id:          number;
  ts:          string;         // ISO-8601 with ms
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

// ─────────────────────────────────────────────────────────────────────────────
// DB types (mirror Rust structs in db.rs)
// ─────────────────────────────────────────────────────────────────────────────

export interface Session {
  id:            number;
  name:          string | null;
  interface:     string | null;
  started_at:    string | null;
  ended_at:      string | null;
  total_packets: number;
}

/** Mirror of `PacketRow` — used for DB reads and the persist_packet command. */
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

/** All-optional filter bag passed to `queryPackets`. */
export interface PacketFilters {
  src_ip?:     string;
  dst_ip?:     string;
  src_port?:   number;
  dst_port?:   number;
  protocol?:   string;
  min_length?: number;
  max_length?: number;
  /** Free-text search across IPs and protocol. */
  search?:     string;
}

export interface PaginatedResult<T> {
  items:       T[];
  total:       number;
  page:        number;
  page_size:   number;
  total_pages: number;
}

// ── Diagnostics / analytics ──────────────────────────────────────────────────

export interface ProtocolStat {
  protocol: string;
  count:    number;
}

export interface TimePoint {
  bucket:  string;   // ISO-8601 bucket start
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

// ─────────────────────────────────────────────────────────────────────────────
// Capture lifecycle commands
// ─────────────────────────────────────────────────────────────────────────────

export interface StartCaptureArgs {
  interfaceId:   number;
  sessionName?:  string;
  interfaceName?: string;
}

/**
 * Start packet capture on the given interface.
 * Returns the new DB session id.
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

/** Stop an active capture session. Idempotent. */
export async function stopCapture(): Promise<void> {
  return invoke("stop_capture");
}

/** Restart capture on a different interface without creating a new session. */
export async function setInterface(interfaceId: number): Promise<void> {
  return invoke("set_interface", { interfaceId });
}

/** Apply a BPF filter expression to the running capture. */
export async function setBpfFilter(filter: string): Promise<void> {
  return invoke("set_bpf_filter", { filter });
}

/** Return available network interfaces. */
export async function listInterfaces(): Promise<ListInterfacesResponse> {
  return invoke("list_interfaces");
}

/** Pull-based stats snapshot. */
export async function getStats(): Promise<Stats> {
  return invoke("get_stats");
}

/** Check whether the sidecar is currently capturing. */
export async function captureStatus(): Promise<CaptureStatusResponse> {
  return invoke("capture_status");
}

// ─────────────────────────────────────────────────────────────────────────────
// Session management commands
// ─────────────────────────────────────────────────────────────────────────────

/** List all recorded sessions, newest first. */
export async function listSessions(): Promise<Session[]> {
  return invoke("list_sessions");
}

/** Delete a session and all its associated packets. */
export async function deleteSession(sessionId: number): Promise<void> {
  return invoke("delete_session", { sessionId });
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet persistence commands
// ─────────────────────────────────────────────────────────────────────────────

/** Persist a single packet into the current session. */
export async function persistPacket(packet: PacketRow): Promise<void> {
  return invoke("persist_packet", { packet });
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet query commands
// ─────────────────────────────────────────────────────────────────────────────

export interface QueryPacketsArgs {
  sessionId: number;
  filters:   PacketFilters;
  page:      number;
  pageSize:  number;
}

/**
 * Paginated, filtered packet query.
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
 * Export all packets matching `filters` as a raw JSON string.
 * Useful for "Save capture" / CSV export flows.
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

// ─────────────────────────────────────────────────────────────────────────────
// Diagnostics / analytics commands
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Return the full analytics bundle for a session.
 *
 * Includes: protocol distribution, 5-second traffic timeline, top IPs,
 * byte totals, average packet size, and recent diagnostic rows.
 */
export async function getDiagnosticsData(
  sessionId: number,
): Promise<DiagnosticsData> {
  return invoke("get_diagnostics_data", { sessionId });
}

/** Record a named metric value into the diagnostics table. */
export async function recordDiagnostic(
  sessionId: number,
  metric:    string,
  value:     number,
): Promise<void> {
  return invoke("record_diagnostic", { sessionId, metric, value });
}

// ─────────────────────────────────────────────────────────────────────────────
// Real-time event subscriptions
// ─────────────────────────────────────────────────────────────────────────────

/** Called for every captured packet (high-frequency — throttle if needed). */
export function onPacket(cb: (pkt: Packet) => void): Promise<UnlistenFn> {
  return listen<Packet>("packet", (e) => cb(e.payload));
}

/** Raw / undeserializable packet fallback. */
export function onPacketRaw(cb: (raw: unknown) => void): Promise<UnlistenFn> {
  return listen<unknown>("packet_raw", (e) => cb(e.payload));
}

/** Called every second with throughput statistics. */
export function onNetStats(cb: (stats: Stats) => void): Promise<UnlistenFn> {
  return listen<Stats>("net_stats", (e) => cb(e.payload));
}

/** Called when the sidecar emits or refreshes the interface list. */
export function onInterfaces(
  cb: (interfaces: Interface[]) => void,
): Promise<UnlistenFn> {
  return listen<Interface[]>("interfaces", (e) => cb(e.payload));
}

/** Called on any error from the sidecar or the Rust layer. */
export function onSnifferError(
  cb: (err: SnifferError) => void,
): Promise<UnlistenFn> {
  return listen<SnifferError>("sniffer_error", (e) => cb(e.payload));
}
