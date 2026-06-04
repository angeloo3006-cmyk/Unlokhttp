import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { Activity, Clock3, Database, Network, RefreshCw, Search, Trash2, type LucideIcon } from "lucide-react";
import {
  deleteSession,
  getDiagnosticsData,
  listSessions,
  queryPackets,
  type DiagnosticsData,
  type PacketRow,
  type Session,
} from "@/lib/tauri";

const PAGE_SIZE = 200;

export function SessionsView() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<number | null>(null);
  const [diagnostics, setDiagnostics] = useState<DiagnosticsData | null>(null);
  const [packets, setPackets] = useState<PacketRow[]>([]);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalPackets, setTotalPackets] = useState(0);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedSession = sessions.find((session) => session.id === selectedSessionId) ?? null;

  const loadSessions = useCallback(async () => {
    try {
      const data = await listSessions();
      setSessions(data);
      setSelectedSessionId((current) => {
        if (current && data.some((session) => session.id === current)) return current;
        return data[0]?.id ?? null;
      });
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    void loadSessions();
  }, [loadSessions]);

  useEffect(() => {
    if (!selectedSessionId) {
      setDiagnostics(null);
      setPackets([]);
      setTotalPackets(0);
      setTotalPages(1);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    const filters = search.trim() ? { search: search.trim() } : {};

    Promise.all([
      getDiagnosticsData(selectedSessionId),
      queryPackets({
        sessionId: selectedSessionId,
        filters,
        page,
        pageSize: PAGE_SIZE,
      }),
    ])
      .then(([diagnosticsData, packetPage]) => {
        if (cancelled) return;
        setDiagnostics(diagnosticsData);
        setPackets(packetPage.items);
        setTotalPackets(packetPage.total);
        setTotalPages(Math.max(1, packetPage.total_pages));
      })
      .catch((err) => {
        if (!cancelled) setError(String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [page, search, selectedSessionId]);

  const protocolWeights = useMemo(() => {
    const total = Math.max(1, diagnostics?.total_packets ?? 0);
    const entries = diagnostics?.protocol_stats ?? [];
    return new Map(entries.map((item) => [item.protocol, (item.count / total) * 100]));
  }, [diagnostics]);

  const windowInfo = useMemo(() => buildWindowInfo(selectedSession, diagnostics), [selectedSession, diagnostics]);
  const protocolRows = diagnostics?.protocol_stats ?? [];
  const maxProtocolCount = Math.max(1, ...protocolRows.map((item) => item.count));
  const maxOriginCount = Math.max(
    1,
    ...(diagnostics?.top_src_ips ?? []).map((item) => item.count),
    ...(diagnostics?.top_dst_ips ?? []).map((item) => item.count),
  );

  const handleDelete = async () => {
    if (!selectedSessionId) return;
    try {
      await deleteSession(selectedSessionId);
      setSelectedSessionId(null);
      setPage(1);
      await loadSessions();
    } catch (err) {
      setError(String(err));
    }
  };

  return (
    <div className="flex h-full min-h-0 gap-3 p-3">
      <aside className="glass-panel flex w-[280px] shrink-0 flex-col overflow-hidden">
        <div className="flex items-center justify-between border-b border-glass p-3">
          <div>
            <p className="text-[10px] uppercase tracking-[0.2em] text-muted">SQLite Sessions</p>
            <h1 className="mt-1 text-sm font-semibold">Saved captures</h1>
          </div>
          <button className="button-ghost px-2" onClick={() => void loadSessions()}>
            <RefreshCw size={13} />
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-auto p-2">
          {sessions.length ? (
            sessions.map((session) => (
              <button
                className={`mb-2 w-full rounded-lg border p-3 text-left transition ${
                  selectedSessionId === session.id
                    ? "border-blue-400/35 bg-blue-500/12"
                    : "border-white/5 bg-white/[0.025] hover:bg-white/[0.055]"
                }`}
                key={session.id}
                onClick={() => {
                  setSelectedSessionId(session.id);
                  setPage(1);
                }}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-xs font-semibold">{session.name ?? `Session #${session.id}`}</span>
                  <span className="rounded-full bg-white/5 px-2 py-0.5 text-[10px] text-muted">#{session.id}</span>
                </div>
                <p className="mt-1 truncate text-[11px] text-secondary">{session.interface ?? "Unknown interface"}</p>
                <div className="mt-3 grid grid-cols-2 gap-2 text-[10px] text-muted">
                  <span>{formatSessionDate(session.started_at)}</span>
                  <span className="text-right">{session.total_packets.toLocaleString()} packets</span>
                </div>
              </button>
            ))
          ) : (
            <div className="p-4 text-xs text-secondary">
              No saved sessions yet. Start and stop a capture to persist packets in SQLite.
            </div>
          )}
        </div>
      </aside>

      <section className="flex min-w-0 flex-1 flex-col gap-3 overflow-hidden">
        <div className="glass-panel p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-[10px] uppercase tracking-[0.2em] text-muted">Database session</p>
              <h2 className="mt-1 text-lg font-semibold">
                {selectedSession ? selectedSession.name ?? `Session #${selectedSession.id}` : "Select a session"}
              </h2>
              <p className="mt-1 text-xs text-secondary">{selectedSession?.interface ?? "No interface selected"}</p>
            </div>
            <div className="flex gap-2">
              <button className="button-ghost" onClick={() => void loadSessions()}>
                <RefreshCw size={13} /> Refresh
              </button>
              <button className="button-danger" disabled={!selectedSessionId} onClick={() => void handleDelete()}>
                <Trash2 size={13} /> Delete
              </button>
            </div>
          </div>

          {error && <div className="mt-3 rounded-lg border border-red-300/15 bg-red-500/10 p-2 text-xs text-red-100">{error}</div>}

          <div className="mt-4 grid grid-cols-4 gap-2">
            <MetricCard icon={Database} label="Packets in DB" value={(diagnostics?.total_packets ?? selectedSession?.total_packets ?? 0).toLocaleString()} />
            <MetricCard icon={Activity} label="Traffic weight" value={formatBytes(diagnostics?.total_bytes ?? 0)} />
            <MetricCard icon={Network} label="Avg packet" value={formatBytes(diagnostics?.avg_packet_size ?? 0)} />
            <MetricCard icon={Clock3} label="Duration" value={windowInfo.duration} />
          </div>
        </div>

        <div className="grid min-h-[210px] grid-cols-[1.1fr_1fr_1fr] gap-3">
          <Panel title="Time window: day / hour / minute">
            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <InfoCell label="Start day" value={windowInfo.startDay} />
              <InfoCell label="End day" value={windowInfo.endDay} />
              <InfoCell label="Start hour" value={windowInfo.startHour} />
              <InfoCell label="End hour" value={windowInfo.endHour} />
              <InfoCell label="Start minute" value={windowInfo.startMinute} />
              <InfoCell label="End minute" value={windowInfo.endMinute} />
            </div>
            <div className="mt-3 rounded-lg border border-white/5 bg-white/[0.025] p-2 text-[11px] text-secondary">
              Timeline buckets stored from DB: {diagnostics?.traffic_timeline.length ?? 0}
            </div>
          </Panel>

          <Panel title="Protocol weight">
            <div className="space-y-2">
              {protocolRows.length ? (
                protocolRows.map((item) => {
                  const percent = protocolWeights.get(item.protocol) ?? 0;
                  return (
                    <div key={item.protocol}>
                      <div className="mb-1 flex justify-between text-[11px]">
                        <span className="text-primary">{item.protocol}</span>
                        <span className="text-secondary">{percent.toFixed(1)}% / {item.count.toLocaleString()}</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-white/5">
                        <div className="h-full rounded-full bg-cyan-400" style={{ width: `${(item.count / maxProtocolCount) * 100}%` }} />
                      </div>
                    </div>
                  );
                })
              ) : (
                <EmptyText text="No protocol data yet." />
              )}
            </div>
          </Panel>

          <Panel title="Origins">
            <OriginList title="Sources" rows={diagnostics?.top_src_ips ?? []} max={maxOriginCount} />
            <div className="mt-3 border-t border-glass pt-3">
              <OriginList title="Destinations" rows={diagnostics?.top_dst_ips ?? []} max={maxOriginCount} />
            </div>
          </Panel>
        </div>

        <div className="glass-panel flex min-h-0 flex-1 flex-col overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-glass p-3">
            <div>
              <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Packets from SQLite</p>
              <p className="mt-1 text-xs text-secondary">
                Showing {packets.length.toLocaleString()} of {totalPackets.toLocaleString()} matching packets
              </p>
            </div>
            <form
              className="flex min-w-[280px] gap-2"
              onSubmit={(event) => {
                event.preventDefault();
                setPage(1);
              }}
            >
              <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-2 top-2 text-muted" size={13} />
                <input
                  className="glass-input pl-7"
                  placeholder="Search IP or protocol in DB"
                  value={search}
                  onChange={(event) => {
                    setSearch(event.target.value);
                    setPage(1);
                  }}
                />
              </div>
            </form>
          </div>

          <div className="min-h-0 flex-1 overflow-auto">
            <table className="w-full border-collapse font-mono text-[11px]">
              <thead className="sticky top-0 z-10 bg-white/[0.055] text-secondary">
                <tr className="border-b border-glass">
                  <Th>#</Th>
                  <Th>Day</Th>
                  <Th>Hour</Th>
                  <Th>Min</Th>
                  <Th>Origin</Th>
                  <Th>Destination</Th>
                  <Th>Protocol</Th>
                  <Th>Protocol weight</Th>
                  <Th>Traffic</Th>
                  <Th>Flags</Th>
                </tr>
              </thead>
              <tbody>
                {packets.map((packet) => {
                  const parts = splitTimestamp(packet.ts);
                  const protocol = packet.protocol ?? "UNKNOWN";
                  const protocolWeight = protocolWeights.get(protocol) ?? 0;
                  const trafficWeight = diagnostics?.total_bytes
                    ? (((packet.length ?? 0) / diagnostics.total_bytes) * 100)
                    : 0;

                  return (
                    <tr className="border-b border-white/[0.025] text-white/75 hover:bg-white/[0.045]" key={`${packet.session_id}-${packet.id}`}>
                      <Td muted>{packet.id}</Td>
                      <Td>{parts.day}</Td>
                      <Td>{parts.hour}</Td>
                      <Td>{parts.minute}</Td>
                      <Td>{formatEndpoint(packet.src_ip, packet.src_port)}</Td>
                      <Td>{formatEndpoint(packet.dst_ip, packet.dst_port)}</Td>
                      <Td>
                        <span className="rounded-full bg-blue-400/10 px-2 py-0.5 text-blue-100">{protocol}</span>
                      </Td>
                      <Td>{protocolWeight.toFixed(1)}%</Td>
                      <Td>{formatBytes(packet.length ?? 0)} / {trafficWeight.toFixed(3)}%</Td>
                      <Td>{packet.flags || "-"}</Td>
                    </tr>
                  );
                })}
                {!packets.length && (
                  <tr>
                    <td className="p-6 text-center text-xs text-secondary" colSpan={10}>
                      {loading ? "Loading packets from SQLite..." : "No packets found for this session."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between border-t border-glass p-3 text-xs text-secondary">
            <span>Page {page} / {totalPages}</span>
            <div className="flex gap-2">
              <button className="button-ghost" disabled={page <= 1 || loading} onClick={() => setPage((value) => Math.max(1, value - 1))}>
                Previous
              </button>
              <button className="button-ghost" disabled={page >= totalPages || loading} onClick={() => setPage((value) => Math.min(totalPages, value + 1))}>
                Next
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

function MetricCard({ icon: Icon, label, value }: { icon: LucideIcon; label: string; value: string }) {
  return (
    <div className="glass-surface p-3">
      <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.16em] text-muted">
        <Icon size={13} /> {label}
      </div>
      <p className="mt-2 text-lg font-semibold">{value}</p>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="glass-panel min-h-0 overflow-auto p-3">
      <h3 className="mb-3 text-[10px] uppercase tracking-[0.18em] text-muted">{title}</h3>
      {children}
    </section>
  );
}

function InfoCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-white/5 bg-white/[0.025] p-2">
      <p className="text-[10px] uppercase tracking-[0.14em] text-muted">{label}</p>
      <p className="mt-1 truncate text-primary">{value}</p>
    </div>
  );
}

function OriginList({ title, rows, max }: { title: string; rows: Array<{ ip: string; count: number }>; max: number }) {
  return (
    <div>
      <p className="mb-2 text-[10px] uppercase tracking-[0.16em] text-muted">{title}</p>
      <div className="space-y-2">
        {rows.length ? (
          rows.slice(0, 5).map((row) => (
            <div key={`${title}-${row.ip}`}>
              <div className="mb-1 flex justify-between gap-2 text-[11px]">
                <span className="truncate font-mono text-primary">{row.ip}</span>
                <span className="text-secondary">{row.count.toLocaleString()}</span>
              </div>
              <div className="h-1.5 rounded-full bg-white/5">
                <div className="h-full rounded-full bg-blue-400" style={{ width: `${(row.count / max) * 100}%` }} />
              </div>
            </div>
          ))
        ) : (
          <EmptyText text="No origin data yet." />
        )}
      </div>
    </div>
  );
}

function EmptyText({ text }: { text: string }) {
  return <p className="rounded-lg border border-white/5 bg-white/[0.025] p-3 text-xs text-secondary">{text}</p>;
}

function Th({ children }: { children: ReactNode }) {
  return <th className="whitespace-nowrap px-3 py-2 text-left font-medium">{children}</th>;
}

function Td({ children, muted = false }: { children: ReactNode; muted?: boolean }) {
  return <td className={`whitespace-nowrap px-3 py-2 ${muted ? "text-muted" : ""}`}>{children}</td>;
}

function splitTimestamp(ts: string) {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) {
    return { day: "-", hour: "-", minute: "-" };
  }
  return {
    day: date.toLocaleDateString([], { month: "2-digit", day: "2-digit" }),
    hour: date.toLocaleTimeString([], { hour: "2-digit", hour12: false }),
    minute: date.toLocaleTimeString([], { minute: "2-digit" }),
  };
}

function formatEndpoint(ip: string | null, port: number | null) {
  if (!ip) return "-";
  return port == null ? ip : `${ip}:${port}`;
}

function formatSessionDate(value: string | null) {
  if (!value) return "No date";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString([], { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function buildWindowInfo(session: Session | null, diagnostics: DiagnosticsData | null) {
  const timeline = diagnostics?.traffic_timeline ?? [];
  const start = parseDate(session?.started_at ?? diagnostics?.traffic_timeline[0]?.bucket ?? null);
  const end = parseDate(session?.ended_at ?? timeline[timeline.length - 1]?.bucket ?? null);
  const startParts = start ? splitTimestamp(start.toISOString()) : null;
  const endParts = end ? splitTimestamp(end.toISOString()) : null;

  return {
    startDay: startParts?.day ?? "-",
    endDay: endParts?.day ?? "-",
    startHour: startParts?.hour ?? "-",
    endHour: endParts?.hour ?? "-",
    startMinute: startParts?.minute ?? "-",
    endMinute: endParts?.minute ?? "-",
    duration: start && end ? formatDuration(end.getTime() - start.getTime()) : "Open",
  };
}

function parseDate(value: string | null) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatDuration(ms: number) {
  if (!Number.isFinite(ms) || ms < 0) return "Open";
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  if (hours > 0) return `${hours}h ${mins}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}
