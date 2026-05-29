import { useState, useEffect, useCallback } from "react";
import { Search, ChevronLeft, ChevronRight, Download } from "lucide-react";
import { queryPackets, exportPacketsJson } from "@/lib/tauri";
import type { PacketRow, PacketFilters, PaginatedResult } from "@/lib/tauri";
import { useAppState } from "@/store";
import { ProtocolBadge } from "@/components/ui/ProtocolBadge";
import { Spinner } from "@/components/ui/Spinner";
import { PacketDetailPanel } from "./PacketDetailPanel";
import type { Packet } from "@/lib/tauri";

const PAGE_SIZE = 100;
const PROTOCOLS = ["", "TCP", "UDP", "HTTP", "HTTPS", "DNS", "ICMP", "ARP", "OTHER"];

// Convert DB PacketRow → live Packet for the detail panel
function toPacket(row: PacketRow): Packet {
  return {
    id:          row.id,
    ts:          row.ts,
    src_ip:      row.src_ip,
    dst_ip:      row.dst_ip,
    src_port:    row.src_port ?? undefined,
    dst_port:    row.dst_port ?? undefined,
    protocol:    (row.protocol ?? "OTHER") as Packet["protocol"],
    length:      row.length ?? 0,
    ttl:         row.ttl ?? undefined,
    flags:       (row.flags ?? "") as Packet["flags"],
    payload_hex: row.payload_hex ?? "",
    raw_ascii:   row.raw_ascii ?? "",
  };
}

export function PacketsView() {
  const { state } = useAppState();
  const sessions  = state.sessions;

  const [sessionId,  setSessionId]  = useState<number | null>(null);
  const [filters,    setFilters]    = useState<PacketFilters>({});
  const [page,       setPage]       = useState(1);
  const [result,     setResult]     = useState<PaginatedResult<PacketRow> | null>(null);
  const [loading,    setLoading]    = useState(false);
  const [selected,   setSelected]   = useState<Packet | null>(null);
  const [searchText, setSearchText] = useState("");

  // Auto-select most recent session
  useEffect(() => {
    if (sessions.length > 0 && !sessionId) {
      setSessionId(sessions[0].id);
    }
  }, [sessions, sessionId]);

  const load = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    try {
      const r = await queryPackets({
        sessionId,
        filters: { ...filters, search: searchText || undefined },
        page,
        pageSize: PAGE_SIZE,
      });
      setResult(r);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [sessionId, filters, page, searchText]);

  useEffect(() => { load(); }, [load]);

  const handleExport = async () => {
    if (!sessionId) return;
    const json = await exportPacketsJson(sessionId, filters);
    const blob = new Blob([json], { type: "application/json" });
    const a    = document.createElement("a");
    a.href     = URL.createObjectURL(blob);
    a.download = `netscope-session-${sessionId}.json`;
    a.click();
  };

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* ── Toolbar ─────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-dim bg-surface shrink-0 flex-wrap">

        {/* Session picker */}
        <select
          className="input w-48"
          value={sessionId ?? ""}
          onChange={(e) => { setSessionId(Number(e.target.value)); setPage(1); }}
        >
          <option value="">— Select session —</option>
          {sessions.map((s) => (
            <option key={s.id} value={s.id}>
              #{s.id} {s.name ?? "Unnamed"} ({s.total_packets} pkts)
            </option>
          ))}
        </select>

        <div className="h-4 w-px bg-border-dim" />

        {/* Protocol filter */}
        <select
          className="input w-28"
          value={filters.protocol ?? ""}
          onChange={(e) => {
            setFilters((f) => ({ ...f, protocol: e.target.value || undefined }));
            setPage(1);
          }}
        >
          {PROTOCOLS.map((p) => (
            <option key={p} value={p}>{p || "All protocols"}</option>
          ))}
        </select>

        {/* Search */}
        <div className="relative flex-1 min-w-[160px]">
          <Search size={11} className="absolute left-2 top-1/2 -translate-y-1/2 text-subtle" />
          <input
            className="input pl-7 w-full"
            placeholder="IP / port search…"
            value={searchText}
            onChange={(e) => { setSearchText(e.target.value); setPage(1); }}
          />
        </div>

        <div className="flex-1" />

        <button onClick={handleExport} className="btn-outline gap-1" disabled={!sessionId}>
          <Download size={11} />
          Export
        </button>
      </div>

      {/* ── Body ─────────────────────────────────────────────────────────── */}
      <div className="flex flex-1 overflow-hidden">
        <div className="flex flex-col flex-1 overflow-hidden">
          {/* Table header */}
          <div className="shrink-0">
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 60 }}>#ID</th>
                  <th style={{ width: 140 }}>Timestamp</th>
                  <th style={{ width: 72 }}>Proto</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th style={{ width: 64 }}>Bytes</th>
                  <th style={{ width: 48 }}>TTL</th>
                  <th style={{ width: 72 }}>Flags</th>
                </tr>
              </thead>
            </table>
          </div>

          {/* Rows */}
          <div className="flex-1 overflow-auto relative">
            {loading && (
              <div className="absolute inset-0 flex items-center justify-center bg-surface/70 z-10">
                <Spinner />
              </div>
            )}
            <table className="data-table">
              <tbody>
                {result?.items.map((row) => (
                  <tr
                    key={row.id}
                    onClick={() => setSelected((prev) =>
                      prev?.id === row.id ? null : toPacket(row)
                    )}
                    className={`cursor-pointer ${selected?.id === row.id ? "selected" : ""}`}
                  >
                    <td className="text-subtle tabular-nums">{row.id}</td>
                    <td className="text-subtle tabular-nums text-[10px]">{row.ts}</td>
                    <td><ProtocolBadge protocol={row.protocol ?? "OTHER"} /></td>
                    <td className="font-mono tabular-nums">
                      {row.src_ip ?? "—"}
                      {row.src_port ? `:${row.src_port}` : ""}
                    </td>
                    <td className="font-mono tabular-nums">
                      {row.dst_ip ?? "—"}
                      {row.dst_port ? `:${row.dst_port}` : ""}
                    </td>
                    <td className="tabular-nums text-subtle">{row.length ?? "—"}</td>
                    <td className="tabular-nums text-subtle">{row.ttl ?? "—"}</td>
                    <td>
                      {row.flags
                        ? <span className="badge proto-TCP text-[9px]">{row.flags}</span>
                        : "—"}
                    </td>
                  </tr>
                ))}
                {!loading && !result?.items.length && (
                  <tr>
                    <td colSpan={8} className="text-center text-subtle py-8">
                      {sessionId ? "No packets match the current filters." : "Select a session to browse packets."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {result && result.total_pages > 1 && (
            <div className="flex items-center justify-between px-4 py-1.5 border-t border-dim shrink-0 text-[10px] font-mono text-subtle">
              <span>
                {result.total.toLocaleString()} results — page {result.page} / {result.total_pages}
              </span>
              <div className="flex gap-1">
                <button
                  className="btn-ghost py-0.5 px-1.5 disabled:opacity-30"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  <ChevronLeft size={12} />
                </button>
                <button
                  className="btn-ghost py-0.5 px-1.5 disabled:opacity-30"
                  disabled={page >= result.total_pages}
                  onClick={() => setPage((p) => Math.min(result.total_pages, p + 1))}
                >
                  <ChevronRight size={12} />
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Detail panel */}
        {selected && (
          <PacketDetailPanel packet={selected} onClose={() => setSelected(null)} />
        )}
      </div>
    </div>
  );
}
