import { useRef, useEffect, useState, useMemo } from "react";
import { useAppState } from "@/store";
import type { Packet } from "@/lib/tauri";
import { ProtocolBadge } from "@/components/ui/ProtocolBadge";
import { PacketDetailPanel } from "@/components/packets/PacketDetailPanel";
import { cn } from "@/lib/utils";
import { ArrowDown } from "lucide-react";

const ROW_HEIGHT = 26; // px
const OVERSCAN   = 20;

function formatTime(ts: string): string {
  return ts.slice(11, 23); // HH:MM:SS.mmm
}

export function LivePacketFeed() {
  const { state, dispatch } = useAppState();
  const { livePackets, selectedPacket, searchFilter } = state;

  const [autoScroll, setAutoScroll]   = useState(true);
  const [scrollTop,  setScrollTop]    = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [containerHeight, setContainerHeight] = useState(400);

  // Filter packets by search
  const filtered = useMemo(() => {
    if (!searchFilter) return livePackets;
    const q = searchFilter.toLowerCase();
    return livePackets.filter(
      (p) =>
        p.src_ip?.includes(q) ||
        p.dst_ip?.includes(q) ||
        p.protocol.toLowerCase().includes(q) ||
        String(p.src_port).includes(q) ||
        String(p.dst_port).includes(q)
    );
  }, [livePackets, searchFilter]);

  // Measure container
  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver(([e]) => {
      setContainerHeight(e.contentRect.height);
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  // Auto-scroll to bottom
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [filtered.length, autoScroll]);

  const totalHeight   = filtered.length * ROW_HEIGHT;
  const visibleCount  = Math.ceil(containerHeight / ROW_HEIGHT) + OVERSCAN;
  const startIdx      = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const endIdx        = Math.min(filtered.length, startIdx + visibleCount);
  const visibleRows   = filtered.slice(startIdx, endIdx);
  const topPad        = startIdx * ROW_HEIGHT;

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget;
    setScrollTop(el.scrollTop);
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    setAutoScroll(atBottom);
  };

  const selectPacket = (pkt: Packet) => {
    dispatch({
      type: "SELECT_PACKET",
      payload: selectedPacket?.id === pkt.id ? null : pkt,
    });
  };

  return (
    <div className="flex flex-1 overflow-hidden">
      {/* ── Packet table ─────────────────────────────────────────────── */}
      <div className="flex flex-col flex-1 overflow-hidden">
        {/* Search bar */}
        <div className="flex items-center gap-2 px-3 py-1.5 border-b border-dim bg-surface shrink-0">
          <input
            className="input flex-1 bg-transparent border-transparent focus:border-dim py-0.5"
            placeholder="Filter: IP, port, protocol…"
            value={searchFilter}
            onChange={(e) => dispatch({ type: "SET_SEARCH", payload: e.target.value })}
          />
          <span className="text-[10px] text-subtle font-mono shrink-0">
            {filtered.length.toLocaleString()} / {livePackets.length.toLocaleString()}
          </span>
        </div>

        {/* Header */}
        <div className="shrink-0">
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 60 }}>#</th>
                <th style={{ width: 100 }}>Time</th>
                <th style={{ width: 72 }}>Proto</th>
                <th>Source</th>
                <th>Destination</th>
                <th style={{ width: 56 }}>Len</th>
                <th style={{ width: 70 }}>TTL</th>
                <th style={{ width: 72 }}>Flags</th>
              </tr>
            </thead>
          </table>
        </div>

        {/* Virtualised body */}
        <div
          ref={(el) => {
            // @ts-ignore
            scrollRef.current = el;
            // @ts-ignore
            containerRef.current = el;
          }}
          className="flex-1 overflow-auto"
          onScroll={handleScroll}
        >
          <div style={{ height: totalHeight, position: "relative" }}>
            <table
              className="data-table absolute left-0 right-0"
              style={{ top: topPad }}
            >
              <tbody>
                {visibleRows.map((pkt) => (
                  <PacketRow
                    key={pkt.id}
                    pkt={pkt}
                    selected={selectedPacket?.id === pkt.id}
                    onClick={() => selectPacket(pkt)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Auto-scroll button */}
        {!autoScroll && state.isCapturing && (
          <button
            onClick={() => {
              setAutoScroll(true);
              if (scrollRef.current) {
                scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
              }
            }}
            className="absolute bottom-4 right-4 btn-accent gap-1 shadow-lg z-20 animate-fadein"
          >
            <ArrowDown size={11} />
            Live
          </button>
        )}
      </div>

      {/* ── Detail panel (side drawer) ────────────────────────────────── */}
      {selectedPacket && (
        <PacketDetailPanel
          packet={selectedPacket}
          onClose={() => dispatch({ type: "SELECT_PACKET", payload: null })}
        />
      )}
    </div>
  );
}

// ── Single packet row ─────────────────────────────────────────────────────────

function PacketRow({
  pkt, selected, onClick,
}: {
  pkt:      Packet;
  selected: boolean;
  onClick:  () => void;
}) {
  const src = pkt.src_ip
    ? `${pkt.src_ip}${pkt.src_port ? `:${pkt.src_port}` : ""}`
    : "—";
  const dst = pkt.dst_ip
    ? `${pkt.dst_ip}${pkt.dst_port ? `:${pkt.dst_port}` : ""}`
    : "—";

  return (
    <tr
      onClick={onClick}
      className={cn("cursor-pointer", selected && "selected")}
    >
      <td className="text-subtle">{pkt.id}</td>
      <td className="text-subtle tabular-nums">{formatTime(pkt.ts)}</td>
      <td><ProtocolBadge protocol={pkt.protocol} /></td>
      <td className="tabular-nums font-mono">{src}</td>
      <td className="tabular-nums font-mono">{dst}</td>
      <td className="tabular-nums text-subtle">{pkt.length}</td>
      <td className="tabular-nums text-subtle">{pkt.ttl ?? "—"}</td>
      <td>
        {pkt.flags ? (
          <span className="badge proto-TCP text-[9px]">{pkt.flags}</span>
        ) : "—"}
      </td>
    </tr>
  );
}
