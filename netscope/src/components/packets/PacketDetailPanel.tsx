import { X } from "lucide-react";
import type { Packet } from "@/lib/tauri";
import { ProtocolBadge } from "@/components/ui/ProtocolBadge";

interface Props {
  packet:  Packet;
  onClose: () => void;
}

export function PacketDetailPanel({ packet: pkt, onClose }: Props) {
  const fields: [string, string | number | null | undefined][] = [
    ["ID",          pkt.id],
    ["Timestamp",   pkt.ts],
    ["Protocol",    null],   // rendered separately
    ["Source IP",   pkt.src_ip],
    ["Source Port", pkt.src_port],
    ["Dest IP",     pkt.dst_ip],
    ["Dest Port",   pkt.dst_port],
    ["Length",      pkt.length ? `${pkt.length} bytes` : null],
    ["TTL",         pkt.ttl],
    ["TCP Flags",   pkt.flags || null],
  ];

  // Format hex dump with 16-byte rows
  const hexRows: string[] = [];
  const hex = pkt.payload_hex;
  for (let i = 0; i < hex.length; i += 32) {
    const row = hex.slice(i, i + 32);
    const pairs = row.match(/.{1,2}/g) ?? [];
    const offset = (i / 2).toString(16).padStart(4, "0");
    const ascii = pairs
      .map((h) => {
        const c = parseInt(h, 16);
        return c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : ".";
      })
      .join("");
    hexRows.push(`${offset}  ${pairs.join(" ").padEnd(47)}  ${ascii}`);
  }

  return (
    <div className="flex flex-col w-80 border-l border-dim bg-surface shrink-0 overflow-hidden animate-slidein">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-dim shrink-0">
        <span className="section-title">Packet #{pkt.id}</span>
        <button onClick={onClose} className="text-subtle hover:text-foreground transition-colors">
          <X size={12} />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto">
        {/* Fields */}
        <div className="p-3 space-y-2">
          {fields.map(([label, value]) => {
            if (label === "Protocol") {
              return (
                <div key={label} className="flex items-center justify-between">
                  <span className="text-subtle text-[10px] font-mono uppercase">{label}</span>
                  <ProtocolBadge protocol={pkt.protocol} />
                </div>
              );
            }
            if (value == null || value === "") return null;
            return (
              <div key={label} className="flex items-start justify-between gap-2">
                <span className="text-subtle text-[10px] font-mono uppercase shrink-0">{label}</span>
                <span className="text-foreground text-[11px] font-mono text-right break-all">{value}</span>
              </div>
            );
          })}
        </div>

        {/* Hex dump */}
        {hexRows.length > 0 && (
          <div className="border-t border-dim">
            <div className="px-3 pt-2 pb-1">
              <span className="section-title">Payload ({hex.length / 2} bytes)</span>
            </div>
            <pre className="px-3 pb-3 text-[10px] font-mono text-subtle leading-[1.6] overflow-x-auto whitespace-pre">
              {hexRows.join("\n")}
            </pre>
          </div>
        )}

        {/* ASCII */}
        {pkt.raw_ascii && (
          <div className="border-t border-dim px-3 py-2">
            <span className="section-title block mb-1">ASCII</span>
            <pre className="text-[10px] font-mono text-muted-foreground leading-relaxed whitespace-pre-wrap break-all">
              {pkt.raw_ascii}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
