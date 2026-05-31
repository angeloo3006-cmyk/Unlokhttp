import { useState, type ReactNode } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { Packet } from "@/types/packet";

export function PacketDetail({ selectedPacket }: { selectedPacket: Packet | null }) {
  if (!selectedPacket) return <Empty text="Select a packet to inspect" />;
  const packet = selectedPacket;

  return (
    <section className="h-full overflow-auto p-2 text-[11px]">
      <TreeSection title={`Frame · ${packet.length} bytes captured`}>
        <Field label="Arrival time" value={new Date(packet.ts).toLocaleString()} bytes={[0, 5]} />
        <Field label="Frame length" value={`${packet.length} bytes`} bytes={[0, 1]} />
      </TreeSection>
      <TreeSection title="Ethernet II">
        <Field label="Src" value="00:1A:2B:3C:4D:5E" bytes={[6, 11]} />
        <Field label="Dst" value="FF:FF:FF:FF:FF:FF" bytes={[0, 5]} />
        <Field label="Type" value="0x0800 (IPv4)" bytes={[12, 13]} />
      </TreeSection>
      <TreeSection title="Internet Protocol (IPv4)">
        <Field label="Source" value={packet.src_ip ?? "—"} bytes={[26, 29]} />
        <Field label="Destination" value={packet.dst_ip ?? "—"} bytes={[30, 33]} />
        <Field label="TTL" value={packet.ttl ?? "—"} bytes={[22, 22]} />
        <Field label="Protocol" value={protocolNumber(packet.protocol)} bytes={[23, 23]} />
      </TreeSection>
      {["TCP", "HTTP", "HTTPS"].includes(packet.protocol) && (
        <TreeSection title="Transmission Control Protocol">
          <Field label="Source port" value={packet.src_port ?? "—"} bytes={[34, 35]} />
          <Field label="Destination port" value={packet.dst_port ?? "—"} bytes={[36, 37]} />
          <Field label="Flags" value={packet.flags || "—"} bytes={[47, 47]} />
        </TreeSection>
      )}
    </section>
  );
}

function TreeSection({ title, children }: { title: string; children: ReactNode }) {
  const [expanded, setExpanded] = useState(true);
  return (
    <div className="mb-1">
      <button className="flex w-full items-center gap-1 rounded px-1 py-1 text-left text-secondary hover:bg-white/5 hover:text-white" onClick={() => setExpanded((value) => !value)}>
        {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        {title}
      </button>
      {expanded && <div className="ml-5 border-l border-white/5 pl-2">{children}</div>}
    </div>
  );
}

function Field({ label, value, bytes }: { label: string; value: string | number; bytes: [number, number] }) {
  return (
    <button
      className="block w-full rounded px-1 py-0.5 text-left font-mono hover:bg-blue-400/10"
      onClick={() => window.dispatchEvent(new CustomEvent("netscope-highlight-bytes", { detail: bytes }))}
    >
      <span className="text-muted">{label}: </span><span className="text-primary">{value}</span>
    </button>
  );
}

function protocolNumber(protocol: Packet["protocol"]) {
  if (["TCP", "HTTP", "HTTPS"].includes(protocol)) return "6 (TCP)";
  if (["UDP", "DNS"].includes(protocol)) return "17 (UDP)";
  if (protocol === "ICMP") return "1 (ICMP)";
  return protocol;
}

function Empty({ text }: { text: string }) {
  return <div className="flex h-full items-center justify-center text-xs text-muted">{text}</div>;
}
