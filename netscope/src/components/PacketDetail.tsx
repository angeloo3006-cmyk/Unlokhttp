import { useMemo, useState, type ReactNode } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { Packet } from "@/types/packet";

interface PacketDetailProps {
  selectedPacket: Packet | null;
  packets?: Packet[];
}

export function PacketDetail({ selectedPacket, packets = [] }: PacketDetailProps) {
  const context = useMemo(() => buildPacketContext(selectedPacket, packets), [selectedPacket, packets]);

  if (!selectedPacket) return <Empty text="Select a packet to inspect" />;
  const packet = selectedPacket;
  const time = splitTimestamp(packet.ts);

  return (
    <section className="h-full overflow-auto p-2 text-[11px]">
      <TreeSection title="Packet row data">
        <Field label="Packet id" value={packet.id} />
        <Field label="Table time" value={time.localTimeMs} />
        <Field label="Day" value={time.localDay} />
        <Field label="Hour" value={time.localHour} />
        <Field label="Minute" value={time.localMinute} />
        <Field label="Source" value={formatEndpoint(packet.src_ip, packet.src_port)} />
        <Field label="Destination" value={formatEndpoint(packet.dst_ip, packet.dst_port)} />
        <Field label="Link layer" value={packet.link_layer ?? "-"} />
        <Field label="Source MAC" value={packet.src_mac ?? "-"} />
        <Field label="Destination MAC" value={packet.dst_mac ?? "-"} />
        <Field label="Protocol" value={packet.protocol} />
        <Field label="Protocol weight" value={context.protocolWeight} />
        <Field label="Length / frame length" value={`${packet.length} bytes`} />
        <Field label="Traffic weight" value={context.trafficWeight} />
        <Field label="Flags" value={packet.flags || "-"} />
        <Field label="Info" value={packetInfo(packet)} />
      </TreeSection>

      <TreeSection title={`Frame - ${packet.length} bytes captured`}>
        <Field label="Arrival time local" value={time.localFull} bytes={[0, 5]} />
        <Field label="Arrival time UTC" value={packet.ts} bytes={[0, 5]} />
        <Field label="Frame length" value={`${packet.length} bytes`} bytes={[0, 1]} />
        <Field label="Captured length" value={`${packet.length} bytes`} />
        <Field label="Visible packet index" value={context.visibleIndex} />
      </TreeSection>

      <TreeSection title={packet.link_layer === "Ethernet" ? "Ethernet II" : "Link Layer"}>
        <Field label="Link type" value={packet.link_layer ?? "Unknown"} />
        <Field label="Src MAC" value={packet.src_mac ?? "-"} bytes={[6, 11]} />
        <Field label="Src vendor" value={packet.src_vendor ?? "Unknown"} />
        <Field label="Dst MAC" value={packet.dst_mac ?? "-"} bytes={[0, 5]} />
        <Field label="Dst vendor" value={packet.dst_vendor ?? "Unknown"} />
        <Field label="Type" value={packet.protocol === "ARP" ? "0x0806 (ARP)" : "0x0800 (IPv4)"} bytes={[12, 13]} />
      </TreeSection>

      <TreeSection title="Internet Protocol">
        <Field label="Source IP" value={packet.src_ip ?? "-"} bytes={[26, 29]} />
        <Field label="Destination IP" value={packet.dst_ip ?? "-"} bytes={[30, 33]} />
        <Field label="TTL" value={packet.ttl ?? "-"} bytes={[22, 22]} />
        <Field label="Protocol number" value={protocolNumber(packet.protocol)} bytes={[23, 23]} />
      </TreeSection>

      {["TCP", "HTTP", "HTTPS"].includes(packet.protocol) && (
        <TreeSection title="Transmission Control Protocol">
          <Field label="Source port" value={packet.src_port ?? "-"} bytes={[34, 35]} />
          <Field label="Destination port" value={packet.dst_port ?? "-"} bytes={[36, 37]} />
          <Field label="Flags" value={packet.flags || "-"} bytes={[47, 47]} />
          <Field label="Connection role" value={tcpRole(packet.flags)} />
        </TreeSection>
      )}

      {["UDP", "DNS"].includes(packet.protocol) && (
        <TreeSection title="User Datagram Protocol">
          <Field label="Source port" value={packet.src_port ?? "-"} bytes={[34, 35]} />
          <Field label="Destination port" value={packet.dst_port ?? "-"} bytes={[36, 37]} />
          <Field label="UDP payload preview" value={packet.raw_ascii || "-"} />
        </TreeSection>
      )}

      <TreeSection title="Payload preview">
        <Field label="Payload hex bytes shown" value={`${Math.floor(packet.payload_hex.length / 2)} bytes`} />
        <Field label="Payload hex" value={packet.payload_hex || "-"} />
        <Field label="Raw ASCII" value={packet.raw_ascii || "-"} />
      </TreeSection>
    </section>
  );
}

function TreeSection({ title, children }: { title: string; children: ReactNode }) {
  const [expanded, setExpanded] = useState(true);
  return (
    <div className="mb-1">
      <button
        className="flex w-full items-center gap-1 rounded px-1 py-1 text-left text-secondary hover:bg-white/5 hover:text-white"
        onClick={() => setExpanded((value) => !value)}
      >
        {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        {title}
      </button>
      {expanded && <div className="ml-5 border-l border-white/5 pl-2">{children}</div>}
    </div>
  );
}

function Field({ label, value, bytes }: { label: string; value: string | number; bytes?: [number, number] }) {
  return (
    <button
      className="block w-full rounded px-1 py-0.5 text-left font-mono hover:bg-blue-400/10"
      onClick={() => {
        if (bytes) window.dispatchEvent(new CustomEvent("netscope-highlight-bytes", { detail: bytes }));
      }}
    >
      <span className="text-muted">{label}: </span>
      <span className="break-all text-primary">{value}</span>
    </button>
  );
}

function buildPacketContext(packet: Packet | null, packets: Packet[]) {
  if (!packet) {
    return {
      protocolWeight: "-",
      trafficWeight: "-",
      visibleIndex: "-",
    };
  }

  const captureIndex = packets.findIndex((item) => item.id === packet.id);
  const packetSet = packets.length ? packets : [packet];
  const totalPackets = packetSet.length;
  const totalBytes = packetSet.reduce((sum, item) => sum + item.length, 0);
  const protocolCount = packetSet.filter((item) => item.protocol === packet.protocol).length;
  const protocolWeight = `${((protocolCount / totalPackets) * 100).toFixed(1)}% of captured packets`;
  const trafficWeight =
    totalBytes > 0
      ? `${formatBytes(packet.length)} / ${((packet.length / totalBytes) * 100).toFixed(3)}% of captured bytes`
      : `${formatBytes(packet.length)} / 0.000% of captured bytes`;

  return {
    protocolWeight,
    trafficWeight,
    visibleIndex: captureIndex >= 0 ? `${captureIndex + 1} of ${packets.length}` : "Not in current capture buffer",
  };
}

function splitTimestamp(ts: string) {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) {
    return {
      localTimeMs: "-",
      localFull: ts,
      localDay: "-",
      localHour: "-",
      localMinute: "-",
    };
  }

  return {
    localTimeMs: date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }) + `.${String(date.getMilliseconds()).padStart(3, "0")}`,
    localFull: date.toLocaleString(),
    localDay: date.toLocaleDateString([], { year: "numeric", month: "2-digit", day: "2-digit" }),
    localHour: date.toLocaleTimeString([], { hour: "2-digit", hour12: false }),
    localMinute: date.toLocaleTimeString([], { minute: "2-digit" }),
  };
}

function formatEndpoint(ip: string | null, port: number | null) {
  if (!ip) return "-";
  return port == null ? ip : `${ip}:${port}`;
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

function packetInfo(packet: Packet) {
  if (packet.protocol === "DNS") return "Domain name system";
  if (packet.protocol === "HTTP") return "HTTP request / response";
  if (packet.protocol === "HTTPS") return "TLS encrypted traffic";
  return packet.flags || `${packet.length} bytes`;
}

function protocolNumber(protocol: Packet["protocol"]) {
  if (["TCP", "HTTP", "HTTPS"].includes(protocol)) return "6 (TCP)";
  if (["UDP", "DNS"].includes(protocol)) return "17 (UDP)";
  if (protocol === "ICMP") return "1 (ICMP)";
  if (protocol === "ARP") return "ARP (EtherType 0x0806)";
  return protocol;
}

function tcpRole(flags: string) {
  if (flags === "SYN") return "Connection request";
  if (flags === "SYN-ACK") return "Connection accepted response";
  if (flags.includes("RST")) return "Connection reset or rejected";
  if (flags.includes("FIN")) return "Graceful close";
  if (flags.includes("ACK")) return "Acknowledgement";
  if (flags.includes("PSH")) return "Push data";
  return "No TCP control flag decoded";
}

function Empty({ text }: { text: string }) {
  return <div className="flex h-full items-center justify-center text-xs text-muted">{text}</div>;
}
