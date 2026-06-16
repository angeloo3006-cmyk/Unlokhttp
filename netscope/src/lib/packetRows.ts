import type { Packet, Protocol } from "@/types/packet";
import type { PacketRow } from "@/lib/tauri";

export function packetRowToPacket(row: PacketRow): Packet {
  return {
    id: row.id,
    ts: row.ts,
    src_ip: row.src_ip,
    dst_ip: row.dst_ip,
    src_port: row.src_port,
    dst_port: row.dst_port,
    protocol: toProtocol(row.protocol),
    length: row.length ?? 0,
    ttl: row.ttl,
    flags: row.flags ?? "",
    link_layer: row.link_layer,
    src_mac: row.src_mac,
    dst_mac: row.dst_mac,
    src_vendor: row.src_vendor,
    dst_vendor: row.dst_vendor,
    payload_hex: row.payload_hex ?? "",
    raw_ascii: row.raw_ascii ?? "",
  };
}

export function toProtocol(value: string | null): Protocol {
  const protocols: Protocol[] = ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "OTHER"];
  return protocols.includes(value as Protocol) ? (value as Protocol) : "OTHER";
}
