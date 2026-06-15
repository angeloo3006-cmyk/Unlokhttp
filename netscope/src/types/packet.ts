export type Protocol =
  | "TCP"
  | "UDP"
  | "ICMP"
  | "ARP"
  | "DNS"
  | "HTTP"
  | "HTTPS"
  | "OTHER";

export interface Packet {
  id: number;
  ts: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: Protocol;
  length: number;
  ttl: number | null;
  flags: string;
  link_layer: string | null;
  src_mac: string | null;
  dst_mac: string | null;
  src_vendor: string | null;
  dst_vendor: string | null;
  payload_hex: string;
  raw_ascii: string;
}

export interface CaptureStats {
  pps: number;
  total: number;
  dropped: number;
}
