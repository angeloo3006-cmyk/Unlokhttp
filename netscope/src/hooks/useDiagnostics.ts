import { useMemo } from "react";
import type { Packet, Protocol } from "@/types/packet";
import { analyzeDiagnostics } from "@/utils/diagnostics";

export interface TimelinePoint {
  time: string;
  total: number;
  TCP: number;
  UDP: number;
}

export interface TopIp {
  ip: string;
  packets: number;
  bytes: number;
  protocols: string[];
}

export interface UseDiagnosticsOptions {
  startedAt?: string | null;
  endedAt?: string | null;
}

export function useDiagnostics(packets: Packet[], options: UseDiagnosticsOptions = {}) {
  return useMemo(() => {
    const packetTimes = packets
      .map((packet) => Date.parse(packet.ts))
      .filter((value) => Number.isFinite(value));
    const firstPacketMs = packetTimes.length ? Math.min(...packetTimes) : Date.now();
    const lastPacketMs = packetTimes.length ? Math.max(...packetTimes) : firstPacketMs;
    const startMs = parseDateMs(options.startedAt) ?? firstPacketMs;
    const endMs = parseDateMs(options.endedAt) ?? lastPacketMs;
    const durationMs = Math.max(1_000, endMs - startMs);
    const durationSeconds = durationMs / 1_000;
    const tcp = packets.filter((packet) => ["TCP", "HTTP", "HTTPS"].includes(packet.protocol));
    const rst = tcp.filter((packet) => packet.flags.includes("RST")).length;
    const syns = new Map<string, number>();
    const rtts: number[] = [];

    packets.forEach((packet) => {
      const key = `${packet.src_ip}:${packet.src_port}>${packet.dst_ip}:${packet.dst_port}`;
      const reverse = `${packet.dst_ip}:${packet.dst_port}>${packet.src_ip}:${packet.src_port}`;
      if (packet.flags === "SYN") syns.set(key, Date.parse(packet.ts));
      if (packet.flags === "SYN-ACK" && syns.has(reverse)) {
        rtts.push(Date.parse(packet.ts) - (syns.get(reverse) ?? Date.parse(packet.ts)));
      }
    });

    const bucketCount = packets.length ? Math.min(60, Math.max(1, Math.ceil(durationSeconds))) : 60;
    const bucketSizeMs = Math.max(1_000, Math.ceil(durationMs / bucketCount));
    const timeline: TimelinePoint[] = Array.from({ length: bucketCount }, (_, index) => {
      const bucketStart = startMs + index * bucketSizeMs;
      return {
        time: new Date(bucketStart).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        total: 0,
        TCP: 0,
        UDP: 0,
      };
    });

    packets.forEach((packet) => {
      const packetMs = Date.parse(packet.ts);
      if (!Number.isFinite(packetMs)) return;
      const bucketIndex = Math.min(timeline.length - 1, Math.max(0, Math.floor((packetMs - startMs) / bucketSizeMs)));
      const point = timeline[bucketIndex];
      if (!point) return;
      point.total += 1;
      if (["TCP", "HTTP", "HTTPS"].includes(packet.protocol)) point.TCP += 1;
      if (packet.protocol === "UDP" || packet.protocol === "DNS") point.UDP += 1;
    });

    const protocolCounts = new Map<Protocol, number>();
    const ipMap = new Map<string, TopIp>();
    packets.forEach((packet) => {
      protocolCounts.set(packet.protocol, (protocolCounts.get(packet.protocol) ?? 0) + 1);
      [packet.src_ip, packet.dst_ip].forEach((ip) => {
        if (!ip) return;
        const item = ipMap.get(ip) ?? { ip, packets: 0, bytes: 0, protocols: [] };
        item.packets += 1;
        item.bytes += packet.length;
        if (!item.protocols.includes(packet.protocol)) item.protocols.push(packet.protocol);
        ipMap.set(ip, item);
      });
    });

    const totalBytes = packets.reduce((sum, packet) => sum + packet.length, 0);

    return {
      metrics: {
        pps: packets.length / durationSeconds,
        bandwidthMbps: (totalBytes * 8) / durationSeconds / 1_000_000,
        avgRtt: rtts.length ? rtts.reduce((sum, value) => sum + value, 0) / rtts.length : null,
        errorRate: tcp.length ? (rst / tcp.length) * 100 : 0,
      },
      timeline,
      protocolDist: [...protocolCounts.entries()]
        .map(([protocol, value]) => ({ protocol, value }))
        .sort((a, b) => b.value - a.value),
      topIPs: [...ipMap.values()].sort((a, b) => b.packets - a.packets).slice(0, 10),
      alerts: analyzeDiagnostics(packets),
    };
  }, [options.endedAt, options.startedAt, packets]);
}

function parseDateMs(value?: string | null) {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}
