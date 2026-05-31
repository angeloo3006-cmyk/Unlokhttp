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

export function useDiagnostics(packets: Packet[]) {
  return useMemo(() => {
    const now = Date.now();
    const recent = packets.filter((packet) => now - Date.parse(packet.ts) <= 60_000);
    const lastSecond = recent.filter((packet) => now - Date.parse(packet.ts) <= 1_000);
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

    const timelineMap = new Map<number, TimelinePoint>();
    for (let offset = 59; offset >= 0; offset -= 1) {
      const second = Math.floor((now - offset * 1_000) / 1_000);
      timelineMap.set(second, {
        time: new Date(second * 1_000).toLocaleTimeString([], { minute: "2-digit", second: "2-digit" }),
        total: 0,
        TCP: 0,
        UDP: 0,
      });
    }
    recent.forEach((packet) => {
      const point = timelineMap.get(Math.floor(Date.parse(packet.ts) / 1_000));
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

    return {
      metrics: {
        pps: lastSecond.length,
        bandwidthMbps: (lastSecond.reduce((sum, packet) => sum + packet.length, 0) * 8) / 1_000_000,
        avgRtt: rtts.length ? rtts.reduce((sum, value) => sum + value, 0) / rtts.length : null,
        errorRate: tcp.length ? (rst / tcp.length) * 100 : 0,
      },
      timeline: [...timelineMap.values()],
      protocolDist: [...protocolCounts.entries()]
        .map(([protocol, value]) => ({ protocol, value }))
        .sort((a, b) => b.value - a.value),
      topIPs: [...ipMap.values()].sort((a, b) => b.packets - a.packets).slice(0, 10),
      alerts: analyzeDiagnostics(packets),
    };
  }, [packets]);
}
