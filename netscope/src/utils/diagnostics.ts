import type { Packet } from "@/types/packet";

export type AlertLevel = "warning" | "info" | "success";

export interface Alert {
  level: AlertLevel;
  message: string;
}

export function analyzeDiagnostics(packets: Packet[]): Alert[] {
  if (!packets.length) {
    return [{ level: "info", message: "Waiting for captured traffic to run diagnostics." }];
  }

  const alerts: Alert[] = [];
  const tcp = packets.filter((packet) => packet.protocol === "TCP" || packet.protocol === "HTTP" || packet.protocol === "HTTPS");
  const rst = tcp.filter((packet) => packet.flags.includes("RST")).length;
  const dns = packets.filter((packet) => packet.protocol === "DNS").length;
  const arp = packets.filter((packet) => packet.protocol === "ARP").length;
  const ips = new Map<string, number>();

  packets.forEach((packet) => {
    [packet.src_ip, packet.dst_ip].forEach((ip) => {
      if (ip) ips.set(ip, (ips.get(ip) ?? 0) + 1);
    });
  });

  if (tcp.length && rst / tcp.length > 0.05) {
    alerts.push({
      level: "warning",
      message: "High rejected-connection rate: review possible port scans or firewall blocks.",
    });
  }

  const dominant = [...ips.entries()].sort((a, b) => b[1] - a[1])[0];
  if (dominant && dominant[1] / (packets.length * 2) > 0.4) {
    alerts.push({
      level: "warning",
      message: `Possible abnormal traffic source: ${dominant[0]}.`,
    });
  }

  if (dns / packets.length > 0.3) {
    alerts.push({
      level: "info",
      message: "Elevated DNS traffic: review name-resolution activity.",
    });
  }

  if (arp > Math.max(30, packets.length * 0.15)) {
    alerts.push({
      level: "warning",
      message: "Excessive ARP broadcasts detected: review possible ARP flooding.",
    });
  }

  return alerts.length
    ? alerts
    : [{ level: "success", message: "Network operating within normal parameters." }];
}
