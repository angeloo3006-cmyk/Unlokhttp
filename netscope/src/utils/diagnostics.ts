import type { Packet } from "@/types/packet";

export type AlertLevel = "critical" | "warning" | "info" | "success";

export type DiagnosticType =
  | "active_reconnaissance"
  | "port_scan"
  | "tcp_reset_activity"
  | "dns_high"
  | "arp_suspicious"
  | "host_dominant"
  | "heavy_traffic"
  | "normal";

export interface Alert {
  id: string;
  type: DiagnosticType;
  level: AlertLevel;
  title: string;
  message: string;
  confidence: number;
  evidence: string[];
  recommendation: string;
  affected_ips: string[];
  affected_macs: string[];
  metrics: Record<string, number>;
}

interface CaptureBaseline {
  totalPackets: number;
  totalBytes: number;
  captureDurationSec: number;
  avgPacketsPerSec: number;
  tcpPackets: number;
  udpPackets: number;
  visibleHosts: number;
  isSmallCapture: boolean;
  timeReliable: boolean;
  sampleMultiplier: number;
}

interface HostStats {
  id: string;
  packets: number;
  bytes: number;
  protocols: Set<string>;
  ports: Set<number>;
  windows: Set<number>;
}

interface ScoredHost {
  host: HostStats;
  packetShare: number;
  byteShare: number;
  avgPacketBytes: number;
  likelyGateway: boolean;
  gatewayPenalty: number;
}

const TCP_PROTOCOLS = new Set(["TCP", "HTTP", "HTTPS"]);
const DNS_PORTS = new Set([53]);
const TRUSTED_HOSTS = new Set<string>();

export function analyzeDiagnostics(packets: Packet[]): Alert[] {
  if (!packets.length) {
    return [{
      id: "waiting-for-traffic",
      type: "normal",
      level: "info",
      title: "Waiting for traffic",
      message: "Waiting for captured traffic to run diagnostics.",
      confidence: 1,
      evidence: ["No packets are currently available for this session."],
      recommendation: "Start a capture or select a saved session with packets.",
      affected_ips: [],
      affected_macs: [],
      metrics: {},
    }];
  }

  const baseline = computeBaseline(packets);
  const gatewaySet = detectLikelyGateways(packets, baseline);
  const alerts = rankAlerts(correlateAlerts(deduplicateAlerts([
    ...analyzePortScan(packets, baseline),
    ...analyzeTcpResetActivity(packets, baseline),
    ...analyzeDnsBehavior(packets, baseline),
    ...analyzeArpBehavior(packets, baseline),
    ...analyzeDominantHosts(packets, baseline, gatewaySet),
    ...analyzeHeavyTraffic(packets, baseline, gatewaySet),
  ])));

  return alerts.length
    ? alerts
    : [{
      id: "normal-network",
      type: "normal",
      level: "success",
      title: "Network looks normal",
      message: "Network operating within normal parameters for the current capture.",
      confidence: baseline.isSmallCapture ? 0.58 : 0.78,
      evidence: [
        "No non-gateway host crossed the configured diagnostic thresholds.",
        "TCP reset, DNS volume, ARP volume, and heavy-traffic patterns stayed below warning levels.",
        baseline.isSmallCapture
          ? "The sample is small, so the normal result should be treated as preliminary."
          : "The sample size is sufficient for the current lightweight heuristics.",
      ],
      recommendation: "Use a longer capture window if you need a stronger baseline.",
      affected_ips: [...gatewaySet],
      affected_macs: [],
      metrics: {
        packet_count: baseline.totalPackets,
        duration_seconds: baseline.captureDurationSec,
        avg_pps: baseline.avgPacketsPerSec,
        sample_multiplier: baseline.sampleMultiplier,
      },
    }];
}

function analyzePortScan(packets: Packet[], baseline: CaptureBaseline): Alert[] {
  if (baseline.tcpPackets < 6) return [];

  const tcpPackets = packets.filter(isTcpLike);
  const allSynRows = tcpPackets.filter((packet) => hasFlag(packet, "SYN"));
  const bySource = new Map<string, Packet[]>();
  for (const packet of tcpPackets) {
    if (!packet.src_ip) continue;
    pushMap(bySource, packet.src_ip, packet);
  }

  const alerts: Alert[] = [];
  for (const [srcIp, rows] of bySource) {
    const synRows = rows.filter(isSynOnly);
    if (synRows.length < 4) continue;

    const dstPorts = uniqueNumbers(synRows.map((packet) => packet.dst_port));
    const dstIps = uniqueStrings(synRows.map((packet) => packet.dst_ip));
    const ackRows = rows.filter((packet) => hasFlag(packet, "ACK"));
    const synRate = synRows.length / baseline.captureDurationSec;
    const synShare = synRows.length / Math.max(1, baseline.tcpPackets);
    const ackRatio = ackRows.length / Math.max(1, synRows.length);
    const sourceSynShare = synRows.length / Math.max(1, allSynRows.length);
    const portSpreadVelocity = dstPorts.length / baseline.captureDurationSec;
    const bidirectional = appearsBidirectional(srcIp, synRows, tcpPackets);
    const sequentiality = portSequentiality(dstPorts);
    const windows = activeWindows(synRows, baseline.captureDurationSec);

    const volumeScore = capScore([
      baseline.timeReliable && synRate > 2 ? 0.16 : 0,
      synShare > 0.08 ? 0.12 : 0,
      synRows.length > 20 ? 0.12 : 0,
    ], 0.25);
    const dispersionScore = capScore([
      dstPorts.length > 15 ? 0.18 : 0,
      dstIps.length > 5 ? 0.08 : 0,
      sequentiality > 0.5 && dstPorts.length >= 8 ? 0.14 : 0,
    ], 0.3);
    const asymmetryScore = bidirectional && ackRatio < 0.35 ? 0.18 : 0;
    const persistenceScore = capScore([
      windows >= 3 ? 0.12 : 0,
      baseline.timeReliable && portSpreadVelocity > 10 ? 0.1 : 0,
    ], 0.15);
    const concentrationScore = sourceSynShare > 0.7 ? 0.1 : 0;
    const rawScore = volumeScore + dispersionScore + asymmetryScore + persistenceScore + concentrationScore;
    const confidence = clamp(rawScore * baseline.sampleMultiplier, 0, 0.96);
    const impactScore = clamp(
      synRows.length / Math.max(1, baseline.totalPackets) * 0.35
      + Math.min(dstPorts.length / 80, 0.3)
      + Math.min(dstIps.length / 25, 0.2)
      + (sequentiality > 0.5 ? 0.15 : 0),
      0,
      1,
    );

    if (confidence < 0.4) continue;

    alerts.push({
      id: `port-scan-${srcIp}`,
      type: "port_scan",
      level: confidence >= 0.78 || impactScore > 0.75 ? "critical" : "warning",
      title: "Possible port scan",
      message: `${srcIp} generated a scan-like TCP SYN pattern across multiple destinations or ports.`,
      confidence,
      evidence: [
        `${synRows.length.toLocaleString()} SYN-only packets from ${srcIp}.`,
        `${dstPorts.length.toLocaleString()} unique destination ports and ${dstIps.length.toLocaleString()} unique destination IPs.`,
        `Port sequentiality score: ${(sequentiality * 100).toFixed(0)}%.`,
        bidirectional
          ? `ACK/SYN ratio: ${(ackRatio * 100).toFixed(1)}%.`
          : "ACK/SYN ratio skipped because the capture does not look clearly bidirectional.",
        baseline.timeReliable
          ? `SYN rate: ${synRate.toFixed(1)} packets/sec.`
          : "Time-based scan signals were reduced because the capture is shorter than 2 seconds.",
        baseline.isSmallCapture
          ? "Small-capture penalty applied to reduce false positives."
          : "Sample size did not require a small-capture penalty.",
      ],
      recommendation: "Check whether this host is running a legitimate scanner, security tool, or suspicious process.",
      affected_ips: [srcIp, ...dstIps.slice(0, 5)],
      affected_macs: uniqueStrings(synRows.map((packet) => packet.src_mac)).slice(0, 5),
      metrics: {
        syn_count: synRows.length,
        syn_rate_pps: synRate,
        syn_share_tcp: synShare,
        unique_dst_ports: dstPorts.length,
        unique_dst_ips: dstIps.length,
        ack_ratio: ackRatio,
        source_syn_share: sourceSynShare,
        port_spread_velocity: portSpreadVelocity,
        bidirectional_capture: bidirectional ? 1 : 0,
        volume_score: volumeScore,
        dispersion_score: dispersionScore,
        asymmetry_score: asymmetryScore,
        persistence_score: persistenceScore,
        concentration_score: concentrationScore,
        impact_score: impactScore,
      },
    });
  }

  return alerts;
}

function analyzeTcpResetActivity(packets: Packet[], baseline: CaptureBaseline): Alert[] {
  if (baseline.tcpPackets < 10) return [];

  const tcpPackets = packets.filter(isTcpLike);
  const rstRows = tcpPackets.filter((packet) => hasFlag(packet, "RST"));
  if (!rstRows.length) return [];

  const rstCountShare = rstRows.length / Math.max(1, baseline.totalPackets);
  const rstRate = rstRows.length / baseline.captureDurationSec;
  const rstTcpRatio = rstRows.length / Math.max(1, baseline.tcpPackets);
  const dstCounts = countStrings(rstRows.map((packet) => endpoint(packet.dst_ip, packet.dst_port)));
  const srcCounts = countStrings(rstRows.map((packet) => endpoint(packet.src_ip, packet.src_port)));
  const [topDst, topDstCount] = topEntry(dstCounts);
  const [topSrc, topSrcCount] = topEntry(srcCounts);
  const sourceConcentration = topSrcCount / Math.max(1, rstRows.length);
  const destConcentration = topDstCount / Math.max(1, rstRows.length);
  const maxBurst = baseline.timeReliable ? maxPacketsInWindow(rstRows, 2) : 0;

  const volumeScore = capScore([
    rstCountShare > 0.01 ? 0.16 : 0,
    baseline.timeReliable && rstRate > 2 ? 0.18 : 0,
    rstTcpRatio > 0.08 ? 0.2 : 0,
  ], 0.35);
  const concentrationScore = capScore([
    sourceConcentration > 0.65 ? 0.14 : 0,
    destConcentration > 0.65 ? 0.14 : 0,
  ], 0.22);
  const burstScore = baseline.timeReliable && maxBurst > 10 ? 0.12 : 0;
  const rawScore = volumeScore + concentrationScore + burstScore;
  const confidence = clamp(rawScore * baseline.sampleMultiplier, 0, 0.9);
  const impactScore = clamp(
    rstRows.length / Math.max(1, baseline.totalPackets) * 0.4
    + rstTcpRatio * 0.35
    + Math.max(sourceConcentration, destConcentration) * 0.25,
    0,
    1,
  );

  if (confidence < 0.38) return [];

  return [{
    id: "tcp-reset-activity",
    type: "tcp_reset_activity",
    level: confidence >= 0.78 || rstTcpRatio > 0.18 ? "critical" : "warning",
    title: "Elevated TCP reset activity",
    message: `${(rstTcpRatio * 100).toFixed(1)}% of TCP-like packets contained RST flags.`,
    confidence,
    evidence: [
      `${rstRows.length.toLocaleString()} TCP reset packets.`,
      `RST/TCP ratio: ${(rstTcpRatio * 100).toFixed(1)}%.`,
      baseline.timeReliable
        ? `RST rate: ${rstRate.toFixed(1)} packets/sec.`
        : "RST/sec and burst scoring were reduced because the capture is shorter than 2 seconds.",
      topDst ? `Most common reset destination: ${topDst} (${topDstCount} packets).` : "No dominant reset destination.",
      topSrc ? `Most common reset source: ${topSrc} (${topSrcCount} packets).` : "No dominant reset source.",
      baseline.timeReliable ? `Largest 2-second RST burst: ${maxBurst.toLocaleString()} packets.` : "No reliable burst window was computed.",
    ],
    recommendation: "Review closed services, client retries, middleboxes, load balancers, firewall policy, or scan responses around the affected endpoints.",
    affected_ips: uniqueStrings(rstRows.flatMap((packet) => [packet.src_ip, packet.dst_ip])).slice(0, 8),
    affected_macs: uniqueStrings(rstRows.flatMap((packet) => [packet.src_mac, packet.dst_mac])).slice(0, 8),
    metrics: {
      tcp_packets: baseline.tcpPackets,
      rst_count: rstRows.length,
      rst_total_share: rstCountShare,
      rst_rate_pps: rstRate,
      rst_tcp_ratio: rstTcpRatio,
      source_concentration: sourceConcentration,
      destination_concentration: destConcentration,
      rst_burst_2s: maxBurst,
      volume_score: volumeScore,
      concentration_score: concentrationScore,
      burst_score: burstScore,
      impact_score: impactScore,
    },
  }];
}

function analyzeDnsBehavior(packets: Packet[], baseline: CaptureBaseline): Alert[] {
  const dnsRows = packets.filter(isDnsPacket);
  if (!dnsRows.length) return [];

  const dnsRate = dnsRows.length / baseline.captureDurationSec;
  const dnsShare = dnsRows.length / Math.max(1, baseline.totalPackets);
  const sourceCounts = countStrings(dnsRows.map((packet) => packet.src_ip));
  const [topSource, topSourceCount] = topEntry(sourceCounts);
  const topSourceShare = topSourceCount / Math.max(1, dnsRows.length);
  const sources = uniqueStrings(dnsRows.map((packet) => packet.src_ip));

  const volumeScore = capScore([
    dnsShare > 0.3 ? 0.2 : 0,
    baseline.timeReliable && dnsRate > 20 ? 0.2 : 0,
    topSourceShare > 0.7 ? 0.1 : 0,
  ], 0.45);
  const confidence = clamp(volumeScore * baseline.sampleMultiplier, 0, 0.62);
  const impactScore = clamp(dnsShare * 0.55 + Math.min(dnsRows.length / 1_000, 0.25) + topSourceShare * 0.2, 0, 1);

  if (confidence < 0.35) return [];

  return [{
    id: "dns-high-volume",
    type: "dns_high",
    level: confidence > 0.6 ? "warning" : "info",
    title: "Elevated DNS activity",
    message: `DNS-like traffic represents ${(dnsShare * 100).toFixed(1)}% of the visible packets.`,
    confidence,
    evidence: [
      `${dnsRows.length.toLocaleString()} DNS-like packets.`,
      baseline.timeReliable ? `DNS packet rate: ${dnsRate.toFixed(1)} packets/sec.` : "DNS/sec scoring was reduced because the capture is shorter than 2 seconds.",
      topSource ? `Top DNS source: ${topSource} (${(topSourceShare * 100).toFixed(1)}% of DNS packets).` : "No dominant DNS source.",
      "Structural DNS analysis is disabled until the sidecar exposes query name, record type, and response code.",
    ],
    recommendation: "Review whether the source is resolving many domains normally or retrying failed lookups. DNS tunneling analysis is not enabled yet.",
    affected_ips: sources.slice(0, 8),
    affected_macs: uniqueStrings(dnsRows.map((packet) => packet.src_mac)).slice(0, 8),
    metrics: {
      dns_count: dnsRows.length,
      dns_share: dnsShare,
      dns_rate_pps: dnsRate,
      top_source_share: topSourceShare,
      volume_score: volumeScore,
      structural_dns_enabled: 0,
      impact_score: impactScore,
    },
  }];
}

function analyzeArpBehavior(packets: Packet[], baseline: CaptureBaseline): Alert[] {
  const arpRows = packets.filter((packet) => packet.protocol === "ARP");
  if (!arpRows.length) return [];

  const arpShare = arpRows.length / Math.max(1, baseline.totalPackets);
  const arpRate = arpRows.length / baseline.captureDurationSec;
  const broadcastRows = arpRows.filter((packet) => isBroadcastMac(packet.dst_mac) || packet.dst_ip === "255.255.255.255");

  const volumeScore = capScore([
    arpRows.length > Math.max(30, baseline.totalPackets * 0.15) ? 0.2 : 0,
    broadcastRows.length > Math.max(20, baseline.totalPackets * 0.1) ? 0.15 : 0,
    baseline.timeReliable && arpRate > 10 ? 0.08 : 0,
  ], 0.43);
  const confidence = clamp(volumeScore * baseline.sampleMultiplier, 0, 0.59);
  const impactScore = clamp(arpShare * 0.55 + broadcastRows.length / Math.max(1, arpRows.length) * 0.25 + Math.min(arpRows.length / 500, 0.2), 0, 1);

  if (confidence < 0.3) return [];

  return [{
    id: "arp-volume",
    type: "arp_suspicious",
    level: "info",
    title: "Elevated ARP volume",
    message: "ARP traffic volume is higher than expected for the visible capture.",
    confidence,
    evidence: [
      `${arpRows.length.toLocaleString()} ARP packets (${(arpShare * 100).toFixed(1)}% of traffic).`,
      `${broadcastRows.length.toLocaleString()} ARP broadcast-like packets.`,
      baseline.timeReliable ? `ARP rate: ${arpRate.toFixed(1)} packets/sec.` : "ARP/sec scoring was reduced because the capture is shorter than 2 seconds.",
      "ARP identity-conflict analysis is disabled until the sidecar parses ARP sender/target fields.",
    ],
    recommendation: "Review whether the ARP volume matches normal local discovery, virtualization, bridges, or failover. ARP spoofing analysis is not enabled yet.",
    affected_ips: uniqueStrings(arpRows.flatMap((packet) => [packet.src_ip, packet.dst_ip])).slice(0, 8),
    affected_macs: uniqueStrings(arpRows.flatMap((packet) => [packet.src_mac, packet.dst_mac])).slice(0, 8),
    metrics: {
      arp_count: arpRows.length,
      arp_share: arpShare,
      arp_rate_pps: arpRate,
      broadcast_arp_count: broadcastRows.length,
      identity_checks_enabled: 0,
      volume_score: volumeScore,
      impact_score: impactScore,
    },
  }];
}

function analyzeDominantHosts(packets: Packet[], baseline: CaptureBaseline, gatewaySet: Set<string>): Alert[] {
  const candidates = scoreHosts(packets, baseline, "ip", gatewaySet)
    .concat(scoreHosts(packets, baseline, "mac", new Set()))
    .sort((a, b) => Math.max(b.packetShare, b.byteShare) - Math.max(a.packetShare, a.byteShare));

  const top = candidates[0];
  const second = candidates[1];
  if (!top) return [];

  const dominanceGap = Math.max(top.packetShare - (second?.packetShare ?? 0), top.byteShare - (second?.byteShare ?? 0));
  const networkSizePenalty = baseline.visibleHosts < 4 ? 0.75 : 1;
  const gatewayPenalty = top.gatewayPenalty;
  const volumeScore = capScore([
    top.packetShare > 0.4 ? 0.24 : 0,
    top.byteShare > 0.4 ? 0.24 : 0,
    dominanceGap > 0.2 ? 0.18 : 0,
  ], 0.45);
  const behaviorScore = capScore([
    top.host.windows.size >= 3 ? 0.14 : 0,
    top.host.protocols.size > 4 ? 0.08 : 0,
    top.host.ports.size > 30 ? 0.08 : 0,
  ], 0.25);
  const confidence = clamp((volumeScore + behaviorScore) * baseline.sampleMultiplier * networkSizePenalty * gatewayPenalty, 0, 0.86);
  const impactScore = clamp(Math.max(top.packetShare, top.byteShare) * 0.65 + dominanceGap * 0.25 + Math.min(top.host.bytes / Math.max(1, baseline.totalBytes), 0.1), 0, 1);

  if (confidence < 0.32) return [];

  const isMac = isMacAddress(top.host.id);

  return [{
    id: `dominant-host-${top.host.id}`,
    type: "host_dominant",
    level: confidence > 0.58 ? "warning" : "info",
    title: "Dominant host detected",
    message: `${top.host.id} concentrates a large share of packets or bytes.`,
    confidence,
    evidence: [
      `Packet share: ${(top.packetShare * 100).toFixed(1)}%.`,
      `Byte share: ${(top.byteShare * 100).toFixed(1)}%.`,
      `Dominance gap versus next host: ${(dominanceGap * 100).toFixed(1)}%.`,
      `${top.host.windows.size.toLocaleString()} active time windows.`,
      `Protocols observed: ${[...top.host.protocols].join(", ") || "unknown"}.`,
      top.likelyGateway
        ? `Likely-gateway penalty applied instead of suppressing the alert (${gatewayPenalty.toFixed(2)}x).`
        : gatewaySet.size ? `Likely gateway detected elsewhere: ${[...gatewaySet].join(", ")}.` : "No likely gateway was detected.",
      baseline.visibleHosts < 4
        ? "Small visible-host count penalty applied because dominance is normal in tiny networks."
        : "Visible-host count is sufficient for relative dominance scoring.",
    ],
    recommendation: "Decide whether this host is expected to dominate traffic, such as a streaming client, backup job, update process, gateway, or monitoring agent.",
    affected_ips: isMac ? [] : [top.host.id],
    affected_macs: isMac ? [top.host.id] : [],
    metrics: {
      packet_share: top.packetShare,
      byte_share: top.byteShare,
      dominance_gap: dominanceGap,
      endpoint_packets: top.host.packets,
      endpoint_bytes: top.host.bytes,
      active_windows: top.host.windows.size,
      protocol_count: top.host.protocols.size,
      distinct_ports: top.host.ports.size,
      likely_gateway: top.likelyGateway ? 1 : 0,
      gateway_penalty: gatewayPenalty,
      volume_score: volumeScore,
      behavior_score: behaviorScore,
      impact_score: impactScore,
    },
  }];
}

function analyzeHeavyTraffic(packets: Packet[], baseline: CaptureBaseline, gatewaySet: Set<string>): Alert[] {
  if (baseline.totalPackets < 5 || baseline.totalBytes < 32_000) return [];

  const candidates = scoreHosts(packets, baseline, "ip", gatewaySet)
    .sort((a, b) => b.byteShare - a.byteShare);

  const top = candidates[0];
  const second = candidates[1];
  if (!top) return [];

  const packetsForTop = packetsForHost(packets, top.host.id);
  const destByteShares = destinationByteShares(packetsForTop, top.host.id, top.host.bytes);
  const [topDestination, topDestinationShare] = topEntry(destByteShares);
  const byteRate = top.host.bytes / baseline.captureDurationSec;
  const byteGap = top.byteShare - (second?.byteShare ?? 0);
  const gatewayPenalty = top.gatewayPenalty;

  const asymmetryScore = top.byteShare > 0.35 && top.packetShare < 0.25 ? 0.3 : 0;
  const sizeScore = top.avgPacketBytes > 900 && top.byteShare > 0.25 ? 0.22 : 0;
  const throughputScore = baseline.timeReliable && baseline.captureDurationSec > 10 && byteRate > Math.max(500 * 1024, baseline.totalBytes / baseline.captureDurationSec * 0.4) ? 0.18 : 0;
  const destinationScore = topDestinationShare > 0.8 ? 0.12 : 0;
  const relativeScore = byteGap > 0.2 ? 0.14 : 0;
  const confidence = clamp((asymmetryScore + sizeScore + throughputScore + destinationScore + relativeScore) * baseline.sampleMultiplier * gatewayPenalty, 0, 0.84);
  const impactScore = clamp(top.byteShare * 0.55 + byteGap * 0.25 + Math.min(byteRate / Math.max(1, baseline.totalBytes / baseline.captureDurationSec), 1) * 0.2, 0, 1);

  if (confidence < 0.33) return [];

  return [{
    id: `heavy-traffic-${top.host.id}`,
    type: "heavy_traffic",
    level: confidence >= 0.72 ? "warning" : "info",
    title: "Heavy traffic concentration",
    message: `${top.host.id} carries a high byte share compared with its packet share.`,
    confidence,
    evidence: [
      `Byte share: ${(top.byteShare * 100).toFixed(1)}%.`,
      `Packet share: ${(top.packetShare * 100).toFixed(1)}%.`,
      `Byte-share gap versus next host: ${(byteGap * 100).toFixed(1)}%.`,
      `Average counted packet size: ${formatBytes(top.avgPacketBytes)}.`,
      baseline.timeReliable ? `Estimated byte rate: ${formatBytes(byteRate)}/sec.` : "Throughput scoring was reduced because the capture is shorter than 2 seconds.",
      topDestination ? `Top opposite endpoint: ${topDestination} (${(topDestinationShare * 100).toFixed(1)}% of this host's bytes).` : "No single opposite endpoint dominated bytes.",
      top.likelyGateway ? `Likely-gateway penalty applied instead of suppressing the alert (${gatewayPenalty.toFixed(2)}x).` : "No gateway penalty was applied.",
    ],
    recommendation: "Review whether this is an expected download, stream, backup, cloud sync, update, or large transfer.",
    affected_ips: [top.host.id],
    affected_macs: [],
    metrics: {
      byte_share: top.byteShare,
      packet_share: top.packetShare,
      byte_gap: byteGap,
      avg_packet_bytes: top.avgPacketBytes,
      endpoint_bytes: top.host.bytes,
      byte_rate: byteRate,
      top_destination_share: topDestinationShare,
      likely_gateway: top.likelyGateway ? 1 : 0,
      gateway_penalty: gatewayPenalty,
      asymmetry_score: asymmetryScore,
      size_score: sizeScore,
      throughput_score: throughputScore,
      destination_score: destinationScore,
      relative_score: relativeScore,
      impact_score: impactScore,
    },
  }];
}

function computeBaseline(packets: Packet[]): CaptureBaseline {
  const totalPackets = packets.length;
  const totalBytes = packets.reduce((sum, packet) => sum + packet.length, 0);
  const captureDurationSec = sessionDurationSeconds(packets);
  const visibleHosts = collectVisibleIps(packets).length;
  return {
    totalPackets,
    totalBytes,
    captureDurationSec,
    avgPacketsPerSec: totalPackets / captureDurationSec,
    tcpPackets: packets.filter(isTcpLike).length,
    udpPackets: packets.filter((packet) => packet.protocol === "UDP" || packet.protocol === "DNS").length,
    visibleHosts,
    isSmallCapture: totalPackets < 50,
    timeReliable: captureDurationSec >= 2,
    sampleMultiplier: totalPackets < 50 ? 0.85 : totalPackets < 200 ? 0.95 : 1,
  };
}

function detectLikelyGateways(packets: Packet[], baseline: CaptureBaseline) {
  const gatewaySet = new Set<string>();
  const topIp = scoreHosts(packets, baseline, "ip", new Set())
    .sort((a, b) => b.packetShare - a.packetShare)[0];

  if (topIp && topIp.packetShare > 0.35 && !isLocalBroadcast(topIp.host.id)) {
    gatewaySet.add(topIp.host.id);
  }

  for (const trusted of TRUSTED_HOSTS) {
    gatewaySet.add(trusted);
  }

  return gatewaySet;
}

function scoreHosts(packets: Packet[], baseline: CaptureBaseline, kind: "ip" | "mac", gatewaySet: Set<string>): ScoredHost[] {
  return [...collectHostStats(packets, baseline, kind).values()]
    .filter((host) => !isLocalBroadcast(host.id))
    .map((host) => ({
      host,
      packetShare: host.packets / Math.max(1, baseline.totalPackets * 2),
      byteShare: host.bytes / Math.max(1, baseline.totalBytes * 2),
      avgPacketBytes: host.bytes / Math.max(1, host.packets),
      likelyGateway: gatewaySet.has(host.id),
      gatewayPenalty: gatewaySet.has(host.id)
        ? gatewayPenaltyFor(host.packets / Math.max(1, baseline.totalPackets * 2))
        : 1,
    }));
}

function collectHostStats(packets: Packet[], baseline: CaptureBaseline, kind: "ip" | "mac") {
  const stats = new Map<string, HostStats>();
  for (const packet of packets) {
    const endpoints = kind === "ip" ? [packet.src_ip, packet.dst_ip] : [packet.src_mac, packet.dst_mac];
    for (const endpointId of endpoints) {
      if (!endpointId || isBroadcastMac(endpointId)) continue;
      const item = stats.get(endpointId) ?? {
        id: endpointId,
        packets: 0,
        bytes: 0,
        protocols: new Set<string>(),
        ports: new Set<number>(),
        windows: new Set<number>(),
      };
      item.packets += 1;
      item.bytes += packet.length;
      item.protocols.add(packet.protocol);
      if (typeof packet.src_port === "number") item.ports.add(packet.src_port);
      if (typeof packet.dst_port === "number") item.ports.add(packet.dst_port);
      item.windows.add(timeWindowIndex(packet, baseline.captureDurationSec));
      stats.set(endpointId, item);
    }
  }
  return stats;
}

function correlateAlerts(alerts: Alert[]) {
  const result: Alert[] = [];
  const used = new Set<string>();
  const scans = alerts.filter((alert) => alert.type === "port_scan");
  const resets = alerts.filter((alert) => alert.type === "tcp_reset_activity");

  for (const scan of scans) {
    const source = scan.affected_ips[0];
    const reset = resets.find((candidate) => source && candidate.affected_ips.includes(source));
    if (!source || !reset) continue;

    used.add(scan.id);
    used.add(reset.id);
    result.push({
      id: `active-recon-${source}`,
      type: "active_reconnaissance",
      level: scan.level === "critical" || reset.level === "critical" || Math.max(scan.confidence, reset.confidence) >= 0.78 ? "critical" : "warning",
      title: "Possible active reconnaissance",
      message: `${source} shows scan-like SYN behavior together with elevated TCP reset activity.`,
      confidence: clamp(Math.max(scan.confidence, reset.confidence) + 0.08, 0, 0.98),
      evidence: uniqueStrings([
        "Contributing signals: Possible Port Scan + Elevated TCP Reset Activity.",
        ...scan.evidence.slice(0, 4),
        ...reset.evidence.slice(0, 4),
        "Port-scan and TCP-reset signals overlap on the same host, so NetScope reports the combined behavior.",
      ]),
      recommendation: "Prioritize this host for review. Check authorized scanners, endpoint processes, firewall logs, and destination services.",
      affected_ips: uniqueStrings([...scan.affected_ips, ...reset.affected_ips]),
      affected_macs: uniqueStrings([...scan.affected_macs, ...reset.affected_macs]),
      metrics: {
        ...scan.metrics,
        ...prefixMetrics(reset.metrics, "reset"),
        impact_score: clamp((scan.metrics.impact_score ?? 0) * 0.55 + (reset.metrics.impact_score ?? 0) * 0.45, 0, 1),
        correlated_alert: 1,
        contributing_port_scan: 1,
        contributing_tcp_reset_activity: 1,
      },
    });
  }

  for (const alert of alerts) {
    if (!used.has(alert.id)) result.push(alert);
  }

  return result;
}

function deduplicateAlerts(alerts: Alert[]) {
  const merged: Alert[] = [];
  const used = new Set<number>();

  for (let index = 0; index < alerts.length; index += 1) {
    if (used.has(index)) continue;
    const alert = alerts[index];
    const counterpartIndex = alerts.findIndex((candidate, candidateIndex) => {
      if (candidateIndex <= index || used.has(candidateIndex)) return false;
      if (!isVolumeAlert(alert) || !isVolumeAlert(candidate)) return false;
      return primarySubject(alert) !== null && primarySubject(alert) === primarySubject(candidate);
    });

    if (counterpartIndex === -1) {
      merged.push(alert);
      continue;
    }

    const counterpart = alerts[counterpartIndex];
    used.add(counterpartIndex);
    const stronger = severityWeight(alert.level) > severityWeight(counterpart.level) ? alert : counterpart;
    const confidence = Math.max(alert.confidence, counterpart.confidence);

    merged.push({
      ...stronger,
      id: `volume-${primarySubject(alert)}`,
      title: "Dominant heavy-traffic host",
      message: `${primarySubject(alert)} is both traffic-dominant and byte-heavy in this capture.`,
      confidence,
      evidence: uniqueStrings([...alert.evidence, ...counterpart.evidence]).slice(0, 8),
      recommendation: "Review whether this host is expected to dominate traffic because of streaming, backup, cloud sync, updates, or large transfers.",
      affected_ips: uniqueStrings([...alert.affected_ips, ...counterpart.affected_ips]),
      affected_macs: uniqueStrings([...alert.affected_macs, ...counterpart.affected_macs]),
      metrics: {
        ...alert.metrics,
        ...prefixMetrics(counterpart.metrics, "volume"),
        impact_score: Math.max(alert.metrics.impact_score ?? 0, counterpart.metrics.impact_score ?? 0),
        merged_volume_alert: 1,
      },
    });
  }

  return merged;
}

function rankAlerts(alerts: Alert[]) {
  return [...alerts].sort((a, b) => (
    severityWeight(b.level) - severityWeight(a.level)
    || (b.metrics.impact_score ?? 0) - (a.metrics.impact_score ?? 0)
    || b.confidence - a.confidence
  ));
}

function isVolumeAlert(alert: Alert) {
  return alert.type === "host_dominant" || alert.type === "heavy_traffic";
}

function primarySubject(alert: Alert) {
  return alert.affected_ips[0] ?? alert.affected_macs[0] ?? null;
}

function appearsBidirectional(srcIp: string, synRows: Packet[], tcpPackets: Packet[]) {
  const targets = new Set(uniqueStrings(synRows.map((packet) => packet.dst_ip)));
  return tcpPackets.some((packet) => packet.src_ip && targets.has(packet.src_ip) && packet.dst_ip === srcIp && hasFlag(packet, "ACK"));
}

function maxPacketsInWindow(packets: Packet[], seconds: number) {
  const times = packets
    .map((packet) => Date.parse(packet.ts))
    .filter((value) => Number.isFinite(value))
    .sort((a, b) => a - b);
  if (!times.length) return 0;

  let max = 0;
  let left = 0;
  const windowMs = seconds * 1_000;
  for (let right = 0; right < times.length; right += 1) {
    while (times[right] - times[left] > windowMs) left += 1;
    max = Math.max(max, right - left + 1);
  }
  return max;
}

function destinationByteShares(packets: Packet[], hostId: string, totalHostBytes: number) {
  const counts = new Map<string, number>();
  for (const packet of packets) {
    const opposite = packet.src_ip === hostId ? packet.dst_ip : packet.src_ip;
    if (!opposite || opposite === hostId) continue;
    counts.set(opposite, (counts.get(opposite) ?? 0) + packet.length);
  }
  for (const [key, value] of counts) {
    counts.set(key, value / Math.max(1, totalHostBytes));
  }
  return counts;
}

function packetsForHost(packets: Packet[], hostId: string) {
  return packets.filter((packet) => packet.src_ip === hostId || packet.dst_ip === hostId);
}

function activeWindows(packets: Packet[], durationSeconds: number) {
  return new Set(packets.map((packet) => timeWindowIndex(packet, durationSeconds))).size;
}

function timeWindowIndex(packet: Packet, durationSeconds: number) {
  const parsed = Date.parse(packet.ts);
  if (!Number.isFinite(parsed)) return 0;
  const windowMs = Math.max(1_000, (durationSeconds * 1_000) / 3);
  return Math.floor(parsed / windowMs);
}

function portSequentiality(ports: number[]) {
  const sorted = [...new Set(ports)].sort((a, b) => a - b);
  if (sorted.length < 3) return 0;
  let nearAdjacent = 0;
  for (let index = 1; index < sorted.length; index += 1) {
    if (sorted[index] - sorted[index - 1] <= 2) nearAdjacent += 1;
  }
  return nearAdjacent / Math.max(1, sorted.length - 1);
}

function collectVisibleIps(packets: Packet[]) {
  return uniqueStrings(packets.flatMap((packet) => [packet.src_ip, packet.dst_ip]))
    .filter((ip) => !isLocalBroadcast(ip));
}

function isTcpLike(packet: Packet) {
  return TCP_PROTOCOLS.has(packet.protocol);
}

function isDnsPacket(packet: Packet) {
  return packet.protocol === "DNS" || DNS_PORTS.has(packet.src_port ?? -1) || DNS_PORTS.has(packet.dst_port ?? -1);
}

function isSynOnly(packet: Packet) {
  return hasFlag(packet, "SYN") && !hasFlag(packet, "ACK");
}

function hasFlag(packet: Packet, flag: string) {
  return packet.flags.split(/[-,\s]+/).includes(flag);
}

function endpoint(ip: string | null, port: number | null) {
  if (!ip) return null;
  return port === null ? ip : `${ip}:${port}`;
}

function sessionDurationSeconds(packets: Packet[]) {
  const times = packets
    .map((packet) => Date.parse(packet.ts))
    .filter((value) => Number.isFinite(value));
  if (times.length < 2) return 1;
  return Math.max(1, (Math.max(...times) - Math.min(...times)) / 1_000);
}

function countStrings(values: Array<string | null>) {
  const counts = new Map<string, number>();
  for (const value of values) {
    if (!value) continue;
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return counts;
}

function topEntry(map: Map<string, number>): [string | null, number] {
  const entry = [...map.entries()].sort((a, b) => b[1] - a[1])[0];
  return entry ?? [null, 0];
}

function uniqueStrings(values: Array<string | null | undefined>) {
  return [...new Set(values.filter((value): value is string => Boolean(value)))];
}

function uniqueNumbers(values: Array<number | null | undefined>) {
  return [...new Set(values.filter((value): value is number => typeof value === "number"))];
}

function pushMap<K, V>(map: Map<K, V[]>, key: K, value: V) {
  const rows = map.get(key) ?? [];
  rows.push(value);
  map.set(key, rows);
}

function prefixMetrics(metrics: Record<string, number>, prefix: string) {
  return Object.fromEntries(Object.entries(metrics).map(([key, value]) => [`${prefix}_${key}`, value]));
}

function capScore(values: number[], max: number) {
  return Math.min(max, values.reduce((sum, value) => sum + value, 0));
}

function gatewayPenaltyFor(packetShare: number) {
  if (packetShare > 0.65) return 0.55;
  if (packetShare > 0.5) return 0.75;
  return 0.9;
}

function isBroadcastMac(mac: string | null) {
  return mac?.toLowerCase() === "ff:ff:ff:ff:ff:ff";
}

function isMacAddress(value: string) {
  return /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(value);
}

function isLocalBroadcast(value: string) {
  return value === "255.255.255.255" || value === "0.0.0.0" || value.toLowerCase() === "ff:ff:ff:ff:ff:ff";
}

function severityWeight(level: AlertLevel) {
  if (level === "critical") return 3;
  if (level === "warning") return 2;
  if (level === "info") return 1;
  return 0;
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
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
