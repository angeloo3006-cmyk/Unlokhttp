import { cn } from "@/lib/utils";

const PROTO_LABELS: Record<string, string> = {
  TCP: "TCP", UDP: "UDP", HTTP: "HTTP", HTTPS: "TLS",
  DNS: "DNS", ICMP: "ICMP", ARP: "ARP", OTHER: "???",
};

interface Props {
  protocol: string;
  className?: string;
}

export function ProtocolBadge({ protocol, className }: Props) {
  const label = PROTO_LABELS[protocol] ?? protocol;
  return (
    <span className={cn("badge font-mono", `proto-${protocol}`, className)}>
      {label}
    </span>
  );
}
