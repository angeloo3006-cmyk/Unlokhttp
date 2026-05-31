import { AlertCircle, CheckCircle2, Info } from "lucide-react";
import {
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { usePacketCapture } from "@/hooks/usePacketCapture";
import { useDiagnostics } from "@/hooks/useDiagnostics";
import { DiagnosticsCards } from "@/components/DiagnosticsCards";

const COLORS: Record<string, string> = {
  TCP: "#3b82f6",
  UDP: "#06b6d4",
  DNS: "#eab308",
  HTTP: "#22c55e",
  HTTPS: "#14b8a6",
  ICMP: "#f97316",
  ARP: "#d946ef",
  OTHER: "#71717a",
};

export function DiagnosticsView() {
  const { packets } = usePacketCapture();
  const diagnostics = useDiagnostics(packets);
  const maxIpPackets = Math.max(1, ...diagnostics.topIPs.map((ip) => ip.packets));
  const totalProtocols = diagnostics.protocolDist.reduce((sum, item) => sum + item.value, 0);

  return (
    <div className="h-full overflow-auto p-3">
      <DiagnosticsCards metrics={diagnostics.metrics} sparkline={diagnostics.timeline} />
      <div className="mt-3 grid grid-cols-[1.7fr_1fr] gap-3">
        <Panel title="Traffic over the last 60 seconds">
          <ResponsiveContainer width="100%" height={230}>
            <LineChart data={diagnostics.timeline}>
              <CartesianGrid stroke="rgba(255,255,255,.06)" vertical={false} />
              <XAxis dataKey="time" stroke="rgba(255,255,255,.32)" tick={{ fontSize: 10 }} interval={9} />
              <YAxis stroke="rgba(255,255,255,.32)" tick={{ fontSize: 10 }} width={30} />
              <Tooltip content={<GlassTooltip />} />
              <Line type="monotone" dataKey="total" stroke="#3b82f6" dot={false} isAnimationActive={false} />
              <Line type="monotone" dataKey="TCP" stroke="#06b6d4" dot={false} isAnimationActive={false} />
              <Line type="monotone" dataKey="UDP" stroke="#22c55e" dot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </Panel>
        <Panel title="Protocol distribution">
          <div className="flex items-center gap-2">
            <ResponsiveContainer width="55%" height={230}>
              <PieChart>
                <Pie data={diagnostics.protocolDist} dataKey="value" nameKey="protocol" innerRadius={60} outerRadius={88} paddingAngle={2} stroke="transparent">
                  {diagnostics.protocolDist.map((item) => <Cell fill={COLORS[item.protocol] ?? COLORS.OTHER} key={item.protocol} />)}
                </Pie>
                <Tooltip content={<GlassTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            <div className="space-y-2 text-[11px]">
              {diagnostics.protocolDist.map((item) => (
                <div className="flex items-center gap-2" key={item.protocol}>
                  <span className="h-2 w-2 rounded-full" style={{ background: COLORS[item.protocol] ?? COLORS.OTHER }} />
                  <span className="w-12 text-secondary">{item.protocol}</span>
                  <span className="text-primary">{totalProtocols ? ((item.value / totalProtocols) * 100).toFixed(1) : "0.0"}%</span>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      </div>
      <div className="mt-3 grid grid-cols-[1.5fr_1fr] gap-3">
        <Panel title="Top active IPs">
          <div className="space-y-2">
            {diagnostics.topIPs.map((ip, index) => (
              <div className="grid grid-cols-[28px_140px_70px_70px_1fr] items-center gap-2 text-[11px]" key={ip.ip}>
                <span className="text-muted">#{index + 1}</span>
                <span className="font-mono text-primary">{ip.ip}</span>
                <span className="text-secondary">{ip.packets} packets</span>
                <span className="text-secondary">{ip.bytes} bytes</span>
                <div>
                  <div className="h-1.5 rounded-full bg-white/5"><div className="h-full rounded-full bg-blue-400" style={{ width: `${(ip.packets / maxIpPackets) * 100}%` }} /></div>
                  <span className="text-[10px] text-muted">{ip.protocols.join(", ")}</span>
                </div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Automatic diagnostic">
          <div className="space-y-2">
            {diagnostics.alerts.map((alert) => {
              const Icon = alert.level === "success" ? CheckCircle2 : alert.level === "warning" ? AlertCircle : Info;
              return <div className={`alert-${alert.level} flex gap-2 rounded-lg border p-2 text-xs`} key={alert.message}><Icon className="mt-0.5 shrink-0" size={14} /><span>{alert.message}</span></div>;
            })}
          </div>
        </Panel>
      </div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="glass-panel overflow-hidden p-3"><h2 className="mb-3 text-[10px] uppercase tracking-[0.18em] text-muted">{title}</h2>{children}</section>;
}

function GlassTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color?: string }>; label?: string }) {
  if (!active || !payload?.length) return null;
  return <div className="glass-surface p-2 text-[11px] shadow-xl">{label && <p className="mb-1 text-muted">{label}</p>}{payload.map((item) => <p key={item.name} style={{ color: item.color }}>{item.name}: {item.value}</p>)}</div>;
}
