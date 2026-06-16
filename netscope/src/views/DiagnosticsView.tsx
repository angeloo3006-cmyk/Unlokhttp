import { useEffect, useState } from "react";
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
import { useDiagnostics } from "@/hooks/useDiagnostics";
import { DiagnosticsCards } from "@/components/DiagnosticsCards";
import { DiagnosticAlertCard } from "@/components/diagnostics/DiagnosticAlertCard";
import { listSessions, queryPackets, type Session } from "@/lib/tauri";
import { packetRowToPacket } from "@/lib/packetRows";
import type { Packet } from "@/types/packet";

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
  const [session, setSession] = useState<Session | null>(null);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const diagnostics = useDiagnostics(packets, {
    startedAt: session?.started_at,
    endedAt: session?.ended_at,
  });
  const maxIpPackets = Math.max(1, ...diagnostics.topIPs.map((ip) => ip.packets));
  const totalProtocols = diagnostics.protocolDist.reduce((sum, item) => sum + item.value, 0);

  useEffect(() => {
    let cancelled = false;

    async function loadPreviousSession() {
      setLoading(true);
      setError(null);

      try {
        const sessions = await listSessions();
        const previousSession = sessions.find((item) => item.ended_at) ?? sessions[0] ?? null;

        if (!previousSession) {
          if (!cancelled) {
            setSession(null);
            setPackets([]);
          }
          return;
        }

        const firstPage = await queryPackets({
          sessionId: previousSession.id,
          filters: {},
          page: 1,
          pageSize: 1000,
        });

        const rows = [...firstPage.items];
        for (let page = 2; page <= firstPage.total_pages; page += 1) {
          const nextPage = await queryPackets({
            sessionId: previousSession.id,
            filters: {},
            page,
            pageSize: 1000,
          });
          rows.push(...nextPage.items);
        }

        rows.sort((a, b) => a.id - b.id);

        if (!cancelled) {
          setSession(previousSession);
          setPackets(rows.map(packetRowToPacket));
        }
      } catch (err) {
        if (!cancelled) setError(String(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void loadPreviousSession();

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="h-full overflow-auto p-3">
      <div className="glass-panel mb-3 flex items-center justify-between gap-3 p-3">
        <div>
          <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Previous session diagnostics</p>
          <h1 className="mt-1 text-sm font-semibold">
            {session ? session.name ?? `Session #${session.id}` : "No saved session selected"}
          </h1>
          <p className="mt-1 text-xs text-secondary">
            {session
              ? `${session.total_packets.toLocaleString()} packets · ${formatSessionDate(session.started_at)}`
              : "Stop a capture first to create a SQLite session."}
          </p>
        </div>
        <div className="text-right text-xs text-secondary">
          {loading && <span>Loading SQLite packets...</span>}
          {error && <span className="text-red-200">{error}</span>}
        </div>
      </div>
      <DiagnosticsCards metrics={diagnostics.metrics} sparkline={diagnostics.timeline} />
      <div className="mt-3 grid grid-cols-[1.7fr_1fr] gap-3">
        <Panel title="Traffic across previous session">
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
            {diagnostics.alerts.map((alert) => <DiagnosticAlertCard alert={alert} key={alert.id} />)}
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

function formatSessionDate(value: string | null) {
  if (!value) return "No start date";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString([], {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}
