import { useState, useEffect, useCallback } from "react";
import { RefreshCw } from "lucide-react";
import {
  AreaChart, Area,
  BarChart, Bar,
  PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from "recharts";
import { getDiagnosticsData, listSessions } from "@/lib/tauri";
import type { DiagnosticsData } from "@/lib/tauri";
import { useAppState } from "@/store";
import { Spinner } from "@/components/ui/Spinner";

// Protocol colour map (matches CSS variables)
const PROTO_COLORS: Record<string, string> = {
  TCP:   "hsl(214 100% 62%)",
  UDP:   "hsl(280 72% 64%)",
  HTTP:  "hsl(38 100% 56%)",
  HTTPS: "hsl(142 72% 48%)",
  DNS:   "hsl(174 100% 44%)",
  ICMP:  "hsl(355 86% 58%)",
  ARP:   "hsl(32 100% 58%)",
  OTHER: "hsl(220 10% 52%)",
};

function protoColor(p: string) {
  return PROTO_COLORS[p] ?? PROTO_COLORS.OTHER;
}

function fmtBytes(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(2) + " MB";
  if (n >= 1_000)     return (n / 1_000).toFixed(1) + " KB";
  return n + " B";
}

// ── Custom tooltip ────────────────────────────────────────────────────────────
function ChartTip({ active, payload, label, formatter }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="panel px-2.5 py-2 text-[10px] font-mono space-y-1 shadow-xl">
      {label && <div className="text-subtle mb-1">{label}</div>}
      {payload.map((e: any) => (
        <div key={e.name} className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full shrink-0" style={{ background: e.color }} />
          <span className="text-muted-foreground">{e.name}:</span>
          <span className="text-foreground font-semibold">
            {formatter ? formatter(e.value) : e.value}
          </span>
        </div>
      ))}
    </div>
  );
}

// ── Section wrapper ───────────────────────────────────────────────────────────
function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="panel overflow-hidden">
      <div className="px-4 py-2 border-b border-dim bg-surface-raised">
        <span className="section-title">{title}</span>
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export function DiagnosticsView() {
  const { state } = useAppState();
  const sessions = state.sessions;

  const [sessionId, setSessionId] = useState<number | null>(null);
  const [data,      setData]      = useState<DiagnosticsData | null>(null);
  const [loading,   setLoading]   = useState(false);

  useEffect(() => {
    if (sessions.length > 0 && !sessionId) {
      setSessionId(sessions[0].id);
    }
  }, [sessions, sessionId]);

  const load = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    try {
      const d = await getDiagnosticsData(sessionId);
      setData(d);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => { load(); }, [load]);

  // Auto-refresh while active session is capturing
  useEffect(() => {
    if (sessionId !== state.sessionId || !state.isCapturing) return;
    const iv = setInterval(load, 5000);
    return () => clearInterval(iv);
  }, [sessionId, state.sessionId, state.isCapturing, load]);

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-dim bg-surface shrink-0">
        <select
          className="input w-52"
          value={sessionId ?? ""}
          onChange={(e) => setSessionId(Number(e.target.value))}
        >
          <option value="">— Select session —</option>
          {sessions.map((s) => (
            <option key={s.id} value={s.id}>
              #{s.id} {s.name ?? "Unnamed"} ({s.total_packets.toLocaleString()} pkts)
            </option>
          ))}
        </select>

        <button
          className="btn-ghost gap-1"
          onClick={load}
          disabled={loading || !sessionId}
        >
          {loading ? <Spinner /> : <RefreshCw size={12} />}
          Refresh
        </button>

        {data && (
          <div className="flex items-center gap-4 ml-auto text-[10px] font-mono">
            <span className="text-subtle">
              Total: <span className="text-foreground">{data.total_packets.toLocaleString()}</span> pkts
            </span>
            <span className="text-subtle">
              Volume: <span className="text-foreground">{fmtBytes(data.total_bytes)}</span>
            </span>
            <span className="text-subtle">
              Avg: <span className="text-foreground">{data.avg_packet_size.toFixed(1)}</span> B/pkt
            </span>
          </div>
        )}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 animate-fadein">
        {!data && !loading && (
          <div className="flex items-center justify-center h-48 text-subtle text-sm font-mono">
            {sessionId ? "Loading…" : "Select a session to view diagnostics."}
          </div>
        )}

        {loading && !data && (
          <div className="flex items-center justify-center h-48">
            <Spinner className="w-6 h-6" />
          </div>
        )}

        {data && (
          <>
            {/* Row 1: Traffic timeline + Protocol pie */}
            <div className="grid grid-cols-3 gap-4">
              <div className="col-span-2">
                <Section title="Traffic Timeline (5-second buckets)">
                  <ResponsiveContainer width="100%" height={200}>
                    <AreaChart data={data.traffic_timeline}
                      margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                      <defs>
                        <linearGradient id="pktGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%"  stopColor="hsl(174 100% 44%)" stopOpacity={0.35} />
                          <stop offset="95%" stopColor="hsl(174 100% 44%)" stopOpacity={0.02} />
                        </linearGradient>
                        <linearGradient id="byteGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%"  stopColor="hsl(214 100% 62%)" stopOpacity={0.25} />
                          <stop offset="95%" stopColor="hsl(214 100% 62%)" stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid stroke="hsl(240 8% 18%)" strokeDasharray="3 3" vertical={false} />
                      <XAxis
                        dataKey="bucket"
                        tick={{ fontSize: 9, fill: "hsl(220 10% 38%)", fontFamily: "JetBrains Mono" }}
                        tickFormatter={(v) => v.slice(11, 19)}
                        interval="preserveStartEnd"
                        axisLine={false} tickLine={false}
                      />
                      <YAxis
                        yAxisId="pkts"
                        tick={{ fontSize: 9, fill: "hsl(220 10% 38%)", fontFamily: "JetBrains Mono" }}
                        axisLine={false} tickLine={false} width={32}
                      />
                      <Tooltip content={<ChartTip />} />
                      <Area yAxisId="pkts" type="monotone" dataKey="packets"
                        name="Packets" stroke="hsl(174 100% 44%)" strokeWidth={1.5}
                        fill="url(#pktGrad)" dot={false} isAnimationActive={false} />
                    </AreaChart>
                  </ResponsiveContainer>
                </Section>
              </div>

              <Section title="Protocol Distribution">
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={data.protocol_stats}
                      dataKey="count"
                      nameKey="protocol"
                      cx="50%" cy="50%"
                      innerRadius={52} outerRadius={76}
                      strokeWidth={2}
                      stroke="hsl(240 11% 4%)"
                      isAnimationActive={false}
                    >
                      {data.protocol_stats.map((entry) => (
                        <Cell key={entry.protocol} fill={protoColor(entry.protocol)} />
                      ))}
                    </Pie>
                    <Tooltip
                      content={({ active, payload }) =>
                        active && payload?.length ? (
                          <div className="panel px-2.5 py-1.5 text-[10px] font-mono">
                            <span style={{ color: protoColor(payload[0].name as string) }}>
                              {payload[0].name}
                            </span>
                            <span className="text-muted-foreground ml-2">
                              {(payload[0].value as number).toLocaleString()}
                            </span>
                          </div>
                        ) : null
                      }
                    />
                    <Legend
                      iconType="circle"
                      iconSize={7}
                      formatter={(v) => (
                        <span style={{ fontSize: 10, fontFamily: "JetBrains Mono", color: "hsl(210 20% 94%)" }}>
                          {v}
                        </span>
                      )}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </Section>
            </div>

            {/* Row 2: Top IPs */}
            <div className="grid grid-cols-2 gap-4">
              <Section title="Top Source IPs">
                <TopIpChart data={data.top_src_ips.slice(0, 10)} color="hsl(214 100% 62%)" />
              </Section>
              <Section title="Top Destination IPs">
                <TopIpChart data={data.top_dst_ips.slice(0, 10)} color="hsl(280 72% 64%)" />
              </Section>
            </div>

            {/* Row 3: Protocol bar chart */}
            <Section title="Packet Count by Protocol">
              <ResponsiveContainer width="100%" height={160}>
                <BarChart
                  data={data.protocol_stats}
                  margin={{ top: 4, right: 8, bottom: 4, left: 0 }}
                  barSize={28}
                >
                  <CartesianGrid stroke="hsl(240 8% 18%)" vertical={false} strokeDasharray="3 3" />
                  <XAxis
                    dataKey="protocol"
                    tick={{ fontSize: 10, fill: "hsl(220 10% 52%)", fontFamily: "JetBrains Mono" }}
                    axisLine={false} tickLine={false}
                  />
                  <YAxis
                    tick={{ fontSize: 9, fill: "hsl(220 10% 38%)", fontFamily: "JetBrains Mono" }}
                    axisLine={false} tickLine={false} width={40}
                  />
                  <Tooltip content={<ChartTip />} />
                  <Bar dataKey="count" name="Packets" radius={[3, 3, 0, 0]} isAnimationActive={false}>
                    {data.protocol_stats.map((entry) => (
                      <Cell key={entry.protocol} fill={protoColor(entry.protocol)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </Section>
          </>
        )}
      </div>
    </div>
  );
}

// ── Top IP horizontal bar chart ───────────────────────────────────────────────
function TopIpChart({ data, color }: { data: { ip: string; count: number }[]; color: string }) {
  if (!data.length) {
    return (
      <div className="flex items-center justify-center h-24 text-subtle text-[10px] font-mono">
        No data
      </div>
    );
  }

  const max = Math.max(...data.map((d) => d.count), 1);

  return (
    <div className="space-y-1.5">
      {data.map(({ ip, count }) => (
        <div key={ip} className="flex items-center gap-2">
          <span className="text-[10px] font-mono text-muted-foreground w-32 shrink-0 truncate">
            {ip}
          </span>
          <div className="flex-1 h-1.5 bg-surface-overlay rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{ width: `${(count / max) * 100}%`, background: color }}
            />
          </div>
          <span className="text-[10px] font-mono text-subtle w-12 text-right tabular-nums shrink-0">
            {count.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}
