import { Activity, Gauge, RadioTower, ShieldAlert } from "lucide-react";
import { Line, LineChart, ResponsiveContainer } from "recharts";

interface Metrics {
  pps: number;
  bandwidthMbps: number;
  avgRtt: number | null;
  errorRate: number;
}

export function DiagnosticsCards({ metrics, sparkline }: { metrics: Metrics; sparkline: Array<{ total: number }> }) {
  const cards = [
    { label: "Packets / sec", value: metrics.pps.toFixed(0), icon: Activity, chart: true },
    { label: "Bandwidth", value: `${metrics.bandwidthMbps.toFixed(3)} Mbps`, icon: RadioTower },
    { label: "Average RTT", value: metrics.avgRtt === null ? "N/A" : `${metrics.avgRtt.toFixed(1)} ms`, icon: Gauge },
    { label: "TCP error rate", value: `${metrics.errorRate.toFixed(1)}%`, icon: ShieldAlert },
  ];
  return (
    <div className="grid grid-cols-4 gap-3">
      {cards.map(({ label, value, icon: Icon, chart }) => (
        <div className="glass-surface min-h-24 p-3" key={label}>
          <div className="flex items-center justify-between text-muted">
            <span className="text-[10px] uppercase tracking-[0.16em]">{label}</span>
            <Icon size={14} />
          </div>
          <div className="mt-3 text-lg font-semibold text-primary">{value}</div>
          {chart && (
            <div className="mt-1 h-6">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={sparkline}><Line dataKey="total" stroke="#06b6d4" dot={false} strokeWidth={1.5} isAnimationActive={false} /></LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
