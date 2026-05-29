import { AreaChart, Area, ResponsiveContainer, Tooltip, YAxis } from "recharts";
import { useAppState } from "@/store";

export function MiniChart() {
  const { state } = useAppState();

  const data = state.statsHistory.map((s, i) => ({
    i,
    rate: s.rate_pps,
  }));

  if (data.length < 2) {
    return (
      <div className="flex items-center justify-center h-full text-subtle text-[10px] font-mono">
        Waiting for data…
      </div>
    );
  }

  return (
    <div className="relative h-full w-full px-2 py-1">
      <span className="section-title absolute top-2 left-3 z-10">Rate (pps)</span>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 18, right: 4, bottom: 4, left: 0 }}>
          <defs>
            <linearGradient id="rateGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor="hsl(174 100% 44%)" stopOpacity={0.3} />
              <stop offset="95%" stopColor="hsl(174 100% 44%)" stopOpacity={0.01} />
            </linearGradient>
          </defs>
          <YAxis hide domain={[0, "auto"]} />
          <Tooltip
            content={({ active, payload }) =>
              active && payload?.length ? (
                <div className="panel px-2 py-1 text-[10px] font-mono text-accent">
                  {payload[0].value?.toString()} pps
                </div>
              ) : null
            }
          />
          <Area
            type="monotone"
            dataKey="rate"
            stroke="hsl(174 100% 44%)"
            strokeWidth={1.5}
            fill="url(#rateGrad)"
            dot={false}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
