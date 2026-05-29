import { useAppState } from "@/store";

function fmt(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000)     return (n / 1_000).toFixed(1) + "K";
  return n.toString();
}

export function StatCards() {
  const { state } = useAppState();
  const { stats } = state;

  const cards = [
    { label: "Packets/s",  value: stats.rate_pps.toFixed(1), accent: true },
    { label: "Captured",   value: fmt(stats.captured) },
    { label: "Dropped",    value: fmt(stats.dropped), danger: stats.dropped > 0 },
    { label: "Live buffer",value: fmt(state.livePackets.length) },
  ];

  return (
    <div className="flex shrink-0">
      {cards.map(({ label, value, accent, danger }) => (
        <div key={label} className="stat-card border-r border-dim rounded-none w-36">
          <span className="section-title">{label}</span>
          <span className={
            `font-ui text-xl font-700 tabular-nums ` +
            (accent ? "text-accent" : danger ? "text-danger" : "text-foreground")
          }>
            {value}
          </span>
        </div>
      ))}
    </div>
  );
}
