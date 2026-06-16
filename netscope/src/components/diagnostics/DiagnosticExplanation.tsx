import type { Alert } from "@/utils/diagnostics";

interface DiagnosticExplanationProps {
  alert: Alert;
}

const SCORE_LABELS: Array<[string, string]> = [
  ["volume_score", "Volume"],
  ["dispersion_score", "Dispersion"],
  ["asymmetry_score", "Asymmetry"],
  ["persistence_score", "Persistence"],
  ["concentration_score", "Concentration"],
  ["behavior_score", "Behavior"],
  ["size_score", "Packet size"],
  ["throughput_score", "Throughput"],
  ["destination_score", "Destination"],
  ["relative_score", "Relative weight"],
  ["impact_score", "Impact"],
];

const CONTEXT_LABELS: Array<[string, string, (value: number) => string]> = [
  ["sample_multiplier", "Sample multiplier", formatMultiplier],
  ["gateway_penalty", "Gateway penalty", formatMultiplier],
  ["bidirectional_capture", "Bidirectional capture", formatBoolean],
  ["structural_dns_enabled", "Structural DNS enabled", formatBoolean],
  ["identity_checks_enabled", "ARP identity checks", formatBoolean],
  ["correlated_alert", "Correlated alert", formatBoolean],
];

export function DiagnosticExplanation({ alert }: DiagnosticExplanationProps) {
  const scoreItems = SCORE_LABELS
    .map(([key, label]) => ({ key, label, value: alert.metrics[key] }))
    .filter((item): item is { key: string; label: string; value: number } => typeof item.value === "number");

  const contextItems = CONTEXT_LABELS
    .map(([key, label, formatter]) => ({ key, label, value: alert.metrics[key], formatter }))
    .filter((item): item is { key: string; label: string; value: number; formatter: (value: number) => string } => typeof item.value === "number");

  const contributionItems = [
    alert.metrics.contributing_port_scan ? "Possible Port Scan" : null,
    alert.metrics.contributing_tcp_reset_activity ? "Elevated TCP Reset Activity" : null,
    alert.metrics.merged_volume_alert ? "Dominant Host + Heavy Traffic" : null,
  ].filter((value): value is string => Boolean(value));

  return (
    <div className="mt-2 rounded-md border border-white/10 bg-white/[0.03] p-2">
      <p className="mb-2 text-[10px] uppercase tracking-[0.16em] text-muted">Why this alert?</p>

      {scoreItems.length > 0 ? (
        <div className="space-y-1.5">
          {scoreItems.map((item) => (
            <ScoreBar key={item.key} label={item.label} value={item.value} />
          ))}
        </div>
      ) : (
        <p className="text-[11px] text-muted">This alert does not expose score breakdown metrics yet.</p>
      )}

      {contextItems.length > 0 && (
        <div className="mt-3 grid gap-1 text-[11px]">
          {contextItems.map((item) => (
            <div className="flex items-center justify-between gap-3" key={item.key}>
              <span className="text-muted">{item.label}</span>
              <span className="font-mono text-secondary">{item.formatter(item.value)}</span>
            </div>
          ))}
        </div>
      )}

      {contributionItems.length > 0 && (
        <div className="mt-3 rounded-md border border-white/10 bg-black/10 p-2">
          <p className="text-[10px] uppercase tracking-[0.16em] text-muted">Contributing signals</p>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {contributionItems.map((item) => (
              <span className="rounded-full border border-cyan-300/20 bg-cyan-300/10 px-2 py-0.5 text-[10px] text-cyan-100" key={item}>
                {item}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ScoreBar({ label, value }: { label: string; value: number }) {
  const percent = Math.min(100, Math.max(0, value * 100));

  return (
    <div className="grid grid-cols-[92px_1fr_42px] items-center gap-2 text-[11px]">
      <span className="text-muted">{label}</span>
      <div className="h-1.5 overflow-hidden rounded-full bg-white/5">
        <div className="h-full rounded-full bg-cyan-300/70" style={{ width: `${percent}%` }} />
      </div>
      <span className="text-right font-mono text-secondary">{percent.toFixed(0)}%</span>
    </div>
  );
}

function formatMultiplier(value: number) {
  return `${value.toFixed(2)}x`;
}

function formatBoolean(value: number) {
  return value ? "yes" : "no";
}
