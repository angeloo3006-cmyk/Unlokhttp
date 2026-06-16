import { useState } from "react";
import { AlertCircle, CheckCircle2, ChevronDown, Info } from "lucide-react";
import type { Alert } from "@/utils/diagnostics";
import { DiagnosticExplanation } from "@/components/diagnostics/DiagnosticExplanation";

interface DiagnosticAlertCardProps {
  alert: Alert;
}

export function DiagnosticAlertCard({ alert }: DiagnosticAlertCardProps) {
  const [showExplanation, setShowExplanation] = useState(false);
  const Icon = alert.level === "success" ? CheckCircle2 : alert.level === "warning" || alert.level === "critical" ? AlertCircle : Info;

  return (
    <div className={`alert-${alert.level} rounded-lg border p-2 text-xs`}>
      <div className="flex gap-2">
        <Icon className="mt-0.5 shrink-0" size={14} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold text-primary">{alert.title}</span>
            <span className="rounded-full border border-white/10 px-1.5 py-0.5 text-[10px] text-secondary">
              {signalLabel(alert.confidence)}
            </span>
            {typeof alert.metrics.impact_score === "number" && (
              <span className="rounded-full border border-white/10 px-1.5 py-0.5 text-[10px] text-muted">
                Impact {(alert.metrics.impact_score * 100).toFixed(0)}%
              </span>
            )}
          </div>

          <p className="mt-1 text-secondary">{alert.message}</p>

          {alert.evidence.length > 0 && (
            <ul className="mt-2 space-y-1 text-[11px] text-secondary">
              {alert.evidence.slice(0, 4).map((item) => (
                <li className="flex gap-1.5" key={item}>
                  <span className="mt-1 h-1 w-1 shrink-0 rounded-full bg-current opacity-60" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          )}

          <p className="mt-2 text-[11px] text-muted">{alert.recommendation}</p>

          <button
            className="mt-2 inline-flex items-center gap-1 rounded-md border border-white/10 px-2 py-1 text-[11px] text-cyan-100 transition hover:bg-white/5"
            onClick={() => setShowExplanation((value) => !value)}
            type="button"
          >
            <ChevronDown className={`transition ${showExplanation ? "rotate-180" : ""}`} size={12} />
            {showExplanation ? "Hide explanation" : "Why this alert?"}
          </button>

          {showExplanation && <DiagnosticExplanation alert={alert} />}
        </div>
      </div>
    </div>
  );
}

function signalLabel(value: number) {
  if (value >= 0.78) return "Very strong signal";
  if (value >= 0.58) return "Strong signal";
  if (value >= 0.38) return "Moderate signal";
  return "Low signal";
}
