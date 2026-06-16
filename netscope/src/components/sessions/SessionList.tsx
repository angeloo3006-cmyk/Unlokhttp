import { Database, RefreshCw } from "lucide-react";
import { interfaceDisplayName } from "@/lib/interfaces";
import type { Interface, Session } from "@/lib/tauri";
import { getSessionStatusColor } from "@/utils/status";

interface SessionListProps {
  sessions: Session[];
  interfaces: Interface[];
  selectedSessionId: number | null;
  compact?: boolean;
  onSelect: (sessionId: number) => void;
  onRefresh: () => void;
}

export function SessionList({ sessions, interfaces, selectedSessionId, compact = false, onSelect, onRefresh }: SessionListProps) {
  return (
    <aside className={`glass-panel container-inline flex h-full flex-col overflow-hidden ${compact ? "items-center" : ""}`}>
      <div className={`flex w-full items-center justify-between border-b border-glass ${compact ? "p-2" : "p-3"}`}>
        {!compact ? (
          <div>
            <h1 className="text-fluid-title mt-1 font-semibold">Saved captures</h1>
          </div>
        ) : (
          <Database className="mx-auto text-secondary" size={16} />
        )}
        <button className={compact ? "button-icon" : "button-ghost px-2"} onClick={onRefresh}>
          <RefreshCw size={13} />
        </button>
      </div>

      <div className={`min-h-0 flex-1 overflow-auto ${compact ? "w-full p-2" : "p-2"}`}>
        {sessions.length ? (
          sessions.map((session, index) => (
            <button
              className={`mb-2 w-full rounded-lg border text-left transition ${
                compact ? "flex h-10 items-center justify-center p-0" : "p-3"
              } ${
                selectedSessionId === session.id
                  ? "border-blue-400/35 bg-blue-500/12"
                  : "border-white/5 bg-white/[0.025] hover:bg-white/[0.055]"
              }`}
              key={session.id}
              onClick={() => onSelect(session.id)}
              title={session.name ?? `Session #${session.id}`}
            >
              {compact ? (
                <div className="flex items-center gap-2">
                  <span className={`h-1 w-1 rounded-full ${getSessionStatusColor(session)}`} />
                  <span className="text-fluid-label text-muted">{index + 1}</span>
                </div>
              ) : (
                <>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-fluid-body truncate font-semibold">{session.name ?? `Session #${session.id}`}</span>
                    <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${getSessionStatusColor(session)}`} title={`Session ${session.id}`} />
                  </div>
                  <p className="text-fluid-body mt-1 flex items-center gap-1.5 truncate text-secondary">
                    <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-white/25" />
                    {interfaceDisplayName(session.interface, interfaces)}
                  </p>
                  <div className="text-fluid-label mt-3 grid grid-cols-2 gap-2 text-muted">
                    <span>{formatSessionDate(session.started_at)}</span>
                    <span className="text-right">{session.total_packets.toLocaleString()} packets</span>
                  </div>
                </>
              )}
            </button>
          ))
        ) : (
          compact ? (
            <div className="flex justify-center p-2">
              <span className="h-1.5 w-1.5 rounded-full bg-white/20" title="No saved sessions yet." />
            </div>
          ) : (
            <div className="p-4 text-xs text-secondary">
              No saved sessions yet. Start and stop a capture to persist packets in SQLite.
            </div>
          )
        )}
      </div>
    </aside>
  );
}

function formatSessionDate(value: string | null) {
  if (!value) return "No date";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString([], {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}
