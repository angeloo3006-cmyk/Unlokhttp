import { useCallback } from "react";
import { Trash2, BarChart2, Table2, Play } from "lucide-react";
import { deleteSession, listSessions } from "@/lib/tauri";
import { useAppState } from "@/store";
import type { Session } from "@/lib/tauri";

function fmt(ts: string | null) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString(undefined, {
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

export function SessionsView() {
  const { state, dispatch } = useAppState();

  const handleDelete = useCallback(async (id: number) => {
    if (!confirm(`Delete session #${id}? This removes all captured packets.`)) return;
    try {
      await deleteSession(id);
      const sessions = await listSessions();
      dispatch({ type: "SET_SESSIONS", payload: sessions });
    } catch (e) {
      dispatch({ type: "SET_ERROR", payload: String(e) });
    }
  }, [dispatch]);

  const goPackets = (id: number) => {
    dispatch({ type: "SET_VIEW", payload: "packets" });
  };

  const goDiag = (id: number) => {
    dispatch({ type: "SET_VIEW", payload: "diagnostics" });
  };

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-4 py-2 border-b border-dim bg-surface shrink-0 flex items-center">
        <span className="section-title">Recorded Sessions</span>
        <span className="ml-3 text-[10px] font-mono text-subtle">
          {state.sessions.length} sessions
        </span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {state.sessions.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 gap-3 text-subtle">
            <Play size={24} strokeWidth={1} />
            <span className="font-mono text-sm">No recorded sessions yet.</span>
            <span className="text-[11px] font-mono">Start a capture to create one.</span>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 48 }}>#</th>
                <th>Name</th>
                <th style={{ width: 120 }}>Interface</th>
                <th style={{ width: 160 }}>Started</th>
                <th style={{ width: 160 }}>Ended</th>
                <th style={{ width: 90 }}>Packets</th>
                <th style={{ width: 110 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {state.sessions.map((s: Session) => (
                <tr key={s.id}>
                  <td className="text-subtle">{s.id}</td>
                  <td>
                    <span className="text-foreground">{s.name ?? <span className="text-subtle italic">Unnamed</span>}</span>
                    {s.id === state.sessionId && (
                      <span className="ml-2 badge text-[9px] bg-accent/15 text-accent">LIVE</span>
                    )}
                  </td>
                  <td className="font-mono text-muted-foreground">{s.interface ?? "—"}</td>
                  <td className="text-subtle tabular-nums text-[11px]">{fmt(s.started_at)}</td>
                  <td className="text-subtle tabular-nums text-[11px]">{fmt(s.ended_at)}</td>
                  <td className="tabular-nums text-foreground font-mono">
                    {s.total_packets.toLocaleString()}
                  </td>
                  <td>
                    <div className="flex items-center gap-1">
                      <button
                        title="Browse packets"
                        onClick={() => goPackets(s.id)}
                        className="btn-ghost px-1.5 py-1"
                      >
                        <Table2 size={11} />
                      </button>
                      <button
                        title="View diagnostics"
                        onClick={() => goDiag(s.id)}
                        className="btn-ghost px-1.5 py-1"
                      >
                        <BarChart2 size={11} />
                      </button>
                      <button
                        title="Delete session"
                        onClick={() => handleDelete(s.id)}
                        disabled={s.id === state.sessionId}
                        className="btn-ghost px-1.5 py-1 text-danger hover:text-danger disabled:opacity-30"
                      >
                        <Trash2 size={11} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
