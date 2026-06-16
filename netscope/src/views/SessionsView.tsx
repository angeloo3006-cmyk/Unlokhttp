import { useCallback, useEffect, useMemo, useState } from "react";
import { Group, Panel, Separator } from "react-resizable-panels";
import { SessionList } from "@/components/sessions/SessionList";
import { deleteSession, listInterfaces, listSessions, type Interface, type Session } from "@/lib/tauri";
import { SessionDetailView } from "@/views/SessionDetailView";

export function SessionsView() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [interfaces, setInterfaces] = useState<Interface[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sessionsCompact, setSessionsCompact] = useState(false);

  const selectedSession = useMemo(
    () => sessions.find((session) => session.id === selectedSessionId) ?? null,
    [selectedSessionId, sessions],
  );

  const loadSessions = useCallback(async () => {
    try {
      setError(null);
      const [data, interfaceData] = await Promise.all([
        listSessions(),
        listInterfaces().catch(() => ({ interfaces: [], refreshed: false })),
      ]);
      setSessions(data);
      setInterfaces(interfaceData.interfaces);
      setSelectedSessionId((current) => {
        if (current && data.some((session) => session.id === current)) return current;
        return data[0]?.id ?? null;
      });
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    void loadSessions();
  }, [loadSessions]);

  const handleDeleteSession = async (sessionId: number) => {
    try {
      setError(null);
      await deleteSession(sessionId);
      setSelectedSessionId(null);
      await loadSessions();
    } catch (err) {
      setError(String(err));
    }
  };

  return (
    <div className="h-full min-h-0 p-3">
      <Group orientation="horizontal" className="h-full min-h-0">
        <Panel
          id="sessions-sidebar"
          defaultSize="220px"
          minSize="64px"
          maxSize="320px"
          collapsible
          collapsedSize="64px"
          onResize={(size) => setSessionsCompact(size.inPixels < 140)}
        >
          <SessionList
            sessions={sessions}
            interfaces={interfaces}
            selectedSessionId={selectedSessionId}
            compact={sessionsCompact}
            onSelect={setSelectedSessionId}
            onRefresh={() => void loadSessions()}
          />
        </Panel>
        <HorizontalResizeHandle />
        <Panel id="sessions-detail" minSize={52}>
          <div className="flex h-full min-w-0 flex-col gap-2 pl-3">
            {error && (
              <button
                className="rounded-lg border border-red-300/15 bg-red-500/10 p-2 text-left text-xs text-red-100"
                onClick={() => setError(null)}
              >
                {error}
              </button>
            )}
            <SessionDetailView
              session={selectedSession}
              interfaces={interfaces}
              onRefreshSessions={() => void loadSessions()}
              onDeleteSession={handleDeleteSession}
            />
          </div>
        </Panel>
      </Group>
    </div>
  );
}

function HorizontalResizeHandle() {
  return (
    <Separator className="resize-handle resize-handle-x">
      <span />
    </Separator>
  );
}
