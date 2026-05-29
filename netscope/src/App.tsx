import { AppStateProvider, useAppState } from "@/store";
import { useTauriEvents } from "@/hooks/useTauriEvents";
import { Titlebar }        from "@/components/layout/Titlebar";
import { Sidebar }         from "@/components/layout/Sidebar";
import { ErrorBanner }     from "@/components/ui/ErrorBanner";
import { CaptureView }     from "@/components/capture/CaptureView";
import { PacketsView }     from "@/components/packets/PacketsView";
import { DiagnosticsView } from "@/components/diagnostics/DiagnosticsView";
import { SessionsView }    from "@/components/capture/SessionsView";

function Shell() {
  useTauriEvents();
  const { state } = useAppState();

  const view = {
    capture:     <CaptureView />,
    packets:     <PacketsView />,
    diagnostics: <DiagnosticsView />,
    sessions:    <SessionsView />,
  }[state.view];

  return (
    <div className="flex flex-col h-screen bg-background text-foreground overflow-hidden scanlines relative">
      <Titlebar />
      <ErrorBanner />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-hidden animate-fadein">
          {view}
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AppStateProvider>
      <Shell />
    </AppStateProvider>
  );
}
