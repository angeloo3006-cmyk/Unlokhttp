import { useState } from "react";
import { Group, Panel, Separator } from "react-resizable-panels";
import { TitleBar } from "@/components/TitleBar";
import { Sidebar, type AppView } from "@/components/Sidebar";
import { CaptureView } from "@/views/CaptureView";
import { DiagnosticsView } from "@/views/DiagnosticsView";
import { SessionsView } from "@/views/SessionsView";
import { usePacketCapture } from "@/hooks/usePacketCapture";

export function Layout() {
  const [view, setView] = useState<AppView>("capture");
  const [sidebarCompact, setSidebarCompact] = useState(false);
  const capture = usePacketCapture();

  return (
    <div className="app-glass-shell flex h-screen flex-col overflow-hidden bg-transparent text-primary">
      <TitleBar />
      {capture.error && (
        <button className="border-b border-red-300/15 bg-red-500/15 px-3 py-1 text-left text-xs text-red-100" onClick={() => capture.setError(null)}>
          {capture.error}
        </button>
      )}
      <Group orientation="horizontal" className="min-h-0 flex-1">
        <Panel
          id="app-sidebar"
          className="py-3 pl-3"
          defaultSize="180px"
          minSize="58px"
          maxSize="240px"
          collapsible
          collapsedSize="58px"
          onResize={(size) => setSidebarCompact(size.inPixels < 110)}
        >
          <Sidebar
            activeView={view}
            interfaces={capture.interfaces}
            selectedInterfaceId={capture.selectedInterfaceId}
            captureActive={capture.isCapturing}
            compact={sidebarCompact}
            onViewChange={setView}
            onInterfaceSelect={capture.setSelectedInterfaceId}
          />
        </Panel>
        <HorizontalResizeHandle />
        <Panel id="app-main" minSize={55}>
          <main className="h-full min-w-0">
            {view === "capture" && <CaptureView />}
            {view === "diagnostics" && <DiagnosticsView />}
            {view === "sessions" && <SessionsView />}
            {view === "settings" && <Placeholder title="Settings" text="Capture preferences and sidecar configuration live here." />}
          </main>
        </Panel>
      </Group>
    </div>
  );
}

function Placeholder({ title, text }: { title: string; text: string }) {
  return <div className="glass-panel m-3 p-6"><h1 className="text-lg font-semibold">{title}</h1><p className="mt-2 text-sm text-secondary">{text}</p></div>;
}

function HorizontalResizeHandle() {
  return (
    <Separator className="resize-handle resize-handle-x">
      <span />
    </Separator>
  );
}
