import { useState } from "react";
import { TitleBar } from "@/components/TitleBar";
import { Sidebar, type AppView } from "@/components/Sidebar";
import { CaptureView } from "@/views/CaptureView";
import { DiagnosticsView } from "@/views/DiagnosticsView";
import { SessionsView } from "@/views/SessionsView";
import { usePacketCapture } from "@/hooks/usePacketCapture";

export function Layout() {
  const [view, setView] = useState<AppView>("capture");
  const capture = usePacketCapture();

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-transparent text-primary">
      <TitleBar />
      {capture.error && (
        <button className="border-b border-red-300/15 bg-red-500/15 px-3 py-1 text-left text-xs text-red-100" onClick={() => capture.setError(null)}>
          {capture.error}
        </button>
      )}
      <div className="flex min-h-0 flex-1">
        <Sidebar
          activeView={view}
          interfaces={capture.interfaces}
          selectedInterfaceId={capture.selectedInterfaceId}
          captureActive={capture.isCapturing}
          onViewChange={setView}
          onInterfaceSelect={capture.setSelectedInterfaceId}
        />
        <main className="min-w-0 flex-1">
          {view === "capture" && <CaptureView />}
          {view === "diagnostics" && <DiagnosticsView />}
          {view === "sessions" && <SessionsView />}
          {view === "settings" && <Placeholder title="Settings" text="Capture preferences and sidecar configuration live here." />}
        </main>
      </div>
    </div>
  );
}

function Placeholder({ title, text }: { title: string; text: string }) {
  return <div className="glass-panel m-3 p-6"><h1 className="text-lg font-semibold">{title}</h1><p className="mt-2 text-sm text-secondary">{text}</p></div>;
}
