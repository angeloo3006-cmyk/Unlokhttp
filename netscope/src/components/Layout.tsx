import { useState } from "react";
import { Group, Panel, Separator } from "react-resizable-panels";
import { TitleBar } from "@/components/TitleBar";
import { Sidebar, type AppView } from "@/components/Sidebar";
import { Toolbar } from "@/components/Toolbar";
import { PacketList } from "@/components/PacketList";
import { PacketDetail } from "@/components/PacketDetail";
import { HexViewer } from "@/components/HexViewer";
import { DiagnosticsView } from "@/views/DiagnosticsView";
import { usePacketCapture } from "@/hooks/usePacketCapture";
import { useFilteredPackets } from "@/hooks/useFilteredPackets";
import { useFiltersStore } from "@/store/filters";

export function Layout() {
  const [view, setView] = useState<AppView>("capture");
  const capture = usePacketCapture();
  const filters = useFiltersStore();
  const packets = useFilteredPackets(capture.packets, filters);

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
          {view === "capture" && (
            <div className="flex h-full flex-col">
              <Toolbar packets={packets} filteredCount={packets.length} />
              <div className="glass-panel m-3 min-h-0 flex-1 overflow-hidden">
                <Group orientation="vertical">
                  <Panel defaultSize="55%" minSize="24%">
                    <PacketList packets={packets} filters={filters} selectedPacket={capture.selectedPacket} onSelectPacket={capture.setSelectedPacket} />
                  </Panel>
                  <ResizeHandle />
                  <Panel defaultSize="25%" minSize="12%">
                    <PacketDetail selectedPacket={capture.selectedPacket} />
                  </Panel>
                  <ResizeHandle />
                  <Panel defaultSize="20%" minSize="10%">
                    <HexViewer payload_hex={capture.selectedPacket?.payload_hex ?? ""} raw_ascii={capture.selectedPacket?.raw_ascii ?? ""} />
                  </Panel>
                </Group>
              </div>
            </div>
          )}
          {view === "diagnostics" && <DiagnosticsView />}
          {view === "sessions" && <Placeholder title="Sessions" text="Captured sessions are persisted in netscope.db and ready for the historical browser." />}
          {view === "settings" && <Placeholder title="Settings" text="Capture preferences and sidecar configuration live here." />}
        </main>
      </div>
    </div>
  );
}

function ResizeHandle() {
  return <Separator className="group flex h-1 cursor-row-resize items-center justify-center bg-transparent"><span className="h-px w-full bg-white/5 transition group-hover:bg-cyan-400/70" /></Separator>;
}

function Placeholder({ title, text }: { title: string; text: string }) {
  return <div className="glass-panel m-3 p-6"><h1 className="text-lg font-semibold">{title}</h1><p className="mt-2 text-sm text-secondary">{text}</p></div>;
}
