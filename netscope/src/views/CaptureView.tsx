import { Group, Panel, Separator } from "react-resizable-panels";
import { HexViewer } from "@/components/HexViewer";
import { PacketDetail } from "@/components/PacketDetail";
import { PacketList } from "@/components/PacketList";
import { Toolbar } from "@/components/Toolbar";
import { useFilteredPackets } from "@/hooks/useFilteredPackets";
import { usePacketCapture } from "@/hooks/usePacketCapture";
import { useFiltersStore } from "@/store/filters";

export function CaptureView() {
  const capture = usePacketCapture();
  const filters = useFiltersStore();
  const packets = useFilteredPackets(capture.packets, filters);

  return (
    <div className="flex h-full flex-col">
      <Toolbar packets={packets} filteredCount={packets.length} />
      <div className="glass-panel m-3 min-h-0 flex-1 overflow-hidden">
        <Group orientation="vertical">
          <Panel defaultSize="55%" minSize="24%">
            <PacketList
              packets={packets}
              filters={filters}
              selectedPacket={capture.selectedPacket}
              onSelectPacket={capture.setSelectedPacket}
            />
          </Panel>
          <ResizeHandle />
          <Panel defaultSize="25%" minSize="12%">
            <PacketDetail selectedPacket={capture.selectedPacket} />
          </Panel>
          <ResizeHandle />
          <Panel defaultSize="20%" minSize="10%">
            <HexViewer
              payload_hex={capture.selectedPacket?.payload_hex ?? ""}
              raw_ascii={capture.selectedPacket?.raw_ascii ?? ""}
            />
          </Panel>
        </Group>
      </div>
    </div>
  );
}

function ResizeHandle() {
  return (
    <Separator className="group flex h-1 cursor-row-resize items-center justify-center bg-transparent">
      <span className="h-px w-full bg-white/5 transition group-hover:bg-cyan-400/70" />
    </Separator>
  );
}
