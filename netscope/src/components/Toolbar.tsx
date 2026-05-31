import { useState } from "react";
import { Download, Filter, Play, Square, Trash2, X } from "lucide-react";
import { FilterModal } from "@/components/FilterModal";
import { usePacketCapture } from "@/hooks/usePacketCapture";
import { setBpfFilter, startCapture, stopCapture } from "@/lib/tauri";
import { countActiveFilters, useFiltersStore } from "@/store/filters";
import type { Packet } from "@/types/packet";

const QUICK_FILTERS = ["tcp", "udp", "port 53", "tcp port 80"];

export function Toolbar({ packets, filteredCount }: { packets: Packet[]; filteredCount: number }) {
  const capture = usePacketCapture();
  const filters = useFiltersStore();
  const [bpfInput, setBpfInput] = useState("");
  const [activeBpf, setActiveBpf] = useState("");
  const [modalOpen, setModalOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const activeFilterCount = countActiveFilters(filters);

  const handleCapture = async () => {
    setBusy(true);
    try {
      if (capture.isCapturing) {
        await stopCapture();
        capture.setIsCapturing(false);
        capture.setSessionId(null);
      } else {
        capture.clearPackets();
        const selected = capture.interfaces.find(
          (networkInterface) => networkInterface.id === capture.selectedInterfaceId,
        );
        const sessionId = await startCapture({
          interfaceId: selected?.id ?? 0,
          interfaceName: selected?.name ?? "interface-0",
          sessionName: `Capture ${new Date().toLocaleString()}`,
        });
        capture.setSessionId(sessionId);
        capture.setIsCapturing(true);
      }
    } catch (error) {
      capture.setError(String(error));
    } finally {
      setBusy(false);
    }
  };

  const applyBpf = async (next = bpfInput) => {
    try {
      await setBpfFilter(next);
      setActiveBpf(next);
      setBpfInput(next);
    } catch (error) {
      capture.setError(String(error));
    }
  };

  const exportCsv = () => {
    const header = "id,ts,source,destination,protocol,length,ttl,flags\n";
    const rows = packets.map((packet) =>
      [
        packet.id,
        packet.ts,
        packet.src_ip,
        packet.dst_ip,
        packet.protocol,
        packet.length,
        packet.ttl,
        packet.flags,
      ]
        .map((value) => `"${String(value ?? "").replace(/"/g, '""')}"`)
        .join(","),
    );
    const href = URL.createObjectURL(new Blob([header, rows.join("\n")], { type: "text/csv" }));
    const link = document.createElement("a");
    link.href = href;
    link.download = "netscope-capture.csv";
    link.click();
    URL.revokeObjectURL(href);
  };

  const selectedInterface = capture.interfaces.find(
    (networkInterface) => networkInterface.id === capture.selectedInterfaceId,
  );

  return (
    <>
      <div className="glass-panel m-3 mb-0 flex min-h-14 flex-wrap items-center gap-2 px-3 py-2">
        <button
          className={capture.isCapturing ? "button-danger" : "button-success"}
          disabled={busy}
          onClick={handleCapture}
        >
          {capture.isCapturing ? <Square size={13} /> : <Play size={13} />}
          {capture.isCapturing ? "Stop" : "Start"}
        </button>
        <span className="rounded-full border border-cyan-300/15 bg-cyan-400/10 px-2 py-1 text-[11px] text-cyan-200">
          {capture.stats.pps.toFixed(1)} packets/sec
        </span>
        <span className="text-[11px] text-secondary">
          {filteredCount.toLocaleString()} / {packets.length.toLocaleString()} packets
        </span>
        <form
          className="flex min-w-[280px] flex-1 gap-1"
          onSubmit={(event) => {
            event.preventDefault();
            void applyBpf();
          }}
        >
          <input
            className="glass-input"
            value={bpfInput}
            onChange={(event) => setBpfInput(event.target.value)}
            placeholder="Filter: tcp port 80 or udp"
          />
          <button className="button-ghost" type="submit">
            Apply
          </button>
        </form>
        <button className="button-ghost" onClick={exportCsv}>
          <Download size={13} /> Export CSV
        </button>
        <button className="button-ghost" onClick={capture.clearPackets}>
          <Trash2 size={13} /> Clear
        </button>
        <button className="button-ghost relative" onClick={() => setModalOpen(true)}>
          <Filter size={13} /> Advanced
          {activeFilterCount > 0 && (
            <span className="absolute -right-1 -top-1 rounded-full bg-red-500 px-1 text-[9px] text-white">
              {activeFilterCount}
            </span>
          )}
        </button>
        <div className="flex w-full items-center gap-2 text-[10px]">
          <span className={capture.isCapturing ? "text-emerald-300" : "text-muted"}>
            <span
              className={`mr-1 inline-block size-1.5 rounded-full ${
                capture.isCapturing ? "bg-emerald-300" : "border border-white/35"
              }`}
            />
            {capture.isCapturing ? `Capturing on ${selectedInterface?.name ?? "interface-0"}` : "Idle"}
          </span>
          {QUICK_FILTERS.map((filter) => (
            <button className="quick-chip" key={filter} onClick={() => void applyBpf(filter)}>
              {filter.toUpperCase()}
            </button>
          ))}
          {activeBpf && (
            <button className="filter-chip filter-chip-active ml-auto" onClick={() => void applyBpf("")}>
              {activeBpf}
              <X size={11} />
            </button>
          )}
        </div>
      </div>
      <FilterModal open={modalOpen} onOpenChange={setModalOpen} />
    </>
  );
}
