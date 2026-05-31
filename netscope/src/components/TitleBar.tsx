import { Minus, Square, X } from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { usePacketCapture } from "@/hooks/usePacketCapture";

const appWindow = getCurrentWindow();

export function TitleBar() {
  const { isCapturing, stats } = usePacketCapture();

  return (
    <header
      data-tauri-drag-region
      className="flex h-10 shrink-0 items-center border-b border-glass bg-transparent"
    >
      <div data-tauri-drag-region className="flex items-center gap-2 px-4 text-[10px] text-secondary">
        <span className={isCapturing ? "status-dot bg-emerald-400" : "status-dot bg-white/25"} />
        {isCapturing ? `${stats.pps.toFixed(1)} packets/sec` : "Idle"}
      </div>
      <div data-tauri-drag-region className="flex-1" />
      <div className="flex h-full">
        <button className="title-button" onClick={() => appWindow.minimize()} aria-label="Minimize">
          <Minus size={14} />
        </button>
        <button className="title-button" onClick={() => appWindow.toggleMaximize()} aria-label="Maximize">
          <Square size={12} />
        </button>
        <button className="title-button hover:bg-red-500/80" onClick={() => appWindow.close()} aria-label="Close">
          <X size={14} />
        </button>
      </div>
    </header>
  );
}
