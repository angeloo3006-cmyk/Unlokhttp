import { getCurrentWindow } from "@tauri-apps/api/window";
import { Minus, Square, X, Activity } from "lucide-react";
import { useAppState } from "@/store";
import { cn } from "@/lib/utils";

const appWin = getCurrentWindow();

export function Titlebar() {
  const { state } = useAppState();

  return (
    <div
      data-tauri-drag-region
      className="flex items-center h-9 bg-surface border-b border-dim select-none shrink-0 z-50"
    >
      {/* Logo */}
      <div className="flex items-center gap-2 px-4 pr-6" data-tauri-drag-region>
        <Activity size={14} className="text-accent" strokeWidth={2.5} />
        <span className="font-ui text-xs font-700 tracking-widest uppercase text-foreground">
          Net<span className="text-accent">scope</span>
        </span>
      </div>

      {/* Capture status indicator */}
      <div className="flex items-center gap-1.5" data-tauri-drag-region>
        <span className={cn(
          "pulse-dot",
          !state.isCapturing && "opacity-0"
        )} />
        {state.isCapturing && (
          <span className="text-accent text-[10px] font-mono tracking-widest uppercase animate-fadein">
            capturing
          </span>
        )}
      </div>

      {/* Spacer */}
      <div className="flex-1" data-tauri-drag-region />

      {/* Stats strip */}
      {state.isCapturing && (
        <div className="flex items-center gap-4 px-4 text-[10px] font-mono text-subtle">
          <span>
            <span className="text-accent">{state.stats.rate_pps.toFixed(1)}</span>
            {" "}pps
          </span>
          <span>
            <span className="text-foreground">{state.stats.captured.toLocaleString()}</span>
            {" "}pkts
          </span>
          {state.stats.dropped > 0 && (
            <span className="text-danger">
              {state.stats.dropped} dropped
            </span>
          )}
        </div>
      )}

      {/* Window controls */}
      <div className="flex items-center">
        <button
          onClick={() => appWin.minimize()}
          className="h-9 w-10 flex items-center justify-center text-subtle hover:text-foreground hover:bg-surface-raised transition-colors"
        >
          <Minus size={12} />
        </button>
        <button
          onClick={() => appWin.toggleMaximize()}
          className="h-9 w-10 flex items-center justify-center text-subtle hover:text-foreground hover:bg-surface-raised transition-colors"
        >
          <Square size={11} />
        </button>
        <button
          onClick={() => appWin.close()}
          className="h-9 w-10 flex items-center justify-center text-subtle hover:text-white hover:bg-danger transition-colors"
        >
          <X size={12} />
        </button>
      </div>
    </div>
  );
}
