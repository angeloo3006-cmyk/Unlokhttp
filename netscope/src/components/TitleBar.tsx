import { Minus, Square, X } from "lucide-react";
import { useEffect, useMemo, useRef, type PointerEvent } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { usePacketCapture } from "@/hooks/usePacketCapture";

export function TitleBar() {
  const { isCapturing, stats } = usePacketCapture();
  const appWindow = useMemo(() => (isTauriRuntime() ? getCurrentWindow() : null), []);
  const restoreTimer = useRef<number | null>(null);
  const effectPaused = useRef(false);
  const disablingEffect = useRef(false);
  const suppressResizePauseUntil = useRef(0);

  const restoreWindowEffect = () => {
    if (restoreTimer.current !== null) {
      window.clearTimeout(restoreTimer.current);
      restoreTimer.current = null;
    }

    if (!effectPaused.current) return;
    effectPaused.current = false;
    document.documentElement.classList.remove("window-effect-paused");
  };

  const scheduleVisualFallbackRestore = (delay = 10_000) => {
    if (restoreTimer.current !== null) {
      window.clearTimeout(restoreTimer.current);
    }

    restoreTimer.current = window.setTimeout(restoreWindowEffect, delay);
  };

  const disableWindowEffect = async () => {
    if (effectPaused.current || disablingEffect.current) return;

    disablingEffect.current = true;
    effectPaused.current = true;
    document.documentElement.classList.add("window-effect-paused");

    try {
      if (appWindow) await invoke("set_window_effect", { enabled: false });
    } catch (error) {
      console.warn("disable window effect failed", error);
    } finally {
      disablingEffect.current = false;
    }
  };

  useEffect(() => {
    if (!appWindow) return undefined;

    let unlistenRestored: (() => void) | undefined;
    let unlistenResized: (() => void) | undefined;
    let unlistenMoved: (() => void) | undefined;

    void listen("window_effect_restored", restoreWindowEffect).then((listener) => {
      unlistenRestored = listener;
    });

    const pauseEffectDuringWindowChange = () => {
      if (!effectPaused.current) {
        void disableWindowEffect();
      }
      scheduleVisualFallbackRestore();
    };

    void appWindow.onResized(() => {
      if (Date.now() < suppressResizePauseUntil.current) return;
      pauseEffectDuringWindowChange();
    }).then((listener) => {
      unlistenResized = listener;
    });

    void appWindow.onMoved(() => {
      pauseEffectDuringWindowChange();
    }).then((listener) => {
      unlistenMoved = listener;
    });

    return () => {
      unlistenRestored?.();
      unlistenResized?.();
      unlistenMoved?.();
      if (restoreTimer.current !== null) window.clearTimeout(restoreTimer.current);
      document.documentElement.classList.remove("window-effect-paused");
    };
  }, []);

  const startTitleDrag = async (event: PointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    if (!appWindow) return;

    if (event.detail >= 2) {
      await toggleMaximizeWithoutPausingEffect();
      return;
    }

    await disableWindowEffect();
    scheduleVisualFallbackRestore();
    await appWindow.startDragging();
  };

  const toggleMaximizeWithoutPausingEffect = async () => {
    suppressResizePauseUntil.current = Date.now() + 1_200;
    await appWindow?.toggleMaximize();
    window.setTimeout(() => {
      if (Date.now() >= suppressResizePauseUntil.current) suppressResizePauseUntil.current = 0;
    }, 1_300);
  };

  return (
    <header className="flex h-10 shrink-0 items-center border-b border-glass bg-transparent">
      <div
        className="flex h-full items-center gap-2 px-4 text-[10px] text-secondary"
        onPointerDown={startTitleDrag}
      >
        <span className={isCapturing ? "status-dot bg-emerald-400" : "status-dot bg-white/25"} />
        {isCapturing ? `${stats.pps.toFixed(1)} packets/sec` : "Idle"}
      </div>
      <div className="h-full flex-1" onPointerDown={startTitleDrag} />
      <div className="flex h-full">
        <button className="title-button" onClick={() => appWindow?.minimize()} aria-label="Minimize">
          <Minus size={14} />
        </button>
        <button className="title-button" onClick={() => void toggleMaximizeWithoutPausingEffect()} aria-label="Maximize">
          <Square size={12} />
        </button>
        <button className="title-button hover:bg-red-500/80" onClick={() => appWindow?.close()} aria-label="Close">
          <X size={14} />
        </button>
      </div>
    </header>
  );
}

function isTauriRuntime() {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
