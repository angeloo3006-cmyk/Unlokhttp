import { useState, useCallback } from "react";
import {
  Play, Square, Filter, RefreshCw, Trash2, ChevronDown,
} from "lucide-react";
import {
  startCapture, stopCapture, setBpfFilter,
  listInterfaces, listSessions,
} from "@/lib/tauri";
import { useAppState } from "@/store";
import { Spinner } from "@/components/ui/Spinner";
import { LivePacketFeed } from "@/components/capture/LivePacketFeed";
import { StatCards } from "@/components/capture/StatCards";
import { MiniChart } from "@/components/capture/MiniChart";

export function CaptureView() {
  const { state, dispatch } = useAppState();
  const [bpfInput, setBpfInput]   = useState("");
  const [filterOpen, setFilterOpen] = useState(false);
  const [starting, setStarting]   = useState(false);

  const handleStart = useCallback(async () => {
    if (starting || state.isCapturing) return;
    setStarting(true);
    try {
      dispatch({ type: "CLEAR_PACKETS" });
      const sid = await startCapture({
        interfaceId:   state.selectedIface,
        interfaceName: state.interfaces[state.selectedIface]?.name,
        sessionName:   `Session ${new Date().toLocaleTimeString()}`,
      });
      dispatch({ type: "SET_SESSION_ID",  payload: sid });
      dispatch({ type: "SET_CAPTURING",   payload: true });
      // Refresh sessions list
      const sessions = await listSessions();
      dispatch({ type: "SET_SESSIONS",    payload: sessions });
    } catch (e) {
      dispatch({ type: "SET_ERROR", payload: String(e) });
    } finally {
      setStarting(false);
    }
  }, [state.isCapturing, state.selectedIface, state.interfaces, starting, dispatch]);

  const handleStop = useCallback(async () => {
    try {
      await stopCapture();
      dispatch({ type: "SET_CAPTURING",  payload: false });
      dispatch({ type: "SET_SESSION_ID", payload: null });
      const sessions = await listSessions();
      dispatch({ type: "SET_SESSIONS",   payload: sessions });
    } catch (e) {
      dispatch({ type: "SET_ERROR", payload: String(e) });
    }
  }, [dispatch]);

  const handleApplyFilter = useCallback(async () => {
    try {
      await setBpfFilter(bpfInput);
      dispatch({ type: "SET_BPF", payload: bpfInput });
    } catch (e) {
      dispatch({ type: "SET_ERROR", payload: String(e) });
    }
  }, [bpfInput, dispatch]);

  const handleRefreshIfaces = useCallback(async () => {
    try {
      const { interfaces } = await listInterfaces();
      dispatch({ type: "SET_INTERFACES", payload: interfaces });
    } catch (e) {
      dispatch({ type: "SET_ERROR", payload: String(e) });
    }
  }, [dispatch]);

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* ── Toolbar ─────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-dim bg-surface shrink-0">

        {/* Interface selector */}
        <div className="relative">
          <select
            disabled={state.isCapturing}
            value={state.selectedIface}
            onChange={(e) =>
              dispatch({ type: "SET_IFACE", payload: Number(e.target.value) })
            }
            className="input pr-7 appearance-none cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed w-52"
          >
            {state.interfaces.length === 0 ? (
              <option value={0}>No interfaces found</option>
            ) : (
              state.interfaces.map((iface) => (
                <option key={iface.id} value={iface.id}>
                  {iface.name}
                  {iface.desc ? ` — ${iface.desc.slice(0, 28)}` : ""}
                </option>
              ))
            )}
          </select>
          <ChevronDown
            size={10}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-subtle pointer-events-none"
          />
        </div>

        <button
          onClick={handleRefreshIfaces}
          disabled={state.isCapturing}
          title="Refresh interfaces"
          className="btn-ghost px-2 disabled:opacity-40"
        >
          <RefreshCw size={12} />
        </button>

        <div className="h-4 w-px bg-border-dim mx-1" />

        {/* BPF filter toggle */}
        <button
          onClick={() => setFilterOpen((v) => !v)}
          className={`btn-outline gap-1.5 ${state.bpfFilter ? "text-accent border-accent/40" : ""}`}
        >
          <Filter size={11} />
          {state.bpfFilter
            ? <span className="max-w-[140px] truncate">{state.bpfFilter}</span>
            : "Filter"}
        </button>

        <div className="flex-1" />

        {/* Clear */}
        <button
          onClick={() => dispatch({ type: "CLEAR_PACKETS" })}
          className="btn-ghost"
          title="Clear packet buffer"
        >
          <Trash2 size={12} />
        </button>

        {/* Start / Stop */}
        {state.isCapturing ? (
          <button onClick={handleStop} className="btn-danger gap-1.5">
            <Square size={11} fill="currentColor" />
            Stop
          </button>
        ) : (
          <button
            onClick={handleStart}
            disabled={starting || state.interfaces.length === 0}
            className="btn-accent gap-1.5 disabled:opacity-50"
          >
            {starting ? <Spinner /> : <Play size={11} fill="currentColor" />}
            {starting ? "Starting…" : "Capture"}
          </button>
        )}
      </div>

      {/* ── BPF filter bar ─────────────────────────────────────────────── */}
      {filterOpen && (
        <div className="flex items-center gap-2 px-4 py-2 border-b border-dim bg-surface-raised animate-slidein shrink-0">
          <Filter size={11} className="text-subtle shrink-0" />
          <input
            className="input flex-1 bg-surface"
            placeholder="tcp port 443  |  host 192.168.1.1  |  udp and not port 53"
            value={bpfInput}
            onChange={(e) => setBpfInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleApplyFilter()}
          />
          <button onClick={handleApplyFilter} className="btn-outline shrink-0">
            Apply
          </button>
          <button
            onClick={() => { setBpfInput(""); dispatch({ type: "SET_BPF", payload: "" }); setBpfFilter(""); }}
            className="btn-ghost shrink-0"
          >
            Clear
          </button>
        </div>
      )}

      {/* ── Body ───────────────────────────────────────────────────────── */}
      <div className="flex flex-col flex-1 overflow-hidden">
        {/* Stat cards + mini-chart row */}
        <div className="flex gap-0 border-b border-dim shrink-0">
          <StatCards />
          <div className="flex-1 border-l border-dim">
            <MiniChart />
          </div>
        </div>

        {/* Live packet feed */}
        <LivePacketFeed />
      </div>
    </div>
  );
}
