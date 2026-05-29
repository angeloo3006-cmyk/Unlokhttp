import React, {
  createContext, useContext, useReducer, useRef, useCallback, useEffect,
} from "react";
import type {
  Packet, PacketRow, Stats, Interface, Session, DiagnosticsData,
} from "@/lib/tauri";

// ── Types ─────────────────────────────────────────────────────────────────────

export type AppView = "capture" | "packets" | "diagnostics" | "sessions";

export interface AppState {
  // Navigation
  view: AppView;

  // Capture
  isCapturing:     boolean;
  sessionId:       number | null;
  selectedIface:   number;
  bpfFilter:       string;
  interfaces:      Interface[];

  // Live ring-buffer of packets (capped at MAX_LIVE_PACKETS)
  livePackets:     Packet[];

  // Stats
  stats:           Stats;
  statsHistory:    Stats[];   // last 60 samples

  // Sessions
  sessions:        Session[];

  // Diagnostics
  diagnostics:     DiagnosticsData | null;

  // UI state
  selectedPacket:  Packet | null;
  isLoading:       boolean;
  error:           string | null;
  searchFilter:    string;
}

type Action =
  | { type: "SET_VIEW";        payload: AppView }
  | { type: "SET_CAPTURING";   payload: boolean }
  | { type: "SET_SESSION_ID";  payload: number | null }
  | { type: "SET_IFACE";       payload: number }
  | { type: "SET_BPF";         payload: string }
  | { type: "SET_INTERFACES";  payload: Interface[] }
  | { type: "ADD_PACKET";      payload: Packet }
  | { type: "CLEAR_PACKETS" }
  | { type: "SET_STATS";       payload: Stats }
  | { type: "SET_SESSIONS";    payload: Session[] }
  | { type: "SET_DIAGNOSTICS"; payload: DiagnosticsData | null }
  | { type: "SELECT_PACKET";   payload: Packet | null }
  | { type: "SET_LOADING";     payload: boolean }
  | { type: "SET_ERROR";       payload: string | null }
  | { type: "SET_SEARCH";      payload: string };

const MAX_LIVE_PACKETS = 5000;
const MAX_STATS_HISTORY = 60;

const initialState: AppState = {
  view:           "capture",
  isCapturing:    false,
  sessionId:      null,
  selectedIface:  0,
  bpfFilter:      "",
  interfaces:     [],
  livePackets:    [],
  stats:          { captured: 0, dropped: 0, rate_pps: 0 },
  statsHistory:   [],
  sessions:       [],
  diagnostics:    null,
  selectedPacket: null,
  isLoading:      false,
  error:          null,
  searchFilter:   "",
};

function reducer(state: AppState, action: Action): AppState {
  switch (action.type) {
    case "SET_VIEW":        return { ...state, view: action.payload };
    case "SET_CAPTURING":   return { ...state, isCapturing: action.payload };
    case "SET_SESSION_ID":  return { ...state, sessionId: action.payload };
    case "SET_IFACE":       return { ...state, selectedIface: action.payload };
    case "SET_BPF":         return { ...state, bpfFilter: action.payload };
    case "SET_INTERFACES":  return { ...state, interfaces: action.payload };
    case "SET_SESSIONS":    return { ...state, sessions: action.payload };
    case "SET_DIAGNOSTICS": return { ...state, diagnostics: action.payload };
    case "SELECT_PACKET":   return { ...state, selectedPacket: action.payload };
    case "SET_LOADING":     return { ...state, isLoading: action.payload };
    case "SET_ERROR":       return { ...state, error: action.payload };
    case "SET_SEARCH":      return { ...state, searchFilter: action.payload };
    case "CLEAR_PACKETS":   return { ...state, livePackets: [], selectedPacket: null };

    case "ADD_PACKET": {
      const next = state.livePackets.length >= MAX_LIVE_PACKETS
        ? state.livePackets.slice(-MAX_LIVE_PACKETS + 1)
        : state.livePackets;
      return { ...state, livePackets: [...next, action.payload] };
    }

    case "SET_STATS": {
      const history = [
        ...state.statsHistory.slice(-MAX_STATS_HISTORY + 1),
        action.payload,
      ];
      return { ...state, stats: action.payload, statsHistory: history };
    }

    default: return state;
  }
}

// ── Context ───────────────────────────────────────────────────────────────────

interface CtxValue {
  state:    AppState;
  dispatch: React.Dispatch<Action>;
}

const Ctx = createContext<CtxValue | null>(null);

export function AppStateProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  return <Ctx.Provider value={{ state, dispatch }}>{children}</Ctx.Provider>;
}

export function useAppState() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAppState must be used inside AppStateProvider");
  return ctx;
}
