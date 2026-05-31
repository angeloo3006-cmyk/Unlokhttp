import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { listen } from "@tauri-apps/api/event";
import type { Interface, Stats } from "@/lib/tauri";
import type { CaptureStats, Packet } from "@/types/packet";

const MAX_PACKETS = 10_000;
const MAX_STATS_HISTORY = 60;

interface CaptureContextValue {
  packets: Packet[];
  stats: CaptureStats;
  statsHistory: CaptureStats[];
  interfaces: Interface[];
  selectedInterfaceId: number;
  selectedPacket: Packet | null;
  isCapturing: boolean;
  sessionId: number | null;
  error: string | null;
  setSelectedPacket: (packet: Packet | null) => void;
  setSelectedInterfaceId: (interfaceId: number) => void;
  setIsCapturing: (capturing: boolean) => void;
  setSessionId: (sessionId: number | null) => void;
  setError: (error: string | null) => void;
  clearPackets: () => void;
}

const CaptureContext = createContext<CaptureContextValue | null>(null);

export function CaptureProvider({ children }: { children: ReactNode }) {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [stats, setStats] = useState<CaptureStats>({ pps: 0, total: 0, dropped: 0 });
  const [statsHistory, setStatsHistory] = useState<CaptureStats[]>([]);
  const [interfaces, setInterfaces] = useState<Interface[]>([]);
  const [selectedInterfaceId, setSelectedInterfaceId] = useState(0);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [isCapturing, setIsCapturing] = useState(false);
  const [sessionId, setSessionId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const unlisteners: Array<() => void> = [];
    let cancelled = false;

    void Promise.all([
      listen<Packet>("packet", ({ payload }) => {
        setPackets((current) => [...current.slice(-(MAX_PACKETS - 1)), payload]);
      }),
      listen<Stats>("net_stats", ({ payload }) => {
        const next = {
          pps: payload.rate_pps,
          total: payload.captured,
          dropped: payload.dropped,
        };
        setStats(next);
        setStatsHistory((current) => [...current.slice(-(MAX_STATS_HISTORY - 1)), next]);
      }),
      listen<Interface[]>("interfaces", ({ payload }) => setInterfaces(payload)),
      listen<{ msg: string }>("sniffer_error", ({ payload }) => setError(payload.msg)),
      listen<{ running: boolean }>("capture_state", ({ payload }) => {
        setIsCapturing(payload.running);
        if (!payload.running) setSessionId(null);
      }),
    ]).then((listeners) => {
      if (cancelled) {
        listeners.forEach((unlisten) => unlisten());
      } else {
        unlisteners.push(...listeners);
      }
    });

    return () => {
      cancelled = true;
      unlisteners.forEach((unlisten) => unlisten());
    };
  }, []);

  const clearPackets = useCallback(() => {
    setPackets([]);
    setSelectedPacket(null);
  }, []);

  const value = useMemo<CaptureContextValue>(
    () => ({
      packets,
      stats,
      statsHistory,
      interfaces,
      selectedInterfaceId,
      selectedPacket,
      isCapturing,
      sessionId,
      error,
      setSelectedPacket,
      setSelectedInterfaceId,
      setIsCapturing,
      setSessionId,
      setError,
      clearPackets,
    }),
    [
      packets,
      stats,
      statsHistory,
      interfaces,
      selectedInterfaceId,
      selectedPacket,
      isCapturing,
      sessionId,
      error,
      clearPackets,
    ],
  );

  return <CaptureContext.Provider value={value}>{children}</CaptureContext.Provider>;
}

export function usePacketCapture() {
  const context = useContext(CaptureContext);
  if (!context) throw new Error("usePacketCapture must be used within CaptureProvider");
  return context;
}
