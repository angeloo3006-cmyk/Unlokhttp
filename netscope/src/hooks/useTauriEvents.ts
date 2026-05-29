import { useEffect } from "react";
import { useAppState } from "@/store";
import {
  onPacket, onNetStats, onInterfaces, onSnifferError,
  listInterfaces, listSessions,
} from "@/lib/tauri";

/**
 * Subscribe to all Tauri backend events and push them into global state.
 * Mount this once in App.tsx.
 */
export function useTauriEvents() {
  const { dispatch } = useAppState();

  useEffect(() => {
    const unlisteners: Array<() => void> = [];

    (async () => {
      // ── Packet events ──────────────────────────────────────────────────
      const ulPacket = await onPacket((pkt) => {
        dispatch({ type: "ADD_PACKET", payload: pkt });
      });
      unlisteners.push(ulPacket);

      // ── Stats ──────────────────────────────────────────────────────────
      const ulStats = await onNetStats((stats) => {
        dispatch({ type: "SET_STATS", payload: stats });
      });
      unlisteners.push(ulStats);

      // ── Interface list ─────────────────────────────────────────────────
      const ulIfaces = await onInterfaces((ifaces) => {
        dispatch({ type: "SET_INTERFACES", payload: ifaces });
      });
      unlisteners.push(ulIfaces);

      // ── Errors ─────────────────────────────────────────────────────────
      const ulErr = await onSnifferError(({ msg }) => {
        dispatch({ type: "SET_ERROR", payload: msg });
        setTimeout(() => dispatch({ type: "SET_ERROR", payload: null }), 6000);
      });
      unlisteners.push(ulErr);

      // Initial data load
      try {
        const { interfaces } = await listInterfaces();
        dispatch({ type: "SET_INTERFACES", payload: interfaces });
      } catch { /* sidecar not yet started — OK */ }

      try {
        const sessions = await listSessions();
        dispatch({ type: "SET_SESSIONS", payload: sessions });
      } catch { /* db may not be ready */ }
    })();

    return () => { unlisteners.forEach((fn) => fn()); };
  }, [dispatch]);
}
