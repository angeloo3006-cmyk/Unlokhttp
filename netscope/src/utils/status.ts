import type { Session } from "@/lib/tauri";

export function getSessionStatusColor(session: Session): string {
  if (session.total_packets === 0) {
    return "bg-white/25";
  }

  if (session.total_packets < 100) {
    return "bg-blue-400";
  }

  if (session.total_packets < 1000) {
    return "bg-yellow-400";
  }

  return "bg-red-400";
}