import { useMemo } from "react";
import type { Packet } from "@/types/packet";
import type { FilterState } from "@/store/filters";

export function useFilteredPackets(packets: Packet[], filters: FilterState) {
  return useMemo(
    () =>
      packets.filter((packet) => {
        if (filters.src_ip && packet.src_ip !== filters.src_ip) return false;
        if (filters.dst_ip && packet.dst_ip !== filters.dst_ip) return false;
        if (filters.src_port !== null && packet.src_port !== filters.src_port) return false;
        if (filters.dst_port !== null && packet.dst_port !== filters.dst_port) return false;
        if (filters.protocols.length && !filters.protocols.includes(packet.protocol)) return false;
        if (filters.min_length !== null && packet.length < filters.min_length) return false;
        if (filters.max_length !== null && packet.length > filters.max_length) return false;
        if (filters.flags.length && !filters.flags.some((flag) => packet.flags.includes(flag))) {
          return false;
        }
        return true;
      }),
    [packets, filters],
  );
}
