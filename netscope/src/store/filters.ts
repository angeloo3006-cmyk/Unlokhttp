import { create } from "zustand";
import type { Protocol } from "@/types/packet";

export type TcpFlag = "SYN" | "ACK" | "FIN" | "RST" | "PSH";

export interface FilterState {
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocols: Protocol[];
  min_length: number | null;
  max_length: number | null;
  flags: TcpFlag[];
}

interface FiltersStore extends FilterState {
  setFilter: <K extends keyof FilterState>(key: K, value: FilterState[K]) => void;
  replaceFilters: (filters: FilterState) => void;
  clearFilters: () => void;
}

export const EMPTY_FILTERS: FilterState = {
  src_ip: null,
  dst_ip: null,
  src_port: null,
  dst_port: null,
  protocols: [],
  min_length: null,
  max_length: null,
  flags: [],
};

export const useFiltersStore = create<FiltersStore>((set) => ({
  ...EMPTY_FILTERS,
  setFilter: (key, value) => set({ [key]: value } as Pick<FiltersStore, typeof key>),
  replaceFilters: (filters) => set(filters),
  clearFilters: () => set(EMPTY_FILTERS),
}));

export function countActiveFilters(filters: FilterState) {
  return [
    filters.src_ip,
    filters.dst_ip,
    filters.src_port,
    filters.dst_port,
    filters.protocols.length ? filters.protocols : null,
    filters.min_length,
    filters.max_length,
    filters.flags.length ? filters.flags : null,
  ].filter((value) => value !== null).length;
}

export function isFilterStateActive(filters: FilterState) {
  return countActiveFilters(filters) > 0;
}
