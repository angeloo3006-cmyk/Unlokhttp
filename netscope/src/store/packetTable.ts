import { create } from "zustand";
import { persist } from "zustand/middleware";

export type PacketColumnGroup =
  | "Default"
  | "Packet row data"
  | "Frame"
  | "Ethernet II"
  | "Internet Protocol"
  | "Transport"
  | "Payload";

export type PacketTableColumnId =
  | "id"
  | "ts"
  | "src_ip"
  | "dst_ip"
  | "src_port"
  | "dst_port"
  | "protocol"
  | "protocol_weight"
  | "length"
  | "traffic"
  | "window"
  | "flags"
  | "info"
  | "local_full"
  | "utc_time"
  | "local_day"
  | "local_hour"
  | "local_minute"
  | "link_layer"
  | "src_mac"
  | "dst_mac"
  | "src_vendor"
  | "dst_vendor"
  | "ethernet_type"
  | "ip_source"
  | "ip_destination"
  | "ttl"
  | "protocol_number"
  | "frame_length"
  | "captured_length"
  | "visible_index"
  | "connection_role"
  | "payload_hex_bytes"
  | "raw_ascii"
  | "payload_hex";

export interface PacketTableColumnConfig {
  id: PacketTableColumnId;
  label: string;
  group: PacketColumnGroup;
  defaultVisible: boolean;
  required?: boolean;
  minSize: number;
  maxSize: number;
  defaultSize: number;
}

interface PacketTableSettingsStore {
  columnVisibility: Partial<Record<PacketTableColumnId, boolean>>;
  columnSizing: Partial<Record<PacketTableColumnId, number>>;
  setColumnVisible: (id: PacketTableColumnId, visible: boolean) => void;
  setColumnSize: (id: PacketTableColumnId, size: number) => void;
  setColumnSizing: (sizing: Partial<Record<PacketTableColumnId, number>>) => void;
  resetDefaults: () => void;
}

export const PACKET_TABLE_COLUMNS: PacketTableColumnConfig[] = [
  { id: "id", label: "#", group: "Default", defaultVisible: true, required: true, minSize: 42, maxSize: 80, defaultSize: 50 },
  { id: "ts", label: "Time", group: "Default", defaultVisible: true, required: true, minSize: 82, maxSize: 160, defaultSize: 112 },
  { id: "src_ip", label: "Source", group: "Default", defaultVisible: true, required: true, minSize: 96, maxSize: 260, defaultSize: 150 },
  { id: "dst_ip", label: "Destination", group: "Default", defaultVisible: true, required: true, minSize: 96, maxSize: 280, defaultSize: 150 },
  { id: "protocol", label: "Protocol", group: "Default", defaultVisible: true, required: true, minSize: 66, maxSize: 120, defaultSize: 76 },
  { id: "protocol_weight", label: "Weight", group: "Default", defaultVisible: true, required: true, minSize: 58, maxSize: 120, defaultSize: 72 },
  { id: "length", label: "Length", group: "Default", defaultVisible: true, required: true, minSize: 56, maxSize: 120, defaultSize: 68 },
  { id: "traffic", label: "Traffic", group: "Default", defaultVisible: true, required: true, minSize: 70, maxSize: 200, defaultSize: 96 },
  { id: "window", label: "Day Hour Min", group: "Default", defaultVisible: true, required: true, minSize: 82, maxSize: 190, defaultSize: 124 },
  { id: "flags", label: "Flags", group: "Default", defaultVisible: true, required: true, minSize: 54, maxSize: 140, defaultSize: 74 },
  { id: "info", label: "Info", group: "Default", defaultVisible: true, required: true, minSize: 120, maxSize: 560, defaultSize: 300 },

  { id: "src_port", label: "Source port", group: "Packet row data", defaultVisible: false, minSize: 58, maxSize: 150, defaultSize: 82 },
  { id: "dst_port", label: "Destination port", group: "Packet row data", defaultVisible: false, minSize: 58, maxSize: 160, defaultSize: 98 },
  { id: "local_day", label: "Day", group: "Packet row data", defaultVisible: false, minSize: 72, maxSize: 140, defaultSize: 96 },
  { id: "local_hour", label: "Hour", group: "Packet row data", defaultVisible: false, minSize: 54, maxSize: 100, defaultSize: 64 },
  { id: "local_minute", label: "Minute", group: "Packet row data", defaultVisible: false, minSize: 54, maxSize: 100, defaultSize: 70 },

  { id: "local_full", label: "Arrival local", group: "Frame", defaultVisible: false, minSize: 130, maxSize: 280, defaultSize: 190 },
  { id: "utc_time", label: "Arrival UTC", group: "Frame", defaultVisible: false, minSize: 150, maxSize: 300, defaultSize: 210 },
  { id: "frame_length", label: "Frame length", group: "Frame", defaultVisible: false, minSize: 72, maxSize: 140, defaultSize: 96 },
  { id: "captured_length", label: "Captured length", group: "Frame", defaultVisible: false, minSize: 84, maxSize: 160, defaultSize: 116 },
  { id: "visible_index", label: "Visible index", group: "Frame", defaultVisible: false, minSize: 80, maxSize: 150, defaultSize: 110 },

  { id: "link_layer", label: "Link layer", group: "Ethernet II", defaultVisible: false, minSize: 82, maxSize: 150, defaultSize: 106 },
  { id: "src_mac", label: "Source MAC", group: "Ethernet II", defaultVisible: false, minSize: 120, maxSize: 210, defaultSize: 150 },
  { id: "dst_mac", label: "Destination MAC", group: "Ethernet II", defaultVisible: false, minSize: 120, maxSize: 220, defaultSize: 160 },
  { id: "src_vendor", label: "Source vendor", group: "Ethernet II", defaultVisible: false, minSize: 130, maxSize: 320, defaultSize: 210 },
  { id: "dst_vendor", label: "Destination vendor", group: "Ethernet II", defaultVisible: false, minSize: 130, maxSize: 340, defaultSize: 230 },
  { id: "ethernet_type", label: "Ethernet type", group: "Ethernet II", defaultVisible: false, minSize: 96, maxSize: 170, defaultSize: 124 },

  { id: "ip_source", label: "Source IP", group: "Internet Protocol", defaultVisible: false, minSize: 96, maxSize: 190, defaultSize: 130 },
  { id: "ip_destination", label: "Destination IP", group: "Internet Protocol", defaultVisible: false, minSize: 96, maxSize: 200, defaultSize: 140 },
  { id: "ttl", label: "TTL", group: "Internet Protocol", defaultVisible: false, minSize: 42, maxSize: 80, defaultSize: 54 },
  { id: "protocol_number", label: "Protocol number", group: "Internet Protocol", defaultVisible: false, minSize: 110, maxSize: 190, defaultSize: 140 },

  { id: "connection_role", label: "Connection role", group: "Transport", defaultVisible: false, minSize: 130, maxSize: 260, defaultSize: 180 },

  { id: "payload_hex_bytes", label: "Payload bytes shown", group: "Payload", defaultVisible: false, minSize: 110, maxSize: 190, defaultSize: 140 },
  { id: "raw_ascii", label: "Raw ASCII", group: "Payload", defaultVisible: false, minSize: 160, maxSize: 520, defaultSize: 260 },
  { id: "payload_hex", label: "Payload hex", group: "Payload", defaultVisible: false, minSize: 180, maxSize: 620, defaultSize: 320 },
];

export const DEFAULT_PACKET_COLUMN_VISIBILITY = Object.fromEntries(
  PACKET_TABLE_COLUMNS.map((column) => [column.id, column.defaultVisible]),
) as Record<PacketTableColumnId, boolean>;

export const REQUIRED_PACKET_COLUMNS = new Set<PacketTableColumnId>(
  PACKET_TABLE_COLUMNS.filter((column) => column.required).map((column) => column.id),
);

export function getEffectivePacketColumnVisibility(
  visibility: Partial<Record<PacketTableColumnId, boolean>>,
) {
  return Object.fromEntries(
    PACKET_TABLE_COLUMNS.map((column) => [
      column.id,
      column.required ? true : visibility[column.id] ?? column.defaultVisible,
    ]),
  ) as Record<PacketTableColumnId, boolean>;
}

export const DEFAULT_PACKET_COLUMN_SIZING = Object.fromEntries(
  PACKET_TABLE_COLUMNS.map((column) => [column.id, column.defaultSize]),
) as Record<PacketTableColumnId, number>;

export const PACKET_COLUMN_GROUPS: PacketColumnGroup[] = [
  "Default",
  "Packet row data",
  "Frame",
  "Ethernet II",
  "Internet Protocol",
  "Transport",
  "Payload",
];

export const usePacketTableSettings = create<PacketTableSettingsStore>()(
  persist(
    (set) => ({
      columnVisibility: DEFAULT_PACKET_COLUMN_VISIBILITY,
      columnSizing: DEFAULT_PACKET_COLUMN_SIZING,
      setColumnVisible: (id, visible) => set((state) => {
        if (REQUIRED_PACKET_COLUMNS.has(id)) return state;
        return {
          columnVisibility: { ...state.columnVisibility, [id]: visible },
        };
      }),
      setColumnSize: (id, size) => set((state) => {
        const column = PACKET_TABLE_COLUMNS.find((item) => item.id === id);
        const clamped = column ? clamp(size, column.minSize, column.maxSize) : size;
        return { columnSizing: { ...state.columnSizing, [id]: clamped } };
      }),
      setColumnSizing: (sizing) => set({ columnSizing: normalizeColumnSizing(sizing) }),
      resetDefaults: () => set({
        columnVisibility: DEFAULT_PACKET_COLUMN_VISIBILITY,
        columnSizing: DEFAULT_PACKET_COLUMN_SIZING,
      }),
    }),
    {
      name: "netscope-packet-table-settings",
    },
  ),
);

function normalizeColumnSizing(sizing: Partial<Record<PacketTableColumnId, number>>) {
  return Object.fromEntries(
    PACKET_TABLE_COLUMNS.map((column) => {
      const value = sizing[column.id] ?? column.defaultSize;
      return [column.id, clamp(value, column.minSize, column.maxSize)];
    }),
  ) as Record<PacketTableColumnId, number>;
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}
