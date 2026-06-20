import { useEffect, useMemo, useRef, useState } from "react";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnSizingState,
  type SortingState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDownToLine } from "lucide-react";
import type { Packet } from "@/types/packet";
import { EMPTY_FILTERS, type FilterState } from "@/store/filters";
import {
  DEFAULT_PACKET_COLUMN_SIZING,
  PACKET_TABLE_COLUMNS,
  getEffectivePacketColumnVisibility,
  type PacketTableColumnId,
  usePacketTableSettings,
} from "@/store/packetTable";

const columnHelper = createColumnHelper<Packet>();

function formatLocalTime(ts: string) {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }) + `.${String(date.getMilliseconds()).padStart(3, "0")}`;
}

const protocolClasses: Record<Packet["protocol"], string> = {
  TCP: "proto-blue",
  UDP: "proto-cyan",
  DNS: "proto-yellow",
  HTTP: "proto-green",
  HTTPS: "proto-teal",
  ICMP: "proto-orange",
  ARP: "proto-magenta",
  OTHER: "proto-gray",
};

interface PacketListProps {
  packets: Packet[];
  filters?: FilterState;
  selectedPacket: Packet | null;
  onSelectPacket: (packet: Packet) => void;
  title?: string;
  showFollow?: boolean;
  trafficSummary?: {
    totalPackets: number;
    totalBytes: number;
    protocolCounts: Map<Packet["protocol"], number>;
  };
}

export function PacketList({
  packets,
  filters = EMPTY_FILTERS,
  selectedPacket,
  onSelectPacket,
  title = "Packet list",
  showFollow = true,
  trafficSummary,
}: PacketListProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [sorting, setSorting] = useState<SortingState>([]);
  const [follow, setFollow] = useState(true);
  const columnVisibility = usePacketTableSettings((state) => state.columnVisibility);
  const columnSizing = usePacketTableSettings((state) => state.columnSizing);
  const setColumnSizing = usePacketTableSettings((state) => state.setColumnSizing);
  const effectiveColumnVisibility = useMemo(
    () => getEffectivePacketColumnVisibility(columnVisibility),
    [columnVisibility],
  );

  const traffic = useMemo(() => {
    if (trafficSummary) return trafficSummary;

    const protocolCounts = new Map<Packet["protocol"], number>();
    const totalBytes = packets.reduce((sum, packet) => {
      protocolCounts.set(packet.protocol, (protocolCounts.get(packet.protocol) ?? 0) + 1);
      return sum + packet.length;
    }, 0);

    return { protocolCounts, totalBytes, totalPackets: packets.length };
  }, [packets, trafficSummary]);

  const columns = useMemo(
    () => [
      columnHelper.accessor("id", columnOptions("id")),
      columnHelper.accessor("ts", {
        header: "Time",
        ...columnOptions("ts"),
        cell: ({ getValue }) => formatLocalTime(getValue()),
      }),
      columnHelper.accessor("src_ip", {
        header: "Source",
        ...columnOptions("src_ip"),
        cell: ({ row }) => endpoint(row.original.src_ip, row.original.src_port),
      }),
      columnHelper.accessor("dst_ip", {
        header: "Destination",
        ...columnOptions("dst_ip"),
        cell: ({ row }) => endpoint(row.original.dst_ip, row.original.dst_port),
      }),
      columnHelper.accessor("src_port", {
        header: "Source port",
        ...columnOptions("src_port"),
        cell: ({ getValue }) => getValue() ?? "-",
      }),
      columnHelper.accessor("dst_port", {
        header: "Destination port",
        ...columnOptions("dst_port"),
        cell: ({ getValue }) => getValue() ?? "-",
      }),
      columnHelper.accessor("protocol", {
        header: "Protocol",
        ...columnOptions("protocol"),
        cell: ({ getValue }) => (
          <span className={`protocol-pill ${protocolClasses[getValue()]}`}>{getValue()}</span>
        ),
      }),
      columnHelper.display({
        id: "protocol_weight",
        header: "Weight",
        ...columnOptions("protocol_weight"),
        cell: ({ row }) =>
          `${(((traffic.protocolCounts.get(row.original.protocol) ?? 0) / Math.max(1, traffic.totalPackets)) * 100).toFixed(1)}%`,
      }),
      columnHelper.accessor("length", { header: "Length", ...columnOptions("length") }),
      columnHelper.display({
        id: "traffic",
        header: "Traffic",
        ...columnOptions("traffic"),
        cell: ({ row }) =>
          `${formatBytes(row.original.length)} / ${((row.original.length / Math.max(1, traffic.totalBytes)) * 100).toFixed(3)}%`,
      }),
      columnHelper.display({
        id: "window",
        header: "Day Hour Min",
        ...columnOptions("window"),
        cell: ({ row }) => formatWindow(row.original.ts),
      }),
      columnHelper.accessor("flags", { header: "Flags", ...columnOptions("flags"), cell: ({ getValue }) => getValue() || "-" }),
      columnHelper.display({ id: "info", header: "Info", ...columnOptions("info"), cell: ({ row }) => packetInfo(row.original) }),
      columnHelper.display({ id: "local_full", header: "Arrival local", ...columnOptions("local_full"), cell: ({ row }) => splitTimestamp(row.original.ts).localFull }),
      columnHelper.display({ id: "utc_time", header: "Arrival UTC", ...columnOptions("utc_time"), cell: ({ row }) => row.original.ts }),
      columnHelper.display({ id: "local_day", header: "Day", ...columnOptions("local_day"), cell: ({ row }) => splitTimestamp(row.original.ts).localDay }),
      columnHelper.display({ id: "local_hour", header: "Hour", ...columnOptions("local_hour"), cell: ({ row }) => splitTimestamp(row.original.ts).localHour }),
      columnHelper.display({ id: "local_minute", header: "Minute", ...columnOptions("local_minute"), cell: ({ row }) => splitTimestamp(row.original.ts).localMinute }),
      columnHelper.display({ id: "link_layer", header: "Link layer", ...columnOptions("link_layer"), cell: ({ row }) => row.original.link_layer ?? "-" }),
      columnHelper.display({ id: "src_mac", header: "Source MAC", ...columnOptions("src_mac"), cell: ({ row }) => row.original.src_mac ?? "-" }),
      columnHelper.display({ id: "dst_mac", header: "Destination MAC", ...columnOptions("dst_mac"), cell: ({ row }) => row.original.dst_mac ?? "-" }),
      columnHelper.display({ id: "src_vendor", header: "Source vendor", ...columnOptions("src_vendor"), cell: ({ row }) => row.original.src_vendor ?? "Unknown" }),
      columnHelper.display({ id: "dst_vendor", header: "Destination vendor", ...columnOptions("dst_vendor"), cell: ({ row }) => row.original.dst_vendor ?? "Unknown" }),
      columnHelper.display({ id: "ethernet_type", header: "Ethernet type", ...columnOptions("ethernet_type"), cell: ({ row }) => ethernetType(row.original) }),
      columnHelper.display({ id: "ip_source", header: "Source IP", ...columnOptions("ip_source"), cell: ({ row }) => row.original.src_ip ?? "-" }),
      columnHelper.display({ id: "ip_destination", header: "Destination IP", ...columnOptions("ip_destination"), cell: ({ row }) => row.original.dst_ip ?? "-" }),
      columnHelper.display({ id: "ttl", header: "TTL", ...columnOptions("ttl"), cell: ({ row }) => row.original.ttl ?? "-" }),
      columnHelper.display({ id: "protocol_number", header: "Protocol number", ...columnOptions("protocol_number"), cell: ({ row }) => protocolNumber(row.original.protocol) }),
      columnHelper.display({ id: "frame_length", header: "Frame length", ...columnOptions("frame_length"), cell: ({ row }) => `${row.original.length} bytes` }),
      columnHelper.display({ id: "captured_length", header: "Captured length", ...columnOptions("captured_length"), cell: ({ row }) => `${row.original.length} bytes` }),
      columnHelper.display({ id: "visible_index", header: "Visible index", ...columnOptions("visible_index"), cell: ({ row }) => `${row.index + 1} of ${packets.length}` }),
      columnHelper.display({ id: "connection_role", header: "Connection role", ...columnOptions("connection_role"), cell: ({ row }) => connectionRole(row.original) }),
      columnHelper.display({ id: "payload_hex_bytes", header: "Payload bytes shown", ...columnOptions("payload_hex_bytes"), cell: ({ row }) => `${Math.floor(row.original.payload_hex.length / 2)} bytes` }),
      columnHelper.display({ id: "raw_ascii", header: "Raw ASCII", ...columnOptions("raw_ascii"), cell: ({ row }) => row.original.raw_ascii || "-" }),
      columnHelper.display({ id: "payload_hex", header: "Payload hex", ...columnOptions("payload_hex"), cell: ({ row }) => row.original.payload_hex || "-" }),
    ],
    [packets.length, traffic.protocolCounts, traffic.totalBytes, traffic.totalPackets],
  );

  const table = useReactTable({
    data: packets,
    columns,
    state: {
      sorting,
      columnSizing: { ...DEFAULT_PACKET_COLUMN_SIZING, ...columnSizing },
      columnVisibility: effectiveColumnVisibility,
    },
    onSortingChange: setSorting,
    onColumnSizingChange: (updater) => {
      const current = { ...DEFAULT_PACKET_COLUMN_SIZING, ...columnSizing };
      setColumnSizing(typeof updater === "function" ? updater(current as ColumnSizingState) : updater);
    },
    columnResizeMode: "onChange",
    enableColumnResizing: true,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });
  const rows = table.getRowModel().rows;
  const tableWidth = table.getTotalSize();
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 22,
    overscan: 20,
  });

  useEffect(() => {
    if (follow && rows.length) virtualizer.scrollToIndex(rows.length - 1, { align: "end" });
  }, [follow, rows.length, virtualizer]);

  return (
    <section className="flex h-full flex-col overflow-hidden">
      <div className="flex h-7 shrink-0 items-center justify-between border-b border-glass px-3 text-[10px] uppercase tracking-[0.15em] text-muted">
        <span>{title}</span>
        {showFollow && (
          <button className={follow ? "text-cyan-300" : "text-muted"} onClick={() => setFollow((value) => !value)}>
            <ArrowDownToLine className="mr-1 inline" size={12} /> Follow
          </button>
        )}
      </div>
      <div className="min-h-0 flex-1 overflow-x-auto overflow-y-hidden">
        <div className="flex h-full flex-col" style={{ minWidth: tableWidth, width: tableWidth }}>
          <div className="packet-header" style={{ width: tableWidth }}>
            {table.getFlatHeaders().map((header) => (
              <div
                key={header.id}
                className={`packet-cell packet-header-cell ${isColumnFiltered(header.column.id, filters) ? "filtered-header" : ""}`}
                style={{ width: header.getSize() }}
              >
                <button
                  className="min-w-0 flex-1 truncate text-left"
                  onClick={header.column.getToggleSortingHandler()}
                  type="button"
                >
                  {flexRender(header.column.columnDef.header, header.getContext())}
                </button>
                {header.column.getCanResize() && (
                  <span
                    className={`packet-column-resizer ${header.column.getIsResizing() ? "packet-column-resizer-active" : ""}`}
                    onDoubleClick={() => header.column.resetSize()}
                    onMouseDown={header.getResizeHandler()}
                    onTouchStart={header.getResizeHandler()}
                    role="separator"
                  />
                )}
              </div>
            ))}
          </div>
          <div ref={scrollRef} className="min-h-0 flex-1 overflow-x-hidden overflow-y-auto">
            <div className="relative" style={{ height: virtualizer.getTotalSize(), width: tableWidth }}>
              {virtualizer.getVirtualItems().map((virtualRow) => {
                const row = rows[virtualRow.index];
                const selected = row.original.id === selectedPacket?.id;
                return (
                  <button
                    key={row.id}
                    className={`packet-row ${selected ? "packet-row-selected" : ""}`}
                    style={{ transform: `translateY(${virtualRow.start}px)`, width: tableWidth }}
                    onClick={() => onSelectPacket(row.original)}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <span
                        key={cell.id}
                        className="packet-cell truncate text-left"
                        style={{ width: cell.column.getSize() }}
                      >
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </span>
                    ))}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function endpoint(ip: string | null, port: number | null) {
  return `${ip ?? "-"}${port !== null ? `:${port}` : ""}`;
}

function columnOptions(id: PacketTableColumnId) {
  const column = PACKET_TABLE_COLUMNS.find((item) => item.id === id);
  return {
    size: DEFAULT_PACKET_COLUMN_SIZING[id],
    minSize: column?.minSize ?? 48,
    maxSize: column?.maxSize ?? 220,
  };
}

function packetInfo(packet: Packet) {
  if (packet.protocol === "DNS") return "Domain name system";
  if (packet.protocol === "HTTP") return "HTTP request / response";
  if (packet.protocol === "HTTPS") return "TLS encrypted traffic";
  return packet.flags || `${packet.length} bytes`;
}

function formatWindow(ts: string) {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return "-";
  const day = date.toLocaleDateString([], { month: "2-digit", day: "2-digit" });
  const hour = date.toLocaleTimeString([], { hour: "2-digit", hour12: false });
  const minute = date.toLocaleTimeString([], { minute: "2-digit" });
  return `${day} ${hour}:${minute}`;
}

function splitTimestamp(ts: string) {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) {
    return {
      localFull: ts,
      localDay: "-",
      localHour: "-",
      localMinute: "-",
    };
  }

  return {
    localFull: date.toLocaleString(),
    localDay: date.toLocaleDateString([], { year: "numeric", month: "2-digit", day: "2-digit" }),
    localHour: date.toLocaleTimeString([], { hour: "2-digit", hour12: false }),
    localMinute: date.toLocaleTimeString([], { minute: "2-digit" }),
  };
}

function ethernetType(packet: Packet) {
  if (packet.protocol === "ARP") return "0x0806 (ARP)";
  if (packet.link_layer === "Ethernet") return "0x0800 (IPv4)";
  return "-";
}

function protocolNumber(protocol: Packet["protocol"]) {
  if (["TCP", "HTTP", "HTTPS"].includes(protocol)) return "6 (TCP)";
  if (["UDP", "DNS"].includes(protocol)) return "17 (UDP)";
  if (protocol === "ICMP") return "1 (ICMP)";
  if (protocol === "ARP") return "ARP (EtherType 0x0806)";
  return protocol;
}

function connectionRole(packet: Packet) {
  if (["UDP", "DNS"].includes(packet.protocol)) return "Datagram";
  if (!["TCP", "HTTP", "HTTPS"].includes(packet.protocol)) return "-";
  if (packet.flags === "SYN") return "Connection request";
  if (packet.flags === "SYN-ACK") return "Connection accepted response";
  if (packet.flags.includes("RST")) return "Connection reset or rejected";
  if (packet.flags.includes("FIN")) return "Graceful close";
  if (packet.flags.includes("ACK")) return "Acknowledgement";
  if (packet.flags.includes("PSH")) return "Push data";
  return "No TCP control flag decoded";
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function isColumnFiltered(column: string, filters: FilterState) {
  return (
    (column === "src_ip" && (filters.src_ip !== null || filters.src_port !== null)) ||
    (column === "dst_ip" && (filters.dst_ip !== null || filters.dst_port !== null)) ||
    (column === "protocol" && filters.protocols.length > 0) ||
    (column === "length" && (filters.min_length !== null || filters.max_length !== null)) ||
    (column === "flags" && filters.flags.length > 0)
  );
}
