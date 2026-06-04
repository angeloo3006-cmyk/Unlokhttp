import { useEffect, useMemo, useRef, useState } from "react";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type SortingState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDownToLine } from "lucide-react";
import type { Packet } from "@/types/packet";
import type { FilterState } from "@/store/filters";

const columnHelper = createColumnHelper<Packet>();

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
  filters: FilterState;
  selectedPacket: Packet | null;
  onSelectPacket: (packet: Packet) => void;
}

export function PacketList({ packets, filters, selectedPacket, onSelectPacket }: PacketListProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [sorting, setSorting] = useState<SortingState>([]);
  const [follow, setFollow] = useState(true);

  const traffic = useMemo(() => {
    const protocolCounts = new Map<Packet["protocol"], number>();
    const totalBytes = packets.reduce((sum, packet) => {
      protocolCounts.set(packet.protocol, (protocolCounts.get(packet.protocol) ?? 0) + 1);
      return sum + packet.length;
    }, 0);

    return { protocolCounts, totalBytes };
  }, [packets]);

  const columns = useMemo(
    () => [
      columnHelper.accessor("id", { header: "#", size: 50 }),
      columnHelper.accessor("ts", {
        header: "Time",
        size: 112,
        cell: ({ getValue }) => getValue().slice(11, 23),
      }),
      columnHelper.accessor("src_ip", {
        header: "Source",
        size: 150,
        cell: ({ row }) => endpoint(row.original.src_ip, row.original.src_port),
      }),
      columnHelper.accessor("dst_ip", {
        header: "Destination",
        size: 150,
        cell: ({ row }) => endpoint(row.original.dst_ip, row.original.dst_port),
      }),
      columnHelper.accessor("protocol", {
        header: "Protocol",
        size: 76,
        cell: ({ getValue }) => (
          <span className={`protocol-pill ${protocolClasses[getValue()]}`}>{getValue()}</span>
        ),
      }),
      columnHelper.display({
        id: "protocol_weight",
        header: "Weight",
        size: 72,
        cell: ({ row }) =>
          `${(((traffic.protocolCounts.get(row.original.protocol) ?? 0) / Math.max(1, packets.length)) * 100).toFixed(1)}%`,
      }),
      columnHelper.accessor("length", { header: "Length", size: 68 }),
      columnHelper.display({
        id: "traffic",
        header: "Traffic",
        size: 96,
        cell: ({ row }) =>
          `${formatBytes(row.original.length)} / ${((row.original.length / Math.max(1, traffic.totalBytes)) * 100).toFixed(3)}%`,
      }),
      columnHelper.display({
        id: "window",
        header: "Day Hour Min",
        size: 124,
        cell: ({ row }) => formatWindow(row.original.ts),
      }),
      columnHelper.accessor("flags", { header: "Flags", size: 74, cell: ({ getValue }) => getValue() || "-" }),
      columnHelper.display({ id: "info", header: "Info", size: 300, cell: ({ row }) => packetInfo(row.original) }),
    ],
    [packets.length, traffic.protocolCounts, traffic.totalBytes],
  );

  const table = useReactTable({
    data: packets,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });
  const rows = table.getRowModel().rows;
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
        <span>Packet list</span>
        <button className={follow ? "text-cyan-300" : "text-muted"} onClick={() => setFollow((value) => !value)}>
          <ArrowDownToLine className="mr-1 inline" size={12} /> Follow
        </button>
      </div>
      <div className="packet-header">
        {table.getFlatHeaders().map((header) => (
          <button
            key={header.id}
            className={`packet-cell text-left ${isColumnFiltered(header.column.id, filters) ? "filtered-header" : ""}`}
            style={{ width: header.getSize(), flexGrow: header.column.id === "info" ? 1 : 0 }}
            onClick={header.column.getToggleSortingHandler()}
          >
            {flexRender(header.column.columnDef.header, header.getContext())}
          </button>
        ))}
      </div>
      <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto">
        <div className="relative w-full" style={{ height: virtualizer.getTotalSize() }}>
          {virtualizer.getVirtualItems().map((virtualRow) => {
            const row = rows[virtualRow.index];
            const selected = row.original.id === selectedPacket?.id;
            return (
              <button
                key={row.id}
                className={`packet-row ${selected ? "packet-row-selected" : ""}`}
                style={{ transform: `translateY(${virtualRow.start}px)` }}
                onClick={() => onSelectPacket(row.original)}
              >
                {row.getVisibleCells().map((cell) => (
                  <span
                    key={cell.id}
                    className="packet-cell truncate text-left"
                    style={{ width: cell.column.getSize(), flexGrow: cell.column.id === "info" ? 1 : 0 }}
                  >
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </span>
                ))}
              </button>
            );
          })}
        </div>
      </div>
    </section>
  );
}

function endpoint(ip: string | null, port: number | null) {
  return `${ip ?? "-"}${port !== null ? `:${port}` : ""}`;
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
