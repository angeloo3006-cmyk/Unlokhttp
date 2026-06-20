import { Check, RotateCcw } from "lucide-react";
import { useMemo } from "react";
import {
  PACKET_COLUMN_GROUPS,
  PACKET_TABLE_COLUMNS,
  getEffectivePacketColumnVisibility,
  type PacketTableColumnId,
  usePacketTableSettings,
} from "@/store/packetTable";

const PREVIEW_VALUES: Record<PacketTableColumnId, string> = {
  id: "411",
  ts: "16:33:41.872",
  src_ip: "192.168.1.73:63057",
  dst_ip: "34.0.132.103:50005",
  src_port: "63057",
  dst_port: "50005",
  protocol: "UDP",
  protocol_weight: "96.2%",
  length: "979",
  traffic: "979 B / 0.267%",
  window: "17/06 16:33",
  flags: "-",
  info: "979 bytes",
  local_full: "17/6/2026, 4:33:41 p.m.",
  utc_time: "2026-06-17T22:33:41.872Z",
  local_day: "17/06/2026",
  local_hour: "16",
  local_minute: "33",
  link_layer: "Ethernet",
  src_mac: "2c:f0:5d:b1:25:57",
  dst_mac: "f8:aa:3f:1d:88:e0",
  src_vendor: "Micro-Star INTL CO., LTD.",
  dst_vendor: "Dwnet Technologies(Suzhou) Corporation",
  ethernet_type: "0x0800 (IPv4)",
  ip_source: "192.168.1.73",
  ip_destination: "34.0.132.103",
  ttl: "128",
  protocol_number: "17 (UDP)",
  frame_length: "979 bytes",
  captured_length: "979 bytes",
  visible_index: "412 of 547",
  connection_role: "Datagram",
  payload_hex_bytes: "256 bytes",
  raw_ascii: "OPTIONS * HTTP/1.1..Host",
  payload_hex: "4f5054494f4e53202a20485454502f312e31",
};

export function SettingsView() {
  const columnVisibility = usePacketTableSettings((state) => state.columnVisibility);
  const columnSizing = usePacketTableSettings((state) => state.columnSizing);
  const setColumnVisible = usePacketTableSettings((state) => state.setColumnVisible);
  const resetDefaults = usePacketTableSettings((state) => state.resetDefaults);

  const effectiveColumnVisibility = useMemo(
    () => getEffectivePacketColumnVisibility(columnVisibility),
    [columnVisibility],
  );
  const optionalGroups = PACKET_COLUMN_GROUPS.map((group) => ({
    group,
    columns: PACKET_TABLE_COLUMNS.filter((column) => column.group === group && !column.required),
  })).filter(({ columns }) => columns.length > 0);
  const visibleColumns = PACKET_TABLE_COLUMNS.filter((column) => effectiveColumnVisibility[column.id]);
  const tableWidth = visibleColumns.reduce((sum, column) => sum + (columnSizing[column.id] ?? column.defaultSize), 0);

  return (
    <div className="h-full overflow-auto p-2">
      <section className="glass-panel p-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Settings</p>
            <h1 className="mt-0.5 text-lg font-semibold">Packet table columns</h1>
            <p className="mt-1 max-w-3xl text-xs text-secondary">
              Core packet columns stay visible. Enable extra fields only when you want deeper inspection directly in the table.
            </p>
          </div>
          <button className="button-ghost" onClick={resetDefaults} type="button">
            <RotateCcw size={13} />
            Reset defaults
          </button>
        </div>

        <div className="mt-3 rounded-2xl border border-white/[0.055] bg-black/[0.08] p-3">
          <div className="grid gap-x-8 gap-y-3 lg:grid-cols-3">
            {optionalGroups.map(({ group, columns }) => (
              <div key={group}>
                <p className="mb-2 px-0.5 text-[10px] uppercase tracking-[0.19em] text-white/34">{group}</p>
                <div className="grid gap-1">
                  {columns.map((column) => {
                    const visible = effectiveColumnVisibility[column.id];
                    return (
                      <button
                        aria-pressed={visible}
                        className={`group flex min-w-0 items-center gap-2 rounded-md px-1 py-0.5 text-left text-[11px] outline-none transition focus-visible:ring-1 focus-visible:ring-cyan-300/40 ${
                          visible
                            ? "text-primary"
                            : "text-secondary hover:text-primary"
                        }`}
                        key={column.id}
                        onClick={() => setColumnVisible(column.id, !visible)}
                        type="button"
                      >
                        <span
                          className={`flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-[4px] border transition ${
                            visible
                              ? "border-cyan-300/70 bg-sky-500/85 text-white/90 shadow-[0_0_0_2px_rgba(14,165,233,0.16)]"
                              : "border-white/20 bg-transparent text-transparent group-hover:border-white/34"
                          }`}
                        >
                          <Check className="translate-y-[-0.25px]" size={9.5} strokeWidth={3.4} />
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="flex min-w-0 items-baseline gap-1.5">
                            <span className="truncate font-medium text-white/82">{column.label}</span>
                          </span>
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="mt-3 glass-surface min-w-0 p-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-[10px] uppercase tracking-[0.16em] text-muted">Full table preview</p>
              <p className="mt-1 text-[11px] text-secondary">
                Preview of the capture table with required defaults plus the optional fields enabled above.
              </p>
            </div>
            <div className="text-right text-[11px] text-secondary">
              <p>{visibleColumns.length} visible columns</p>
              <p className="font-mono text-muted">{tableWidth}px table width</p>
            </div>
          </div>

          <div className="mt-4 overflow-auto rounded-lg border border-white/10 bg-black/15 p-3">
            <div className="packet-header" style={{ minWidth: tableWidth, position: "static" }}>
              {visibleColumns.map((column) => {
                const width = columnSizing[column.id] ?? column.defaultSize;
                return (
                  <div
                    className={`packet-cell packet-header-cell text-left ${column.required ? "text-primary" : "filtered-header"}`}
                    key={column.id}
                    style={{ width }}
                  >
                    <span className="truncate">{column.label}</span>
                  </div>
                );
              })}
            </div>
            <div className="packet-row mt-1" style={{ minWidth: tableWidth, position: "static" }}>
              {visibleColumns.map((column) => {
                const width = columnSizing[column.id] ?? column.defaultSize;
                return (
                  <span className="packet-cell truncate text-left" key={column.id} style={{ width }}>
                    {PREVIEW_VALUES[column.id]}
                  </span>
                );
              })}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
