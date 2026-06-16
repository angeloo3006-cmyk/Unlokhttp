import { Fragment, useEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from "react";
import { Group, Panel, Separator, usePanelRef, type PanelImperativeHandle } from "react-resizable-panels";
import {
  Activity,
  Clock3,
  Database,
  Maximize2,
  Minimize2,
  Minus,
  Network,
  RefreshCw,
  Search,
  Trash2,
  type LucideIcon,
} from "lucide-react";
import { HexViewer } from "@/components/HexViewer";
import { PacketDetail } from "@/components/PacketDetail";
import { PacketList } from "@/components/PacketList";
import { interfaceDisplayName } from "@/lib/interfaces";
import { getDiagnosticsData, queryPackets, type DiagnosticsData, type Interface, type Session } from "@/lib/tauri";
import { packetRowToPacket, toProtocol } from "@/lib/packetRows";
import { getSessionStatusColor } from "@/utils/status";
import type { Packet } from "@/types/packet";

const PAGE_SIZE = 500;
type FocusPanel = "time" | "protocol" | "origins" | "packets" | null;
type OverviewPanel = Exclude<FocusPanel, "packets" | null>;

interface SessionDetailViewProps {
  session: Session | null;
  interfaces: Interface[];
  onRefreshSessions: () => void;
  onDeleteSession: (sessionId: number) => Promise<void>;
}

export function SessionDetailView({ session, interfaces, onRefreshSessions, onDeleteSession }: SessionDetailViewProps) {
  const [diagnostics, setDiagnostics] = useState<DiagnosticsData | null>(null);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalPackets, setTotalPackets] = useState(0);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [focusPanel, setFocusPanel] = useState<FocusPanel>(null);
  const [packetExplorerMinimized, setPacketExplorerMinimized] = useState(false);
  const [minimizedOverviewPanels, setMinimizedOverviewPanels] = useState<Record<OverviewPanel, boolean>>({
    time: false,
    protocol: false,
    origins: false,
  });
  const headerPanelRef = usePanelRef();
  const overviewPanelRef = usePanelRef();
  const timePanelRef = usePanelRef();
  const protocolPanelRef = usePanelRef();
  const originsPanelRef = usePanelRef();
  const overviewPanelRefs = useMemo<Record<OverviewPanel, RefObject<PanelImperativeHandle | null>>>(() => ({
    time: timePanelRef,
    protocol: protocolPanelRef,
    origins: originsPanelRef,
  }), [originsPanelRef, protocolPanelRef, timePanelRef]);

  useEffect(() => {
    setPage(1);
    setSearch("");
    setSelectedPacket(null);
    setFocusPanel(null);
    setPacketExplorerMinimized(false);
    setMinimizedOverviewPanels({ time: false, protocol: false, origins: false });
  }, [session?.id]);

  useEffect(() => {
    if (!session) {
      setDiagnostics(null);
      setPackets([]);
      setTotalPackets(0);
      setTotalPages(1);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    const filters = search.trim() ? { search: search.trim() } : {};

    Promise.all([
      getDiagnosticsData(session.id),
      queryPackets({
        sessionId: session.id,
        filters,
        page,
        pageSize: PAGE_SIZE,
      }),
    ])
      .then(([diagnosticsData, packetPage]) => {
        if (cancelled) return;

        const nextPackets = packetPage.items.map(packetRowToPacket);
        setDiagnostics(diagnosticsData);
        setPackets(nextPackets);
        setTotalPackets(packetPage.total);
        setTotalPages(Math.max(1, packetPage.total_pages));
        setSelectedPacket((current) => {
          if (current && nextPackets.some((packet) => packet.id === current.id)) return current;
          return nextPackets[0] ?? null;
        });
      })
      .catch((err) => {
        if (!cancelled) setError(String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [page, search, session]);

  const windowInfo = useMemo(() => buildWindowInfo(session, diagnostics), [diagnostics, session]);
  const protocolRows = diagnostics?.protocol_stats ?? [];
  const maxProtocolCount = Math.max(1, ...protocolRows.map((item) => item.count));
  const maxOriginCount = Math.max(
    1,
    ...(diagnostics?.top_src_ips ?? []).map((item) => item.count),
    ...(diagnostics?.top_dst_ips ?? []).map((item) => item.count),
  );
  const trafficSummary = useMemo(() => {
    const protocolCounts = new Map<Packet["protocol"], number>();
    for (const item of protocolRows) {
      protocolCounts.set(toProtocol(item.protocol), item.count);
    }

    return {
      totalPackets: diagnostics?.total_packets ?? packets.length,
      totalBytes: diagnostics?.total_bytes ?? packets.reduce((sum, packet) => sum + packet.length, 0),
      protocolCounts,
    };
  }, [diagnostics, packets, protocolRows]);
  const showOverviewPanels = focusPanel !== "packets";
  const overviewIsFocused = focusPanel === "time" || focusPanel === "protocol" || focusPanel === "origins";
  const visibleOverviewPanels = (["time", "protocol", "origins"] as OverviewPanel[]).filter(
    (panel) => !minimizedOverviewPanels[panel],
  );
  const resizeOverviewPanels = (focused: OverviewPanel | null) => {
    window.requestAnimationFrame(() => {
      overviewPanelRef.current?.resize(focused ? 40 : 22);
      if (!focused) {
        for (const panel of ["time", "protocol", "origins"] as OverviewPanel[]) {
          if (!minimizedOverviewPanels[panel]) overviewPanelRefs[panel].current?.resize(100 / Math.max(1, visibleOverviewPanels.length));
        }
        return;
      }

      for (const panel of ["time", "protocol", "origins"] as OverviewPanel[]) {
        if (minimizedOverviewPanels[panel]) continue;
        overviewPanelRefs[panel].current?.resize(panel === focused ? 68 : 16);
      }
    });
  };
  const handleOverviewFocusChange = (panel: FocusPanel) => {
    setFocusPanel(panel);
    if (panel === "time" || panel === "protocol" || panel === "origins") {
      setMinimizedOverviewPanels((current) => ({ ...current, [panel]: false }));
      resizeOverviewPanels(panel);
      return;
    }
    resizeOverviewPanels(null);
  };
  const restoreOverviewPanel = (panel: OverviewPanel) => {
    setMinimizedOverviewPanels((current) => ({ ...current, [panel]: false }));
    window.requestAnimationFrame(() => {
      overviewPanelRef.current?.resize(22);
      overviewPanelRefs[panel].current?.resize(34);
    });
  };
  const minimizeOverviewPanel = (panel: OverviewPanel) => {
    setFocusPanel((current) => (current === panel ? null : current));
    setMinimizedOverviewPanels((current) => ({ ...current, [panel]: true }));
    resizeOverviewPanels(null);
  };

  if (!session) {
    return (
      <section className="glass-panel flex min-w-0 flex-1 items-center justify-center p-6 text-sm text-secondary">
        Select a saved session to inspect its packets, diagnostics, and raw payloads.
      </section>
    );
  }

  return (
    <section className="min-h-0 flex-1 overflow-hidden">
      <Group orientation="vertical" className="min-h-0">
        <Panel panelRef={headerPanelRef} defaultSize="112px" minSize="52px" maxSize="170px">
          <SessionHeader
            diagnostics={diagnostics}
            error={error}
            interfaceLabel={interfaceDisplayName(session.interface, interfaces)}
            session={session}
            windowInfo={windowInfo}
            onDeleteSession={onDeleteSession}
            onRefreshSessions={onRefreshSessions}
          />
        </Panel>
        <ResizeHandle />
          {showOverviewPanels && (
            <>
              <Panel
                panelRef={overviewPanelRef}
                defaultSize={overviewIsFocused ? "280px" : "150px"}
                minSize="58px"
                maxSize="520px"
              >
                <OverviewPanels
                  focusPanel={focusPanel}
                  maxOriginCount={maxOriginCount}
                  maxProtocolCount={maxProtocolCount}
                  minimizedPanels={minimizedOverviewPanels}
                  protocolRows={protocolRows}
                  topDstIps={diagnostics?.top_dst_ips ?? []}
                  topSrcIps={diagnostics?.top_src_ips ?? []}
                  totalPackets={diagnostics?.total_packets ?? 0}
                  visiblePanels={visibleOverviewPanels}
                  panelRefs={overviewPanelRefs}
                  windowInfo={windowInfo}
                  onFocusChange={handleOverviewFocusChange}
                  onMinimize={minimizeOverviewPanel}
                  onRestore={restoreOverviewPanel}
                />
              </Panel>
              <ResizeHandle />
            </>
          )}

          {!packetExplorerMinimized ? (
            <Panel minSize="180px">
              <PacketExplorer
                focusPanel={focusPanel}
                loading={loading}
                packets={packets}
                selectedPacket={selectedPacket}
                search={search}
                totalPackets={totalPackets}
                totalPages={totalPages}
                page={page}
                trafficSummary={trafficSummary}
                onFocusChange={setFocusPanel}
                onMinimize={() => {
                  setFocusPanel(null);
                  setPacketExplorerMinimized(true);
                }}
                onPageChange={setPage}
                onSearchChange={(value) => {
                  setSearch(value);
                  setPage(1);
                }}
                onSelectPacket={setSelectedPacket}
              />
            </Panel>
          ) : (
            <Panel defaultSize="38px" minSize="38px" maxSize="38px">
              <CollapsedPanelBar
                label="Session packet explorer"
                meta={`${packets.length}/${totalPackets}`}
                onRestore={() => setPacketExplorerMinimized(false)}
              />
            </Panel>
          )}
      </Group>
    </section>
  );
}

function SessionHeader({
  diagnostics,
  error,
  interfaceLabel,
  session,
  windowInfo,
  onDeleteSession,
  onRefreshSessions,
}: {
  diagnostics: DiagnosticsData | null;
  error: string | null;
  interfaceLabel: string;
  session: Session;
  windowInfo: ReturnType<typeof buildWindowInfo>;
  onDeleteSession: (sessionId: number) => Promise<void>;
  onRefreshSessions: () => void;
}) {
  const rootRef = useRef<HTMLDivElement>(null);
  const height = useElementHeight(rootRef);
  const compact = height < 96;
  const mini = height < 70;
  const titleSize = clampNumber(height * 0.13, 10, 15);
  const labelSize = clampNumber(height * 0.085, 7, 9);
  const bodySize = clampNumber(height * 0.1, 8.5, 11);
  const metricSize = clampNumber(height * 0.135, 11, 15);

  return (
    <div ref={rootRef} className={`glass-panel container-inline flex h-full min-h-0 flex-col overflow-hidden px-4 ${mini ? "py-2" : "py-3"}`}>
      <div className="flex min-h-0 items-start justify-between gap-3">
        <div className="min-w-0">
          {!mini && (
            <p className="uppercase tracking-[0.2em] text-muted" style={{ fontSize: labelSize }}>
              Database session
            </p>
          )}
          <h2 className={`${mini ? "mt-0" : "mt-1"} truncate font-semibold`} style={{ fontSize: titleSize, lineHeight: 1.12 }}>
            {session.name ?? `Session #${session.id}`}
          </h2>
          {!mini && (
            <p className="mt-1 flex items-center gap-1.5 truncate text-secondary" style={{ fontSize: bodySize, lineHeight: 1.2 }}>
              <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${getSessionStatusColor(session)}`} />
              {interfaceLabel}
            </p>
          )}
        </div>
        <div className="flex shrink-0 gap-2">
          <button className="button-ghost px-2.5 py-1.5" onClick={onRefreshSessions} title="Refresh session">
            <RefreshCw size={12} /> {!mini && "Refresh"}
          </button>
          <button className="button-danger px-2.5 py-1.5" onClick={() => void onDeleteSession(session.id)} title="Delete session">
            <Trash2 size={12} /> {!mini && "Delete"}
          </button>
        </div>
      </div>

      {error ? (
        <button
          className="mt-2 truncate rounded-md border border-red-300/15 bg-red-500/10 px-2 py-1 text-left text-[11px] text-red-100"
          title={error}
        >
          {error}
        </button>
      ) : !compact ? (
        <div className="mt-auto grid grid-cols-4 gap-3 pt-2">
          <MetricCardFluid icon={Database} label="Packets" labelSize={labelSize} value={(diagnostics?.total_packets ?? session.total_packets).toLocaleString()} valueSize={metricSize} />
          <MetricCardFluid icon={Activity} label="Traffic" labelSize={labelSize} value={formatBytes(diagnostics?.total_bytes ?? 0)} valueSize={metricSize} />
          <MetricCardFluid icon={Network} label="Avg packet" labelSize={labelSize} value={formatBytes(diagnostics?.avg_packet_size ?? 0)} valueSize={metricSize} />
          <MetricCardFluid icon={Clock3} label="Duration" labelSize={labelSize} value={windowInfo.duration} valueSize={metricSize} />
        </div>
      ) : !mini ? (
        <div className="mt-auto flex min-w-0 items-center gap-4 pt-1 text-secondary" style={{ fontSize: bodySize }}>
          <span className="truncate"><span className="text-primary">{(diagnostics?.total_packets ?? session.total_packets).toLocaleString()}</span> packets</span>
          <span className="truncate"><span className="text-primary">{formatBytes(diagnostics?.total_bytes ?? 0)}</span> traffic</span>
          <span className="truncate"><span className="text-primary">{windowInfo.duration}</span> duration</span>
        </div>
      ) : null}
    </div>
  );
}

function MetricCardFluid({
  icon: Icon,
  label,
  labelSize,
  value,
  valueSize,
}: {
  icon: LucideIcon;
  label: string;
  labelSize: number;
  value: string;
  valueSize: number;
}) {
  return (
    <div className="min-w-0 border-l border-white/10 pl-3 first:border-l-0 first:pl-0">
      <div className="flex items-center gap-1.5 uppercase tracking-[0.14em] text-muted" style={{ fontSize: labelSize }}>
        <Icon size={11} /> {label}
      </div>
      <p className="mt-1 truncate font-semibold" style={{ fontSize: valueSize, lineHeight: 1.1 }}>{value}</p>
    </div>
  );
}

function useElementHeight(ref: RefObject<HTMLElement | null>) {
  const [height, setHeight] = useState(999);

  useEffect(() => {
    const element = ref.current;
    if (!element) return;

    const updateHeight = () => setHeight(element.getBoundingClientRect().height);
    updateHeight();

    const observer = new ResizeObserver(updateHeight);
    observer.observe(element);
    return () => observer.disconnect();
  }, [ref]);

  return height;
}

function clampNumber(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

interface OverviewPanelsProps {
  focusPanel: FocusPanel;
  maxOriginCount: number;
  maxProtocolCount: number;
  minimizedPanels: Record<OverviewPanel, boolean>;
  protocolRows: DiagnosticsData["protocol_stats"];
  topDstIps: DiagnosticsData["top_dst_ips"];
  topSrcIps: DiagnosticsData["top_src_ips"];
  totalPackets: number;
  visiblePanels: OverviewPanel[];
  panelRefs: Record<OverviewPanel, RefObject<PanelImperativeHandle | null>>;
  windowInfo: ReturnType<typeof buildWindowInfo>;
  onFocusChange: (panel: FocusPanel) => void;
  onMinimize: (panel: OverviewPanel) => void;
  onRestore: (panel: OverviewPanel) => void;
}

function OverviewPanels({
  focusPanel,
  maxOriginCount,
  maxProtocolCount,
  minimizedPanels,
  protocolRows,
  topDstIps,
  topSrcIps,
  totalPackets,
  visiblePanels,
  panelRefs,
  windowInfo,
  onFocusChange,
  onMinimize,
  onRestore,
}: OverviewPanelsProps) {
  const minimizedEntries = (Object.entries(minimizedPanels) as Array<[OverviewPanel, boolean]>)
    .filter(([, minimized]) => minimized)
    .map(([panel]) => panel);

  if (!visiblePanels.length) {
    return (
      <div className="glass-panel flex h-full min-h-0 items-center gap-2 overflow-hidden px-3">
        <span className="text-[10px] uppercase tracking-[0.18em] text-muted">Minimized</span>
        {minimizedEntries.map((panel) => (
          <button className="button-ghost px-2 py-1 text-[10px]" key={panel} onClick={() => onRestore(panel)} title={`Restore ${panelLabel(panel)}`}>
            <Maximize2 size={11} />
            {panelLabel(panel)}
          </button>
        ))}
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col gap-2">
      {minimizedEntries.length > 0 && (
        <div className="flex shrink-0 items-center gap-2">
          <span className="text-[10px] uppercase tracking-[0.18em] text-muted">Minimized</span>
          {minimizedEntries.map((panel) => (
            <button className="button-ghost px-2 py-1 text-[10px]" key={panel} onClick={() => onRestore(panel)} title={`Restore ${panelLabel(panel)}`}>
              <Maximize2 size={11} />
              {panelLabel(panel)}
            </button>
          ))}
        </div>
      )}

      <div className="min-h-0 flex-1">
        <Group orientation="horizontal">
          {visiblePanels.map((panel, index) => (
            <Fragment key={panel}>
              <Panel panelRef={panelRefs[panel]} defaultSize={100 / visiblePanels.length} minSize={12}>
                <SmallPanel
                  title={panelLabel(panel)}
                  panelKey={panel}
                  focusPanel={focusPanel}
                  onFocusChange={onFocusChange}
                  onMinimize={onMinimize}
                >
                  {panel === "time" && (
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <InfoCell label="Start day" value={windowInfo.startDay} />
                      <InfoCell label="End day" value={windowInfo.endDay} />
                      <InfoCell label="Start hour" value={windowInfo.startHour} />
                      <InfoCell label="End hour" value={windowInfo.endHour} />
                      <InfoCell label="Start min" value={windowInfo.startMinute} />
                      <InfoCell label="End min" value={windowInfo.endMinute} />
                    </div>
                  )}

                  {panel === "protocol" && (
                    <div className="space-y-2">
                      {protocolRows.length ? (
                        protocolRows.map((item) => {
                          const percent = ((item.count / Math.max(1, totalPackets)) * 100).toFixed(1);
                          return (
                            <div key={item.protocol}>
                              <div className="mb-1 flex justify-between text-[11px]">
                                <span className="text-primary">{item.protocol}</span>
                                <span className="text-secondary">{percent}% / {item.count.toLocaleString()}</span>
                              </div>
                              <div className="h-1.5 rounded-full bg-white/5">
                                <div className="h-full rounded-full bg-cyan-400" style={{ width: `${(item.count / maxProtocolCount) * 100}%` }} />
                              </div>
                            </div>
                          );
                        })
                      ) : (
                        <EmptyText text="No protocol data yet." />
                      )}
                    </div>
                  )}

                  {panel === "origins" && (
                    <>
                      <OriginList title="Sources" rows={topSrcIps} max={maxOriginCount} />
                      <div className="mt-3 border-t border-glass pt-3">
                        <OriginList title="Destinations" rows={topDstIps} max={maxOriginCount} />
                      </div>
                    </>
                  )}
                </SmallPanel>
              </Panel>
              {index < visiblePanels.length - 1 && <HorizontalResizeHandle />}
            </Fragment>
          ))}
        </Group>
      </div>
    </div>
  );
}

interface PacketExplorerProps {
  focusPanel: FocusPanel;
  loading: boolean;
  packets: Packet[];
  selectedPacket: Packet | null;
  search: string;
  totalPackets: number;
  totalPages: number;
  page: number;
  trafficSummary: {
    totalPackets: number;
    totalBytes: number;
    protocolCounts: Map<Packet["protocol"], number>;
  };
  onFocusChange: (panel: FocusPanel) => void;
  onMinimize: () => void;
  onPageChange: (updater: (page: number) => number) => void;
  onSearchChange: (value: string) => void;
  onSelectPacket: (packet: Packet) => void;
}

function PacketExplorer({
  focusPanel,
  loading,
  packets,
  selectedPacket,
  search,
  totalPackets,
  totalPages,
  page,
  trafficSummary,
  onFocusChange,
  onMinimize,
  onPageChange,
  onSearchChange,
  onSelectPacket,
}: PacketExplorerProps) {
  const isFocused = focusPanel === "packets";

  return (
    <div className="glass-panel flex h-full min-h-0 flex-col overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-glass p-3">
        <div>
          <p className="text-[11px] uppercase tracking-[0.18em] text-muted">Session packet explorer</p>
          <p className="mt-1 text-[10px] text-secondary">
            {packets.length.toLocaleString()}/{totalPackets.toLocaleString()}
          </p>
        </div>
        <form
          className="flex min-w-0 flex-1 justify-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            onPageChange(() => 1);
          }}
        >
          <div className="relative min-w-[160px] max-w-[420px] flex-1">
            <Search className="pointer-events-none absolute left-2 top-2 text-muted" size={13} />
            <input
              className="glass-input pl-7"
              placeholder="Search IP, protocol, MAC or vendor"
              value={search}
              onChange={(event) => onSearchChange(event.target.value)}
            />
          </div>
          <button className="button-icon-plain" type="button" onClick={onMinimize} title="Minimize packet explorer">
            <Minus size={13} />
          </button>
          <button
            className="button-icon-plain"
            type="button"
            onClick={() => onFocusChange(isFocused ? null : "packets")}
            title={isFocused ? "Restore packet explorer" : "Maximize packet explorer"}
          >
            {isFocused ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
          </button>
        </form>
      </div>

      <div className="min-h-0 flex-1 overflow-hidden">
        <Group orientation="vertical">
          <Panel defaultSize={isFocused ? 62 : 46} minSize={10}>
            <PacketList
              packets={packets}
              selectedPacket={selectedPacket}
              onSelectPacket={onSelectPacket}
              title={loading ? "Loading SQLite packets..." : "Packets from SQLite"}
              showFollow={false}
              trafficSummary={trafficSummary}
            />
          </Panel>
          <ResizeHandle />
          <Panel defaultSize={isFocused ? 24 : 32} minSize={8}>
            <PacketDetail selectedPacket={selectedPacket} packets={packets} />
          </Panel>
          <ResizeHandle />
          <Panel defaultSize={isFocused ? 14 : 22} minSize={5}>
            <HexViewer payload_hex={selectedPacket?.payload_hex ?? ""} raw_ascii={selectedPacket?.raw_ascii ?? ""} />
          </Panel>
        </Group>
      </div>

      <div className="flex items-center justify-between border-t border-glass p-3 text-xs text-secondary">
        <span>Page {page} / {totalPages}</span>
        {totalPages > 1 && (
          <div className="flex gap-2">
            <button className="button-ghost" disabled={page <= 1 || loading} onClick={() => onPageChange((value) => Math.max(1, value - 1))}>
              Previous
            </button>
            <button className="button-ghost" disabled={page >= totalPages || loading} onClick={() => onPageChange((value) => Math.min(totalPages, value + 1))}>
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function SmallPanel({
  title,
  panelKey,
  focusPanel,
  onFocusChange,
  onMinimize,
  children,
}: {
  title: string;
  panelKey: OverviewPanel;
  focusPanel: FocusPanel;
  onFocusChange: (panel: FocusPanel) => void;
  onMinimize: (panel: OverviewPanel) => void;
  children: ReactNode;
}) {
  const isFocused = focusPanel === panelKey;

  return (
    <section className="glass-panel flex min-h-0 flex-col overflow-hidden p-3">
      <div className="mb-3 flex items-center justify-between gap-2">
        <h3 className="text-[10px] uppercase tracking-[0.18em] text-muted">{title}</h3>
        <div className="flex gap-1">
          <button className="button-icon-plain" onClick={() => onMinimize(panelKey)} title={`Minimize ${title}`}>
            <Minus size={12} />
          </button>
          <button
            className="button-icon-plain"
            onClick={() => onFocusChange(isFocused ? null : panelKey)}
            title={isFocused ? `Restore ${title}` : `Maximize ${title}`}
          >
            {isFocused ? <Minimize2 size={12} /> : <Maximize2 size={12} />}
          </button>
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {children}
      </div>
    </section>
  );
}

function InfoCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-white/5 bg-white/[0.025] p-2">
      <p className="text-[10px] uppercase tracking-[0.14em] text-muted">{label}</p>
      <p className="mt-1 truncate text-primary">{value}</p>
    </div>
  );
}

function CollapsedPanelBar({ label, meta, onRestore }: { label: string; meta?: string; onRestore: () => void }) {
  return (
    <div className="glass-panel flex h-full items-center justify-between px-3">
      <div className="min-w-0">
        <span className="text-[10px] uppercase tracking-[0.18em] text-muted">{label}</span>
        {meta && <span className="ml-2 text-[10px] text-secondary">{meta}</span>}
      </div>
      <button className="button-icon-plain" onClick={onRestore} title={`Restore ${label}`}>
        <Maximize2 size={12} />
      </button>
    </div>
  );
}

function HorizontalResizeHandle() {
  return (
    <Separator className="resize-handle resize-handle-x">
      <span />
    </Separator>
  );
}

function panelLabel(panel: OverviewPanel) {
  if (panel === "time") return "Time window";
  if (panel === "protocol") return "Protocol weight";
  return "Origins";
}

function OriginList({ title, rows, max }: { title: string; rows: Array<{ ip: string; count: number }>; max: number }) {
  return (
    <div>
      <p className="mb-2 text-[10px] uppercase tracking-[0.16em] text-muted">{title}</p>
      <div className="space-y-2">
        {rows.length ? (
          rows.slice(0, 5).map((row) => (
            <div key={`${title}-${row.ip}`}>
              <div className="mb-1 flex justify-between gap-2 text-[11px]">
                <span className="truncate font-mono text-primary">{row.ip}</span>
                <span className="text-secondary">{row.count.toLocaleString()}</span>
              </div>
              <div className="h-1.5 rounded-full bg-white/5">
                <div className="h-full rounded-full bg-blue-400" style={{ width: `${(row.count / max) * 100}%` }} />
              </div>
            </div>
          ))
        ) : (
          <EmptyText text="No origin data yet." />
        )}
      </div>
    </div>
  );
}

function EmptyText({ text }: { text: string }) {
  return <p className="rounded-lg border border-white/5 bg-white/[0.025] p-3 text-xs text-secondary">{text}</p>;
}

function ResizeHandle() {
  return (
    <Separator className="resize-handle resize-handle-y">
      <span />
    </Separator>
  );
}

function buildWindowInfo(session: Session | null, diagnostics: DiagnosticsData | null) {
  const timeline = diagnostics?.traffic_timeline ?? [];
  const start = parseDate(session?.started_at ?? timeline[0]?.bucket ?? null);
  const end = parseDate(session?.ended_at ?? timeline[timeline.length - 1]?.bucket ?? null);
  const startParts = start ? splitTimestamp(start.toISOString()) : null;
  const endParts = end ? splitTimestamp(end.toISOString()) : null;

  return {
    startDay: startParts?.day ?? "-",
    endDay: endParts?.day ?? "-",
    startHour: startParts?.hour ?? "-",
    endHour: endParts?.hour ?? "-",
    startMinute: startParts?.minute ?? "-",
    endMinute: endParts?.minute ?? "-",
    duration: start && end ? formatDuration(end.getTime() - start.getTime()) : "Open",
  };
}

function splitTimestamp(ts: string) {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) {
    return { day: "-", hour: "-", minute: "-" };
  }
  return {
    day: date.toLocaleDateString([], { month: "2-digit", day: "2-digit" }),
    hour: date.toLocaleTimeString([], { hour: "2-digit", hour12: false }),
    minute: date.toLocaleTimeString([], { minute: "2-digit" }),
  };
}

function parseDate(value: string | null) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatDuration(ms: number) {
  if (!Number.isFinite(ms) || ms < 0) return "Open";
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  if (hours > 0) return `${hours}h ${mins}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
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
