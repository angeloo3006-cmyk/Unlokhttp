import { useEffect, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import {
  EMPTY_FILTERS,
  useFiltersStore,
  type FilterState,
  type TcpFlag,
} from "@/store/filters";
import type { Protocol } from "@/types/packet";

const PROTOCOLS: Protocol[] = ["TCP", "UDP", "DNS", "HTTP", "HTTPS", "ICMP", "ARP", "OTHER"];
const FLAGS: TcpFlag[] = ["SYN", "ACK", "FIN", "RST", "PSH"];
const IPV4 = /^((25[0-5]|2[0-4]\d|1?\d?\d)(\.|$)){4}$/;

interface FilterModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function optionalNumber(value: string) {
  return value === "" ? null : Number(value);
}

export function FilterModal({ open, onOpenChange }: FilterModalProps) {
  const filters = useFiltersStore();
  const [draft, setDraft] = useState<FilterState>(filters);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) setDraft(filters);
  }, [open, filters]);

  const update = <K extends keyof FilterState>(key: K, value: FilterState[K]) => {
    setDraft((current) => ({ ...current, [key]: value }));
  };

  const apply = () => {
    if (draft.src_ip && !IPV4.test(draft.src_ip)) return setError("Source IP must be valid IPv4.");
    if (draft.dst_ip && !IPV4.test(draft.dst_ip)) return setError("Destination IP must be valid IPv4.");
    if ([draft.src_port, draft.dst_port].some((port) => port !== null && (port < 0 || port > 65535))) {
      return setError("Ports must be between 0 and 65535.");
    }
    if (
      draft.min_length !== null &&
      draft.max_length !== null &&
      draft.min_length > draft.max_length
    ) {
      return setError("Minimum length cannot exceed maximum length.");
    }
    filters.replaceFilters(draft);
    setError(null);
    onOpenChange(false);
  };

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/35 backdrop-blur-sm" />
        <Dialog.Content className="glass-panel fixed left-1/2 top-1/2 z-50 w-[640px] -translate-x-1/2 -translate-y-1/2 p-5 shadow-2xl">
          <div className="mb-5 flex items-start justify-between">
            <div>
              <Dialog.Title className="text-base font-semibold text-primary">Advanced filters</Dialog.Title>
              <Dialog.Description className="mt-1 text-xs text-secondary">
                Combine filters with AND logic over the local packet buffer.
              </Dialog.Description>
            </div>
            <Dialog.Close className="text-muted transition hover:text-white"><X size={16} /></Dialog.Close>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <label className="field-label">Source IP<input className="glass-input" value={draft.src_ip ?? ""} onChange={(e) => update("src_ip", e.target.value || null)} placeholder="192.168.1.10" /></label>
            <label className="field-label">Destination IP<input className="glass-input" value={draft.dst_ip ?? ""} onChange={(e) => update("dst_ip", e.target.value || null)} placeholder="1.1.1.1" /></label>
            <label className="field-label">Source port<input className="glass-input" type="number" min="0" max="65535" value={draft.src_port ?? ""} onChange={(e) => update("src_port", optionalNumber(e.target.value))} /></label>
            <label className="field-label">Destination port<input className="glass-input" type="number" min="0" max="65535" value={draft.dst_port ?? ""} onChange={(e) => update("dst_port", optionalNumber(e.target.value))} /></label>
            <label className="field-label">Minimum length<input className="glass-input" type="range" min="0" max="4096" value={draft.min_length ?? 0} onChange={(e) => update("min_length", Number(e.target.value) || null)} /><span>{draft.min_length ?? 0} bytes</span></label>
            <label className="field-label">Maximum length<input className="glass-input" type="range" min="0" max="4096" value={draft.max_length ?? 4096} onChange={(e) => update("max_length", Number(e.target.value) === 4096 ? null : Number(e.target.value))} /><span>{draft.max_length ?? 4096} bytes</span></label>
          </div>
          <div className="mt-4">
            <p className="field-label">Protocols</p>
            <div className="mt-2 flex flex-wrap gap-2">{PROTOCOLS.map((protocol) => <ToggleChip key={protocol} label={protocol} active={draft.protocols.includes(protocol)} onClick={() => update("protocols", draft.protocols.includes(protocol) ? draft.protocols.filter((value) => value !== protocol) : [...draft.protocols, protocol])} />)}</div>
          </div>
          <div className="mt-4">
            <p className="field-label">TCP flags</p>
            <div className="mt-2 flex flex-wrap gap-2">{FLAGS.map((flag) => <ToggleChip key={flag} label={flag} active={draft.flags.includes(flag)} onClick={() => update("flags", draft.flags.includes(flag) ? draft.flags.filter((value) => value !== flag) : [...draft.flags, flag])} />)}</div>
          </div>
          {error && <p className="mt-4 text-xs text-red-300">{error}</p>}
          <div className="mt-6 flex justify-end gap-2">
            <button className="button-ghost" onClick={() => { setDraft(EMPTY_FILTERS); filters.clearFilters(); }}>Clear all</button>
            <Dialog.Close className="button-ghost">Close</Dialog.Close>
            <button className="button-primary" onClick={apply}>Apply filters</button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function ToggleChip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return <button className={active ? "filter-chip filter-chip-active" : "filter-chip"} onClick={onClick}>{label}</button>;
}
