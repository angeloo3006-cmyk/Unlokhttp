import { BarChart2, Database, Radio, Settings } from "lucide-react";
import type { Interface } from "@/lib/tauri";
import { cn } from "@/lib/utils";

export type AppView = "capture" | "sessions" | "diagnostics" | "settings";

interface SidebarProps {
  activeView: AppView;
  interfaces: Interface[];
  selectedInterfaceId: number;
  captureActive: boolean;
  compact?: boolean;
  onViewChange: (view: AppView) => void;
  onInterfaceSelect: (interfaceId: number) => void;
}

const navItems = [
  { id: "capture", label: "Capture", icon: Radio },
  { id: "sessions", label: "Sessions", icon: Database },
  { id: "diagnostics", label: "Diagnostics", icon: BarChart2 },
  { id: "settings", label: "Settings", icon: Settings },
] satisfies Array<{ id: AppView; label: string; icon: typeof Radio }>;

export function Sidebar({
  activeView,
  interfaces,
  selectedInterfaceId,
  captureActive,
  compact = false,
  onViewChange,
  onInterfaceSelect,
}: SidebarProps) {
  return (
    <aside className={`glass-panel flex h-full w-full flex-col overflow-hidden rounded-xl ${compact ? "items-center" : ""}`}>
      <nav className={`space-y-1 ${compact ? "p-2" : "p-3"}`}>
        {navItems.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => onViewChange(id)}
            className={cn(
              "nav-item",
              compact && "nav-item-compact",
              activeView === id && "nav-item-active",
            )}
            title={compact ? label : undefined}
          >
            <Icon size={15} />
            {!compact && label}
          </button>
        ))}
      </nav>
      <div className={`mt-2 w-full border-t border-glass ${compact ? "px-2 py-2" : "px-3 py-3"}`}>
        {!compact && (
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted">
            Interfaces
          </p>
        )}
        <div className={`space-y-1 ${compact ? "flex flex-col items-center" : ""}`}>
          {interfaces.length ? (
            interfaces.map((networkInterface) => (
              <button
                key={networkInterface.id}
                disabled={captureActive}
                onClick={() => onInterfaceSelect(networkInterface.id)}
                className={`block truncate rounded-md text-[11px] transition ${
                  compact ? "h-8 w-8 px-0 py-0 text-center" : "w-full px-2 py-1.5 text-left"
                } ${
                  selectedInterfaceId === networkInterface.id
                    ? "bg-blue-500/15 text-blue-100"
                    : "text-secondary hover:bg-white/5"
                }`}
                title={networkInterface.desc || networkInterface.name}
              >
                <span className={`${compact ? "mx-auto" : "mr-2"} inline-block h-1.5 w-1.5 rounded-full bg-cyan-400/80`} />
                {!compact && (networkInterface.desc || networkInterface.name)}
              </button>
            ))
          ) : (
            compact ? (
              <span className="mt-1 h-1.5 w-1.5 rounded-full bg-white/20" title="Interfaces appear when the sidecar starts." />
            ) : (
              <p className="px-2 text-[11px] leading-5 text-muted">
                Interfaces appear when the sidecar starts.
              </p>
            )
          )}
        </div>
      </div>
    </aside>
  );
}
