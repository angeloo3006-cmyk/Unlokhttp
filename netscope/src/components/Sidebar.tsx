import { BarChart2, Database, Radio, Settings } from "lucide-react";
import type { Interface } from "@/lib/tauri";
import { cn } from "@/lib/utils";

export type AppView = "capture" | "sessions" | "diagnostics" | "settings";

interface SidebarProps {
  activeView: AppView;
  interfaces: Interface[];
  selectedInterfaceId: number;
  captureActive: boolean;
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
  onViewChange,
  onInterfaceSelect,
}: SidebarProps) {
  return (
    <aside className="glass-panel m-3 mr-0 flex w-[200px] shrink-0 flex-col overflow-hidden rounded-xl">
      <nav className="space-y-1 p-3">
        {navItems.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => onViewChange(id)}
            className={cn("nav-item", activeView === id && "nav-item-active")}
          >
            <Icon size={15} />
            {label}
          </button>
        ))}
      </nav>
      <div className="mt-2 border-t border-glass px-3 py-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted">
          Interfaces
        </p>
        <div className="space-y-1">
          {interfaces.length ? (
            interfaces.map((networkInterface) => (
              <button
                key={networkInterface.id}
                disabled={captureActive}
                onClick={() => onInterfaceSelect(networkInterface.id)}
                className={`block w-full truncate rounded-md px-2 py-1.5 text-left text-[11px] transition ${
                  selectedInterfaceId === networkInterface.id
                    ? "bg-blue-500/15 text-blue-100"
                    : "text-secondary hover:bg-white/5"
                }`}
              >
                <span className="mr-2 inline-block h-1.5 w-1.5 rounded-full bg-cyan-400/80" />
                {networkInterface.desc || networkInterface.name}
              </button>
            ))
          ) : (
            <p className="px-2 text-[11px] leading-5 text-muted">
              Interfaces appear when the sidecar starts.
            </p>
          )}
        </div>
      </div>
    </aside>
  );
}
