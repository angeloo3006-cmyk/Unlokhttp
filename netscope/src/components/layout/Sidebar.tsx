import { Radio, Table2, BarChart2, FolderOpen } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAppState, type AppView } from "@/store";

interface NavItem {
  id:    AppView;
  icon:  React.ElementType;
  label: string;
}

const NAV: NavItem[] = [
  { id: "capture",     icon: Radio,      label: "Capture"     },
  { id: "packets",     icon: Table2,     label: "Packets"     },
  { id: "diagnostics", icon: BarChart2,  label: "Diagnostics" },
  { id: "sessions",    icon: FolderOpen, label: "Sessions"    },
];

export function Sidebar() {
  const { state, dispatch } = useAppState();

  return (
    <nav className="flex flex-col w-14 bg-surface border-r border-dim shrink-0 py-2 gap-1">
      {NAV.map(({ id, icon: Icon, label }) => {
        const active = state.view === id;
        return (
          <button
            key={id}
            title={label}
            onClick={() => dispatch({ type: "SET_VIEW", payload: id })}
            className={cn(
              "relative flex flex-col items-center justify-center gap-1 h-12 w-full",
              "text-[9px] font-ui uppercase tracking-widest transition-all duration-150",
              active
                ? "text-accent"
                : "text-subtle hover:text-muted-foreground"
            )}
          >
            {active && (
              <span className="absolute left-0 top-2 bottom-2 w-0.5 rounded-r bg-accent" />
            )}
            <Icon size={16} strokeWidth={active ? 2 : 1.5} />
            <span>{label}</span>
          </button>
        );
      })}
    </nav>
  );
}
