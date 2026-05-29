import { AlertTriangle, X } from "lucide-react";
import { useAppState } from "@/store";

export function ErrorBanner() {
  const { state, dispatch } = useAppState();
  if (!state.error) return null;

  return (
    <div className="flex items-center gap-2 px-4 py-2 bg-danger/10 border-b border-danger/30 text-danger text-xs animate-slidein">
      <AlertTriangle size={12} />
      <span className="flex-1 font-mono">{state.error}</span>
      <button
        onClick={() => dispatch({ type: "SET_ERROR", payload: null })}
        className="hover:text-foreground transition-colors"
      >
        <X size={12} />
      </button>
    </div>
  );
}
