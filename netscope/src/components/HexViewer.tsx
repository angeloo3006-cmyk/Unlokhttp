import { useEffect, useMemo, useState } from "react";

export function HexViewer({ payload_hex, raw_ascii }: { payload_hex: string; raw_ascii: string }) {
  const [hoveredByte, setHoveredByte] = useState<number | null>(null);
  const [selectedRange, setSelectedRange] = useState<[number, number] | null>(null);
  const bytes = useMemo(() => payload_hex.match(/.{1,2}/g)?.slice(0, 256) ?? [], [payload_hex]);

  useEffect(() => {
    const handler = (event: Event) => setSelectedRange((event as CustomEvent<[number, number]>).detail);
    window.addEventListener("netscope-highlight-bytes", handler);
    return () => window.removeEventListener("netscope-highlight-bytes", handler);
  }, []);

  if (!bytes.length) return <div className="h-full" />;

  return (
    <section className="h-full overflow-auto p-3 font-mono text-[11px] leading-5">
      <div className="mb-1 grid grid-cols-[52px_420px_1fr] text-[10px] uppercase tracking-[0.18em] text-muted">
        <span>Offset</span><span>Hex</span><span>ASCII</span>
      </div>
      {chunk(bytes, 16).map((row, rowIndex) => (
        <div className="grid grid-cols-[52px_420px_1fr]" key={rowIndex}>
          <span className="text-muted">{(rowIndex * 16).toString(16).padStart(4, "0")}</span>
          <div>
            {row.map((byte, index) => {
              const absolute = rowIndex * 16 + index;
              return <Byte key={absolute} active={isActive(absolute, hoveredByte, selectedRange)} onHover={setHoveredByte} index={absolute}>{`${byte}${index === 7 ? "  " : " "}`}</Byte>;
            })}
          </div>
          <div>
            {row.map((byte, index) => {
              const absolute = rowIndex * 16 + index;
              return <Byte key={absolute} active={isActive(absolute, hoveredByte, selectedRange)} onHover={setHoveredByte} index={absolute}>{ascii(byte, raw_ascii[absolute])}</Byte>;
            })}
          </div>
        </div>
      ))}
      {bytes.length === 256 && <p className="mt-2 text-[10px] text-muted">Showing first 256 bytes</p>}
    </section>
  );
}

function Byte({ active, onHover, index, children }: { active: boolean; onHover: (index: number | null) => void; index: number; children: string }) {
  return <span className={active ? "highlight-byte" : ""} onMouseEnter={() => onHover(index)} onMouseLeave={() => onHover(null)}>{children}</span>;
}

function isActive(index: number, hovered: number | null, range: [number, number] | null) {
  return hovered === index || (range !== null && index >= range[0] && index <= range[1]);
}

function ascii(hex: string, fallback?: string) {
  const value = Number.parseInt(hex, 16);
  return value >= 32 && value < 127 ? String.fromCharCode(value) : fallback || ".";
}

function chunk<T>(items: T[], size: number) {
  return Array.from({ length: Math.ceil(items.length / size) }, (_, index) => items.slice(index * size, index * size + size));
}
