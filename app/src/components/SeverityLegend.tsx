import { SEVERITY } from "@/lib/tokens";

// The shared color key, shown once in the chrome so every chart reads in one language.
export default function SeverityLegend() {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[var(--color-muted)]">
      {Object.entries(SEVERITY).map(([name, hex]) => (
        <span key={name} className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: hex }} />
          {name}
        </span>
      ))}
    </div>
  );
}
