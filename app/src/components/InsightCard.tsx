import type { ReactNode } from "react";

import { FIT_LABEL, TECHNIQUE_LABEL } from "@/lib/tokens";

const FIT_COLOR: Record<string, string> = {
  strong: "#2f8f5b",
  supporting: "#8a94a6",
  moderate: "#e0a341",
  forced: "#d2483f",
};

// The claim, stated before its chart. A reader scanning only these reaches the conclusion.
export default function InsightCard({
  children,
  fit,
  technique,
}: {
  children: ReactNode;
  fit: string;
  technique?: string;
}) {
  return (
    <div className="my-6 rounded-lg border-l-4 bg-[var(--color-card)] px-5 py-4 shadow-sm"
         style={{ borderColor: FIT_COLOR[fit] ?? "#8a94a6" }}>
      <div className="mb-1.5 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-[var(--color-muted)]">
        {technique && <span>{TECHNIQUE_LABEL[technique] ?? technique}</span>}
        <span className="inline-flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: FIT_COLOR[fit] ?? "#8a94a6" }} />
          {FIT_LABEL[fit] ?? fit}
        </span>
      </div>
      <p className="text-lg font-semibold leading-snug text-[var(--color-ink)]">{children}</p>
    </div>
  );
}
