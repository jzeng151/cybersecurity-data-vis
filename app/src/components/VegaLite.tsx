"use client";

import { useEffect, useRef } from "react";

// Renders a Vega-Lite spec (data inlined by the analysis side). vega-embed is dynamically
// imported inside the effect so it never evaluates during SSR.
export default function VegaLite({ spec }: { spec: Record<string, unknown> }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    let view: { finalize?: () => void } | undefined;
    import("vega-embed")
      .then(({ default: embed }) => {
        if (cancelled || !ref.current) return undefined;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return embed(ref.current, spec as any, { actions: false, renderer: "svg" });
      })
      .then((result) => {
        if (result) view = result.view;
      })
      .catch((err) => console.error("vega-embed failed", err));
    return () => {
      cancelled = true;
      view?.finalize?.();
    };
  }, [spec]);

  return <div ref={ref} className="w-full" />;
}
