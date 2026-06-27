import Link from "next/link";

import { loadManifest, type Dataset } from "@/lib/artifacts";
import { CATEGORY_LABEL, CATEGORY_ORDER, TECHNIQUE_LABEL } from "@/lib/tokens";

function TechniqueBadge({ technique }: { technique: string }) {
  return (
    <span className="rounded-full border border-[var(--color-line)] bg-[var(--color-paper)] px-2 py-0.5 text-xs text-[var(--color-muted)]">
      {TECHNIQUE_LABEL[technique] ?? technique}
    </span>
  );
}

function DatasetCard({ ds }: { ds: Dataset }) {
  return (
    <Link
      href={`/dataset/${ds.id}`}
      className="group flex flex-col rounded-xl border border-[var(--color-line)] bg-[var(--color-card)] p-5 shadow-sm transition hover:border-[var(--color-accent)] hover:shadow-md"
    >
      <h3 className="text-base font-semibold tracking-tight group-hover:text-[var(--color-accent)]">
        {ds.display_name}
      </h3>
      <p className="mt-1 text-sm text-[var(--color-muted)]">{ds.what_it_is}</p>
      <p className="mt-3 flex-1 text-sm leading-snug text-[var(--color-ink)]">
        <span className="font-medium text-[var(--color-muted)]">The big idea · </span>
        {ds.isolated_insight}
      </p>
      <div className="mt-4 flex flex-wrap gap-1.5">
        {ds.analyses.map((a) => (
          <TechniqueBadge key={a.technique} technique={a.technique} />
        ))}
      </div>
    </Link>
  );
}

export default function IndexPage() {
  const manifest = loadManifest();
  const byCategory = new Map<string, Dataset[]>();
  for (const ds of manifest.datasets) {
    byCategory.set(ds.doc_category, [...(byCategory.get(ds.doc_category) ?? []), ds]);
  }
  const categories = CATEGORY_ORDER.filter((c) => byCategory.has(c));

  return (
    <article>
      <h1 className="text-3xl font-bold tracking-tight">Cybersecurity datasets, one at a time</h1>
      <p className="prose-measure mt-4 text-[var(--color-ink)]">
        {manifest.datasets.length} real cybersecurity datasets. We look at each one{" "}
        <em>on its own</em> — its own charts, its own one big takeaway, and its own idea for
        something you could build. For each dataset we only use the{" "}
        <a
          href={manifest.method.techniques_source}
          className="font-medium underline decoration-[var(--color-line)] underline-offset-2 hover:text-[var(--color-accent)]"
        >
          seven ways of digging into data
        </a>{" "}
        that actually fit it. There&apos;s no grand theory tying them together: each dataset just
        tells us whatever it really shows.
      </p>

      {categories.map((category) => (
        <section key={category} className="mt-10">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            {CATEGORY_LABEL[category] ?? category}
          </h2>
          <div className="mt-3 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {byCategory.get(category)!.map((ds) => (
              <DatasetCard key={ds.id} ds={ds} />
            ))}
          </div>
        </section>
      ))}

      <p className="mt-12 text-xs text-[var(--color-muted)]">
        Bundle {manifest.bundle_version} · schema {manifest.schema_version} ·{" "}
        {manifest.datasets.length} datasets · generated {manifest.generated_at.slice(0, 10)} ·{" "}
        <Link href="/about" className="underline underline-offset-2">how this was built</Link>
      </p>
    </article>
  );
}
