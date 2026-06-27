import Link from "next/link";
import { notFound } from "next/navigation";

import InsightCard from "@/components/InsightCard";
import VegaLite from "@/components/VegaLite";
import { loadJson, loadManifest, type Analysis, type Dataset } from "@/lib/artifacts";
import { CATEGORY_LABEL } from "@/lib/tokens";

export function generateStaticParams() {
  return loadManifest().datasets.map((d) => ({ id: d.id }));
}

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const ds = loadManifest().datasets.find((d) => d.id === id);
  return ds
    ? { title: `${ds.display_name} — independent analysis`, description: ds.isolated_insight }
    : { title: "Dataset not found" };
}

function MetricTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-[var(--color-line)] bg-[var(--color-paper)] px-3 py-2">
      <div className="text-lg font-bold tabular-nums">{value}</div>
      <div className="text-xs text-[var(--color-muted)]">{label}</div>
    </div>
  );
}

function Caveat({ text }: { text: string }) {
  return (
    <p className="mt-3 rounded-md border-l-2 border-[var(--color-suspicious)] bg-[var(--color-card)] px-4 py-2 text-sm text-[var(--color-muted)]">
      {text}
    </p>
  );
}

function AnalysisSection({ analysis, index }: { analysis: Analysis; index: number }) {
  const spec = analysis.spec ? loadJson<Record<string, unknown>>(analysis.spec) : null;
  return (
    <section className="mt-12">
      <h2 className="text-xl font-semibold tracking-tight">
        <span className="text-[var(--color-muted)]">{index + 1} · </span>
        {analysis.title}
      </h2>
      <InsightCard fit={analysis.fit} technique={analysis.technique}>
        {analysis.finding}
      </InsightCard>
      {spec && (
        <figure className="my-5 rounded-xl border border-[var(--color-line)] bg-[var(--color-card)] p-4">
          <VegaLite spec={spec} />
        </figure>
      )}
      {analysis.metrics.length > 0 && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {analysis.metrics.map((m, mi) => (
            <MetricTile key={`${analysis.technique}-${mi}`} label={m.label} value={m.value} />
          ))}
        </div>
      )}
      {analysis.data_quality_note && <Caveat text={analysis.data_quality_note} />}
      {analysis.fit_warning && <Caveat text={analysis.fit_warning} />}
    </section>
  );
}

function nav(datasets: Dataset[], id: string) {
  const i = datasets.findIndex((d) => d.id === id);
  return { prev: datasets[i - 1], next: datasets[i + 1] };
}

export default async function DatasetPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const datasets = loadManifest().datasets;
  const ds = datasets.find((d) => d.id === id);
  if (!ds) notFound();
  const { prev, next } = nav(datasets, ds.id);

  return (
    <article>
      <p className="text-sm font-medium uppercase tracking-wide text-[var(--color-muted)]">
        {CATEGORY_LABEL[ds.doc_category] ?? ds.doc_category}
      </p>
      <h1 className="mt-2 text-3xl font-bold tracking-tight">{ds.display_name}</h1>
      <p className="prose-measure mt-2 text-[var(--color-muted)]">{ds.what_it_is}</p>
      <p className="mt-1 text-xs text-[var(--color-muted)]">
        Source:{" "}
        <a href={ds.source.url} className="underline underline-offset-2 hover:text-[var(--color-accent)]">
          {ds.source.name}
        </a>{" "}
        · {ds.source.license}
      </p>

      <div className="prose-measure mt-6 rounded-xl border border-[var(--color-accent)] bg-[var(--color-card)] p-5">
        <p className="text-xs font-semibold uppercase tracking-wide text-[var(--color-accent)]">
          The big idea — what this dataset tells us, all by itself
        </p>
        <p className="mt-2 text-lg font-medium leading-snug text-[var(--color-ink)]">
          {ds.isolated_insight}
        </p>
      </div>

      {ds.analyses.map((a, i) => (
        <AnalysisSection key={a.technique} analysis={a} index={i} />
      ))}

      <section className="mt-12 rounded-xl border border-[var(--color-line)] bg-[var(--color-card)] p-6">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
          An idea you could build from this
        </h2>
        <p className="prose-measure mt-2 text-[var(--color-ink)]">{ds.solution_idea}</p>
      </section>

      <section className="mt-6">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
          What this can&apos;t tell us
        </h2>
        <p className="prose-measure mt-2 text-sm text-[var(--color-muted)]">{ds.honesty_notes}</p>
      </section>

      <nav className="mt-12 flex justify-between border-t border-[var(--color-line)] pt-4 text-sm">
        {prev ? (
          <Link href={`/dataset/${prev.id}`} className="text-[var(--color-muted)] hover:text-[var(--color-accent)]">
            ← {prev.display_name}
          </Link>
        ) : (
          <span />
        )}
        {next ? (
          <Link href={`/dataset/${next.id}`} className="text-[var(--color-muted)] hover:text-[var(--color-accent)]">
            {next.display_name} →
          </Link>
        ) : (
          <span />
        )}
      </nav>
    </article>
  );
}
