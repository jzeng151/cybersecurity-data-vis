import Link from "next/link";

import { loadManifest } from "@/lib/artifacts";

// Plain-words version of the seven techniques, in the same order as the technique badges.
const TECHNIQUES_PLAIN: [string, string][] = [
  ["Grouping (clustering)", "Putting similar things into piles to see the natural groups."],
  ["Cohorts", "Splitting things into groups by something they share (like the year they were made), then comparing the groups."],
  ["Over-time (time-series)", "Watching a number change over time, learning its normal rhythm, and spotting the weird spikes."],
  ["Prediction (regression)", "Teaching a simple formula to guess an answer from the other columns."],
  ["Squeezing columns (PCA)", "Squeezing lots of columns down to a few that still hold most of the pattern."],
  ["Dice-rolling (Monte Carlo)", "Rolling the dice many times to see the range of what could happen."],
  ["Reading words (text)", "Reading the actual words to find their mood or their theme."],
];

export const metadata = {
  title: "How this was made",
};

export default function AboutPage() {
  const manifest = loadManifest();

  return (
    <article className="prose-measure">
      <h1 className="text-3xl font-bold tracking-tight">How this was made</h1>

      <p className="mt-4 text-[var(--color-ink)]">{manifest.method.principle}</p>

      <h2 className="mt-8 text-xl font-semibold tracking-tight">One dataset, one takeaway</h2>
      <p className="mt-2 text-[var(--color-ink)]">
        Every dataset here is its own little project. We load the real data, try the few digging-into-data
        tricks that actually fit it, and let it reach <em>its own</em> answer and <em>its own</em> idea for
        something you could build. We never bend the data to fit a story we already wanted to tell — a
        dataset is allowed to say something boring, or to disagree with another dataset. If a trick would
        be a bad fit, we leave it out instead of faking it. And each finding comes with an honest tag:{" "}
        <span className="font-medium">strong fit</span> or <span className="font-medium">okay fit</span>,
        plus a note about what it can&apos;t tell us.
      </p>

      <h2 className="mt-8 text-xl font-semibold tracking-tight">The seven ways of digging into data</h2>
      <p className="mt-2 text-sm text-[var(--color-muted)]">
        From{" "}
        <a href={manifest.method.techniques_source} className="underline underline-offset-2 hover:text-[var(--color-accent)]">
          this list of seven
        </a>
        . Each dataset only uses the ones that truly fit it.
      </p>
      <ul className="mt-3 space-y-1.5 text-[var(--color-ink)]">
        {TECHNIQUES_PLAIN.map(([name, desc]) => (
          <li key={name}>
            <span className="font-medium">{name}</span> — {desc}
          </li>
        ))}
      </ul>

      <h2 className="mt-8 text-xl font-semibold tracking-tight">How the site is put together</h2>
      <p className="mt-2 text-[var(--color-ink)]">
        There are two halves that don&apos;t depend on each other. One half is a set of Python programs
        that do the number-crunching ahead of time and save the results — the tables, the chart recipes,
        and the takeaways — into a folder (<span className="font-mono text-sm">artifacts/{manifest.bundle_version}/</span>).
        The other half is this website, which just reads that folder and draws the pages. Before it shows
        anything, it double-checks that every saved result has the right shape, so a mistake would stop the
        site instead of showing something wrong.
      </p>

      <h2 className="mt-8 text-xl font-semibold tracking-tight">Being honest about it</h2>
      <p className="mt-2 text-[var(--color-ink)]">
        These are real, public datasets — practice sets, official lists, and live feeds. They aren&apos;t
        perfect: sometimes the &quot;right answers&quot; in the data are only a rough guide, some sets were
        made in a lab, and some change every day. A finding about one dataset is not a claim about the whole
        world. Every dataset&apos;s page says, in full, what it can&apos;t tell you.
      </p>

      <p className="mt-8 text-xs text-[var(--color-muted)]">
        Bundle {manifest.bundle_version} · schema {manifest.schema_version} · made{" "}
        {manifest.generated_at.slice(0, 10)} · git {manifest.git_rev} ·{" "}
        <Link href="/" className="underline underline-offset-2">back to datasets</Link>
      </p>
    </article>
  );
}
