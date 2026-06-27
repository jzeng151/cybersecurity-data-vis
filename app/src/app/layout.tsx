import type { Metadata } from "next";
import Link from "next/link";

import SeverityLegend from "@/components/SeverityLegend";
import "./globals.css";

export const metadata: Metadata = {
  title: "Cybersecurity datasets — studied one at a time",
  description:
    "A gallery of real cybersecurity datasets. We look at each one on its own, in plain language, " +
    "to find one clear takeaway and one idea for something you could build from it.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="border-b border-[var(--color-line)] bg-[var(--color-card)]">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-6 py-3">
            <Link href="/" className="text-sm font-semibold tracking-tight">
              Cybersecurity Datasets Visualizastion<span className="text-[var(--color-muted)]"></span>
            </Link>
            <nav className="flex gap-4 text-sm text-[var(--color-muted)]">
              <Link href="/" className="hover:text-[var(--color-ink)]">Datasets</Link>
              <Link href="/about" className="hover:text-[var(--color-ink)]">Method</Link>
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-6 py-10">{children}</main>
        <footer className="mt-16 border-t border-[var(--color-line)] bg-[var(--color-card)]">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-6 py-5">
            <SeverityLegend />
            <span className="text-xs text-[var(--color-muted)]">
              Each dataset is analyzed in isolation · artifacts versioned and read straight from the bundle.
            </span>
          </div>
        </footer>
      </body>
    </html>
  );
}
