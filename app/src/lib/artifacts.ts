// The TS side of the seam: read + zod-validate the dataset-centric artifact bundle. Server-only.
// A schema drift anywhere in the bundle makes Manifest.parse throw → the build fails loudly.
import "server-only";

import fs from "node:fs";
import path from "node:path";
import { z } from "zod";

import { BUNDLE_VERSION } from "./tokens";

const ARTIFACTS_DIR = path.resolve(process.cwd(), "..", "artifacts", BUNDLE_VERSION);

export const MetricSchema = z.object({
  label: z.string(),
  // Python emits display strings, but coerce defensively so a stray number never fails the build.
  value: z.coerce.string(),
});

export const AnalysisSchema = z.object({
  technique: z.enum([
    "cluster", "cohort", "timeseries", "regression", "pca_factor", "monte_carlo", "text_sentiment",
  ]),
  title: z.string().min(1),
  finding: z.string().min(1),
  fit: z.enum(["strong", "moderate", "forced"]),
  storage: z.array(z.string()),
  spec: z.string().nullable().optional(),
  metrics: z.array(MetricSchema).default([]),
  params: z.record(z.string(), z.unknown()).default({}),
  row_counts: z.record(z.string(), z.unknown()).default({}),
  data_quality_note: z.string().nullable().optional(),
  fit_warning: z.string().nullable().optional(),
});

export const DatasetSchema = z.object({
  id: z.string(),
  display_name: z.string(),
  doc_category: z.enum(["network-flow", "host-log", "threat-intel", "phishing-email"]),
  what_it_is: z.string(),
  source: z.object({ name: z.string(), url: z.string(), license: z.string() }),
  isolated_insight: z.string().min(1),
  solution_idea: z.string().min(1),
  honesty_notes: z.string(),
  analyses: z.array(AnalysisSchema),
});

export const ManifestSchema = z.object({
  schema_version: z.string(),
  bundle_version: z.string(),
  generated_at: z.string(),
  git_rev: z.string(),
  method: z.object({ principle: z.string(), techniques_source: z.string() }),
  datasets: z.array(DatasetSchema),
});

export type Metric = z.infer<typeof MetricSchema>;
export type Analysis = z.infer<typeof AnalysisSchema>;
export type Dataset = z.infer<typeof DatasetSchema>;
export type Manifest = z.infer<typeof ManifestSchema>;

export function loadManifest(): Manifest {
  const raw = fs.readFileSync(path.join(ARTIFACTS_DIR, "manifest.json"), "utf8");
  return ManifestSchema.parse(JSON.parse(raw));
}

export function loadJson<T = unknown>(relPath: string): T {
  const raw = fs.readFileSync(path.join(ARTIFACTS_DIR, relPath), "utf8");
  return JSON.parse(raw) as T;
}

export function getDataset(id: string): Dataset {
  const ds = loadManifest().datasets.find((d) => d.id === id);
  if (!ds) throw new Error(`dataset not in manifest: ${id}`);
  return ds;
}
