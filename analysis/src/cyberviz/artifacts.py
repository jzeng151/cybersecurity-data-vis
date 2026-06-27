"""The emitter — defines and enforces the artifact-schema seam.

The bundle is DATASET-CENTRIC: every artifact belongs to exactly one dataset, and each dataset
is analyzed in isolation. There is no cross-dataset thesis and no narrative ordering — a dataset
stands on its own with its own isolated insight, its own solution idea, and one Analysis per
data-analysis technique that genuinely fits it.

A dataset module writes its data with write_table/write_json/write_spec (which return manifest-
relative paths), assembles a Dataset(analyses=[Analysis(...), ...]), and registers it via
Manifest.add(). The build script flushes the Manifest once at the end. add() validates eagerly:
every referenced file must already exist on disk, so a typo'd path fails the build immediately
rather than shipping a manifest that points at nothing.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from . import paths

SCHEMA_VERSION = "2"

# The seven hex.tech data-analysis techniques (https://hex.tech/blog/data-analysis-techniques/).
# pca_factor == factor analysis / PCA; text_sentiment == sentiment / text analysis.
VALID_TECHNIQUES = {
    "cluster", "cohort", "timeseries", "regression", "pca_factor", "monte_carlo", "text_sentiment",
}
# Honest fit of a technique to a dataset. "forced" fits are omitted, not emitted — so a registered
# Analysis is always strong or moderate. The enum keeps "forced" only to document the vocabulary.
VALID_FIT = {"strong", "moderate", "forced"}
# The four dataset families from the source-doc inventory.
VALID_CATEGORY = {"network-flow", "host-log", "threat-intel", "phishing-email"}


def _json_default(o: Any):
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    if isinstance(o, (pd.Timestamp, datetime)):
        return o.isoformat()
    raise TypeError(f"not JSON serializable: {type(o)}")


def _rel(p: Path) -> str:
    return p.relative_to(paths.ARTIFACTS_DIR).as_posix()


def write_table(artifact_id: str, df: pd.DataFrame) -> str:
    """Write a rectangular table as Parquet (Arrow-readable by the TS side)."""
    paths.ensure_dirs()
    out = paths.TABLES_DIR / f"{artifact_id}.parquet"
    df.to_parquet(out, index=False)
    return _rel(out)


def write_json(artifact_id: str, obj: Any) -> str:
    """Write a small structure the dashboard iterates directly (series, summaries)."""
    paths.ensure_dirs()
    out = paths.SERIES_DIR / f"{artifact_id}.json"
    out.write_text(json.dumps(obj, indent=2, default=_json_default, allow_nan=False))
    return _rel(out)


def write_spec(artifact_id: str, spec: dict, *, kind: str = "vl") -> str:
    """Write a chart spec. kind='vl' -> Vega-Lite (*.vl.json); kind='plot' -> pre-shaped."""
    paths.ensure_dirs()
    out = paths.SPECS_DIR / f"{artifact_id}.{kind}.json"
    out.write_text(json.dumps(spec, indent=2, default=_json_default, allow_nan=False))
    return _rel(out)


@dataclass
class Metric:
    """One headline number the dataset page renders as a stat tile."""
    label: str
    value: str


@dataclass
class Analysis:
    """One technique applied to one dataset, with the concrete finding it produced."""
    technique: str                # one of VALID_TECHNIQUES
    title: str
    finding: str                  # what THIS technique shows on THIS dataset (one paragraph)
    fit: str                      # "strong" | "moderate" (honesty flag)
    storage: list[str] = field(default_factory=list)   # series/ + tables/ paths
    spec: str | None = None       # the chart spec path
    metrics: list[Metric] = field(default_factory=list)
    params: dict = field(default_factory=dict)
    row_counts: dict = field(default_factory=dict)
    data_quality_note: str | None = None
    fit_warning: str | None = None

    def validate(self, ds_id: str) -> None:
        where = f"{ds_id}/{self.technique}"
        assert self.technique in VALID_TECHNIQUES, f"{where}: bad technique {self.technique!r}"
        assert self.fit in VALID_FIT, f"{where}: bad fit {self.fit!r}"
        assert self.title.strip(), f"{where}: missing title"
        assert self.finding.strip(), f"{where}: missing finding"
        refs = list(self.storage) + ([self.spec] if self.spec else [])
        assert refs, f"{where}: registers no files"
        for rel in refs:
            assert (paths.ARTIFACTS_DIR / rel).exists(), f"{where}: referenced file missing: {rel}"


@dataclass
class Dataset:
    """One dataset analyzed in isolation: its own insight, its own solution idea, its analyses."""
    id: str
    display_name: str
    doc_category: str             # one of VALID_CATEGORY
    what_it_is: str               # plain one-liner: the raw data and its row grain
    source: dict                  # {name, url, license}
    isolated_insight: str         # THE conclusion from this dataset ALONE
    solution_idea: str            # a product idea derived ONLY from this dataset's conclusion
    honesty_notes: str            # dataset-specific caveats / label-proxy limits
    analyses: list[Analysis] = field(default_factory=list)

    def validate(self) -> None:
        assert self.id, "dataset: missing id"
        assert self.doc_category in VALID_CATEGORY, f"{self.id}: bad category {self.doc_category!r}"
        assert self.isolated_insight.strip(), f"{self.id}: missing isolated_insight"
        assert self.solution_idea.strip(), f"{self.id}: missing solution_idea"
        for fld in ("display_name", "what_it_is", "honesty_notes"):
            assert (getattr(self, fld) or "").strip(), f"{self.id}: missing {fld}"
        assert all((self.source.get(k) or "").strip() for k in ("name", "url", "license")), \
            f"{self.id}: source must have non-empty name + url + license"
        assert self.analyses, f"{self.id}: registers no analyses"
        techniques = [a.technique for a in self.analyses]
        assert len(techniques) == len(set(techniques)), f"{self.id}: duplicate technique on one dataset"
        for a in self.analyses:
            a.validate(self.id)


def _git_rev() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=paths.REPO_DIR, text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "uninitialized"


class Manifest:
    """Accumulates validated datasets and flushes manifest.json (written last)."""

    METHOD = {
        "principle": "We study each dataset on its own. We never force them into one big shared story "
        "— each dataset gets its own takeaway and its own idea for something you could build.",
        "techniques_source": "https://hex.tech/blog/data-analysis-techniques/",
    }

    def __init__(self) -> None:
        self._datasets: list[Dataset] = []

    def add(self, ds: Dataset) -> Dataset:
        ds.validate()
        self._datasets.append(ds)
        return ds

    def flush(self) -> Path:
        paths.ensure_dirs()
        ids = [d.id for d in self._datasets]
        assert len(ids) == len(set(ids)), f"duplicate dataset ids: {ids}"
        doc = {
            "schema_version": SCHEMA_VERSION,
            "bundle_version": paths.BUNDLE_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "git_rev": _git_rev(),
            "method": self.METHOD,
            "datasets": [asdict(d) for d in self._datasets],
        }
        out = paths.ARTIFACTS_DIR / "manifest.json"
        # Same cross-language safety as write_json/write_spec: coerce numpy/datetime via
        # _json_default, and forbid NaN/Infinity (which JS JSON.parse rejects on the TS side).
        out.write_text(json.dumps(doc, indent=2, default=_json_default, allow_nan=False))
        return out
