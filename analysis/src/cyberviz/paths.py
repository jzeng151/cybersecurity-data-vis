"""Filesystem layout for the analysis side. The ONLY module that knows where things live."""
from __future__ import annotations

from pathlib import Path

# This file: <repo>/analysis/src/cyberviz/paths.py
PKG_DIR = Path(__file__).resolve().parent
ANALYSIS_DIR = PKG_DIR.parents[1]          # <repo>/analysis
REPO_DIR = ANALYSIS_DIR.parent             # <repo>

DATA_RAW = ANALYSIS_DIR / "data" / "raw"
DATA_INTERIM = ANALYSIS_DIR / "data" / "interim"

# The seam. Bump BUNDLE_VERSION (and the const in app/src/lib/tokens.ts) to evolve the schema.
# v2 is the dataset-centric bundle: every artifact belongs to exactly one dataset, analyzed in
# isolation. (v1 was the older technique/act-centric bundle; it is left on disk untouched.)
BUNDLE_VERSION = "v2"
ARTIFACTS_DIR = REPO_DIR / "artifacts" / BUNDLE_VERSION
TABLES_DIR = ARTIFACTS_DIR / "tables"
SERIES_DIR = ARTIFACTS_DIR / "series"
SPECS_DIR = ARTIFACTS_DIR / "specs"


def ensure_dirs() -> None:
    for d in (DATA_RAW, DATA_INTERIM, TABLES_DIR, SERIES_DIR, SPECS_DIR):
        d.mkdir(parents=True, exist_ok=True)
