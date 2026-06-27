"""EPSS — Exploit Prediction Scoring System (FIRST.org). Daily 0-1 exploit probability +
percentile per CVE. ~340k CVEs, tiny gzipped CSV, no auth. The first line is a comment
(#model_version,score_date); the header is the second line.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from .. import paths
from .registry import fetch

_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_DIR = paths.DATA_RAW / "epss"


def acquire() -> dict[str, Path]:
    return {"scores": fetch(_URL, _DIR / "epss_scores-current.csv.gz", "epss.current")}


def load() -> pd.DataFrame:
    """cve, epss, percentile — skipping the leading comment line."""
    return pd.read_csv(acquire()["scores"], skiprows=1)


if __name__ == "__main__":
    df = load()
    print(df.shape, df.columns.tolist())
    print(df.head())
