"""abuse.ch URLhaus — recent malicious-URL feed. One row per reported malicious URL with its
status (online/offline), threat type, campaign tags, and reporter. Open feed, no auth.

The "recent" CSV is a rolling ~30-day window that abuse.ch regenerates continuously, so it is
NOT reproducible: re-downloading yields a different window. checksums.json pins the exact snapshot
a build used (same convention as the daily EPSS feed) — re-fetching after deletion will mismatch
by design.
"""
from __future__ import annotations

import io
from pathlib import Path

import pandas as pd

from .. import paths
from .registry import fetch

_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
_DIR = paths.DATA_RAW / "urlhaus"

# The feed ships a fixed 9-column schema under a commented (#) header block.
_COLUMNS = [
    "id", "dateadded", "url", "url_status", "last_online",
    "threat", "tags", "urlhaus_link", "reporter",
]


def acquire() -> dict[str, Path]:
    return {"recent": fetch(_URL, _DIR / "urlhaus_recent.csv", "urlhaus.recent")}


def load() -> pd.DataFrame:
    text = acquire()["recent"].read_text(encoding="utf-8", errors="replace")
    # Drop the leading "# ..." comment block; the data rows are quoted CSV with no header row.
    rows = "\n".join(ln for ln in text.splitlines() if ln and not ln.startswith("#"))
    df = pd.read_csv(io.StringIO(rows), names=_COLUMNS, quotechar='"', skipinitialspace=True)
    df["dateadded"] = pd.to_datetime(df["dateadded"], errors="coerce", utc=True)
    df["last_online"] = pd.to_datetime(df["last_online"], errors="coerce", utc=True)
    return df


if __name__ == "__main__":
    df = load()
    print(df.shape, df.columns.tolist())
    print(df["url_status"].value_counts().to_dict())
