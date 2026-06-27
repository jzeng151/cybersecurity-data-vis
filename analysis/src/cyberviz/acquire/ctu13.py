"""CTU-13 botnet netflow (Stratosphere IPS / CTU University). Real botnet traffic mixed with
real normal + background traffic. We pin one scenario: capture Botnet-52 (CTU-13 scenario 11),
a single ~15-minute bidirectional-netflow capture with a per-flow Label (Botnet / Normal /
Background). Public, anonymous HTTP, no auth — and a static 2011 file, so fully reproducible.

(The numbered /CTU-13-Dataset/<n>/ subdirectories 404; the live data lives under the per-capture
CTU-Malware-Capture-Botnet-* directories.)
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from .. import paths
from .registry import fetch

_URL = (
    "https://mcfp.felk.cvut.cz/publicDatasets/"
    "CTU-Malware-Capture-Botnet-52/capture20110818-2.binetflow.2format"
)
_DIR = paths.DATA_RAW / "ctu13"


def acquire() -> dict[str, Path]:
    return {"binetflow": fetch(_URL, _DIR / "botnet-52.binetflow", "ctu13.botnet52")}


def load() -> pd.DataFrame:
    """Argus bidirectional netflow: comma-separated with a header row; Label is the ground truth."""
    df = pd.read_csv(acquire()["binetflow"], low_memory=False)
    if "StartTime" in df.columns:
        df["StartTime"] = pd.to_datetime(df["StartTime"], errors="coerce")
    return df


if __name__ == "__main__":
    df = load()
    print(df.shape, df.columns.tolist())
    if "Label" in df.columns:
        klass = df["Label"].str.extract(r"(Botnet|Normal|Background)", expand=False)
        print(klass.value_counts(dropna=False).to_dict())
