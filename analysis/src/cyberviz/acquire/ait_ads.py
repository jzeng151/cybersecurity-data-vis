"""AIT Alert Data Set (AIT-ADS, 2023) — 2.65M real IDS alerts (Wazuh + AMiner) over 8
testbed scenarios, with attack time-windows as ground truth. CC-BY-4.0.

The closest public proxy to a labeled SOC alert stream. Source: Zenodo record 8263181.
The alerts ship as one ndjson file per (scenario, ids); the Wazuh files are hundreds of MB
each, so consumers must STREAM from the zip rather than extract it.
"""
from __future__ import annotations

from pathlib import Path

from .. import paths
from .registry import fetch

_REC = "https://zenodo.org/api/records/8263181/files"
_DIR = paths.DATA_RAW / "ait_ads"

SCENARIOS = ["fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler", "wilson"]
IDS = ["wazuh", "aminer"]


def acquire() -> dict[str, Path]:
    return {
        "zip": fetch(f"{_REC}/ait_ads.zip/content", _DIR / "ait_ads.zip", "ait_ads.zip"),
        "labels": fetch(f"{_REC}/labels.csv/content", _DIR / "labels.csv", "ait_ads.labels"),
    }


if __name__ == "__main__":
    for name, path in acquire().items():
        print(f"{name}: {path} ({path.stat().st_size:,} bytes)")
