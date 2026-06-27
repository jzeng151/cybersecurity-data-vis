"""CISA KEV — Known Exploited Vulnerabilities catalog. CVEs with confirmed in-the-wild
exploitation, with a ransomware-campaign-use flag. ~1,600 entries, CC0, no auth.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from .. import paths
from .registry import fetch

_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_DIR = paths.DATA_RAW / "cisa_kev"


def acquire() -> dict[str, Path]:
    return {"kev": fetch(_URL, _DIR / "kev.json", "cisa.kev")}


def load() -> pd.DataFrame:
    data = json.loads(acquire()["kev"].read_text())
    return pd.DataFrame(data["vulnerabilities"])


if __name__ == "__main__":
    df = load()
    print(df.shape, df.columns.tolist())
