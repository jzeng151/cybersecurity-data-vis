"""Acquire every dataset the pipeline needs; print what's present and what's missing.

    uv run python scripts/acquire_all.py
"""
from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cyberviz.acquire import (  # noqa: E402
    ait_ads, cisa_kev, ctu13, epss, nazario, unsw_nb15, urlhaus,
)

DATASETS = {
    "unsw-nb15": unsw_nb15.acquire,
    "ait-ads": ait_ads.acquire,
    "epss": epss.acquire,
    "cisa-kev": cisa_kev.acquire,
    "urlhaus": urlhaus.acquire,
    "nazario": nazario.acquire,
    "ctu-13": ctu13.acquire,
}


def main() -> None:
    for name, acquire in DATASETS.items():
        try:
            paths = acquire()
            total = sum(p.stat().st_size for p in paths.values())
            print(f"OK   {name}: {len(paths)} file(s), {total / 1e6:.1f} MB")
        except Exception as exc:  # noqa: BLE001 - report and continue to the next dataset
            print(f"FAIL {name}: {exc}")
            traceback.print_exc()


if __name__ == "__main__":
    main()
