"""The pipeline: build every dataset's isolated analyses, flush the manifest once.

    uv run python scripts/build_artifacts.py

Each dataset module owns its own analysis and emits only its own artifact files (all prefixed
with the dataset id). The manifest is dataset-centric — no narrative ordering, no shared thesis.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow running as a plain script without an editable install.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cyberviz import artifacts  # noqa: E402
from cyberviz.datasets import (  # noqa: E402
    ait_ads, cisa_kev, ctu13, epss, nazario, unsw_nb15, urlhaus,
)

# Order = how datasets appear in prev/next nav; grouped to match the index's category order.
BUILDERS = [
    unsw_nb15.build,   # network-flow
    ctu13.build,       # network-flow
    ait_ads.build,     # host-log
    epss.build,        # threat-intel
    cisa_kev.build,    # threat-intel
    urlhaus.build,     # threat-intel
    nazario.build,     # phishing-email
]


def main() -> None:
    m = artifacts.Manifest()
    for build in BUILDERS:
        build(m)

    out = m.flush()
    print(f"wrote {out}")
    print(f"  {len(m._datasets)} datasets")
    for d in m._datasets:
        techs = ", ".join(f"{a.technique}/{a.fit}" for a in d.analyses)
        print(f"  - {d.id:14s} [{d.doc_category}] {len(d.analyses)} analyses: {techs}")


if __name__ == "__main__":
    main()
