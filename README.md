# Cybersecurity datasets — independent analyses

> Seven public cybersecurity datasets, each analyzed **in isolation**. Every dataset gets its own
> visualizations, reaches its own conclusion, and suggests its own solution idea — using whichever
> of the seven [hex.tech](https://hex.tech/blog/data-analysis-techniques/) data-analysis techniques
> genuinely fit its shape. There is **no overarching thesis**: a dataset is allowed to say whatever
> it actually says, even if it contradicts another dataset.

This is a deliberate design choice. Each dataset is a self-contained study — load the real data,
apply the techniques that fit, derive the insight, propose the solution. Techniques that would be a
forced fit are omitted rather than faked, and every analysis carries an honest `strong`/`moderate`
fit rating plus its own caveats.

It is two independent halves joined by **one seam** — a versioned artifact bundle on disk:

```
analysis/  (Python, uv)  ──writes──►  artifacts/v2/  ──read──►  app/ (Next.js, pnpm)
   pandas / scikit-learn /             manifest.json            reads + zod-validates,
   statsmodels, offline batch          tables/ series/ specs/   renders one page per dataset
```

Neither side imports the other's libraries. The app never runs scikit-learn; the analysis never
knows React. The manifest is **dataset-centric**: top-level `datasets[]`, each owning its analyses,
its `isolated_insight`, and its `solution_idea`.

## Run it

**Analysis (produces the artifact bundle):**
```bash
cd analysis
uv sync                                   # Python 3.12+; installs the `cyberviz` package
uv run python scripts/acquire_all.py      # downloads + checksum-verifies the 7 datasets
uv run python scripts/build_artifacts.py  # runs each dataset's analyses → artifacts/v2/manifest.json
uv run pytest                             # schema round-trip tests for the emitter
```

**App (reads the bundle):**
```bash
cd app
pnpm install
pnpm build      # zod-validates every record in the bundle; fails loudly on schema drift
pnpm dev        # http://localhost:3000
```

## The site

- **`/`** — a neutral gallery of the datasets, grouped by category. No thesis, just a catalog.
- **`/dataset/[id]`** — one self-contained page per dataset: its isolated insight, one section per
  analysis (finding + chart + metrics + caveats), the solution it suggests, and its honest limits.
- **`/about`** — the method and the architecture.

## The seven datasets

Each row is an independent analysis. The insight in the last column is derived from that dataset
*alone*; the full version (with numbers and a solution idea) lives on its page.

| Dataset | Category | Techniques (fit) | What it says, on its own |
|---|---|---|---|
| **UNSW-NB15** | network-flow | regression ●, PCA ●, cluster ◐ | Attack detection is easy *and* redundant — 0.94 AUC rests on no single feature; 10 principal components hold 94% of the variance (≈29 of 39 features near-redundant). |
| **CTU-13** (Botnet-52) | network-flow | cluster ●, time-series ● | The botnet is invisible per-flow (1066-byte ICMP echoes); it only shows up as a synchronized per-host fan-in *burst*. |
| **AIT-ADS** | host-log | cluster ●, time-series ●, cohort ◐ | Severity and volume are decoupled from attack progression: one automated recon burst is 66% of 2.66M alerts; post-exploitation is nearly invisible. |
| **EPSS** | threat-intel | cohort ●, regression ◐, Monte Carlo ◐ | Exploit-probability is extreme-concentrated (top 10% of CVEs ≈ 70% of expected exploits) and falls with CVE age. |
| **CISA KEV** | threat-intel | time-series ●, cohort ●, cluster ◐ | The official remediation deadline is a vintage-keyed admin *policy*, not a risk signal; exploitation concentrates in 5 vendors / 2 CWE families. |
| **URLhaus** | threat-intel | cluster ●, cohort ●, time-series ◐, regression ◐ | The feed is two distinct hosting ecosystems; campaign family predicts takedown survival far better than the feed-wide baseline. |
| **Nazario phishing** | phishing-email | text/sentiment ●, cluster ◐, time-series ◐ | Phishing is a small repeating toolkit of content + structure (urgency lexicon, brand mismatch, HTML); arrival timing carries no signal. |

(● strong · ◐ moderate. Forced techniques are omitted per dataset, on purpose.)

## Data sources (all directly downloadable, no Kaggle)

| Dataset | Source | License / access note |
|---|---|---|
| UNSW-NB15 | ACCS train/test CSV (GitHub mirror) | research use; cite Moustafa & Slay 2015 |
| CTU-13 | Stratosphere IPS, capture Botnet-52 | free for research; static 2011 capture, reproducible |
| AIT-ADS | Zenodo 8263181 | CC-BY-4.0; ndjson streamed from the zip (never extracted) |
| EPSS | epss.cyentia.com daily CSV | free, no auth; single-day snapshot pinned by checksum |
| CISA KEV | cisa.gov JSON feed | CC0 |
| URLhaus | urlhaus.abuse.ch recent CSV | CC0; rolling 30-day feed — the snapshot used is checksum-pinned |
| Nazario phishing | monkey.org/~jose/phishing (2020) | public research archive; non-anonymized → analysis aggregates only, never re-exposes PII |

`analysis/data/checksums.json` is committed (raw data is gitignored); acquisition is reproducible
and verified. Re-downloading a rolling feed (URLhaus, EPSS) will mismatch by design — the checksum
pins the exact version a build used.

## Honest scope

- These are **public** datasets — synthetic testbeds, curated catalogs, rolling feeds. Labels are
  often proxies (attack-time windows, not analyst verdicts), some sets are engineered (UNSW-NB15's
  class balance, NSL-style separability) or non-reproducible (rolling feeds), and a finding on one
  dataset is **not** a claim about the world. Each page states its own limits in full.
- Several analyses **corrected** their design brief against the real data — e.g. AIT-ADS attack
  "windows" are minutes, not days; UNSW-NB15's `sttl` is not the load-bearing feature it's reputed
  to be. The committed numbers are what the data actually shows.
- Adding a dataset is additive: a new `acquire/*` module + a new `datasets/*.py` emitting to the
  same manifest, plus a row in the bundle. The app renders it with no new page code. (NSL-KDD is
  designed and ready to slot in as an eighth if desired.)
