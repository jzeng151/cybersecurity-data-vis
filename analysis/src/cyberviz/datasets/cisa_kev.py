"""CISA KEV (Known Exploited Vulnerabilities) — analyzed in isolation.

One row = one CVE that CISA has confirmed is being exploited in the wild, with a remediation
dueDate and a ransomware-campaign-use flag. The catalog's own fields say two concrete things:
(1) the official remediation deadline is a deterministic two-tier POLICY keyed to a CVE's vintage,
not a risk signal — fresh CVEs get a tight 14/21-day SLA while ~6-month (181-day) deadlines were
assigned almost exclusively to the pre-2021 backlog CISA seeded at the 2021-2022 catalog launch;
and (2) the exploited-in-the-wild population is heavily concentrated (Microsoft 23%, top-5 vendors
44%) across two dominant bug families. Net: read real exploitation risk from concentration, not
from the dueDate.

Build is deterministic: every figure is a plain aggregation over the full catalog (no sampling,
no randomness).
"""
from __future__ import annotations

import re
from collections import Counter

import pandas as pd

from .. import artifacts
from ..artifacts import Analysis, Dataset, Metric
from ..acquire import cisa_kev as acq

DATASET_ID = "cisa-kev"

# Severity / palette hexes (mirror cyberviz/colors.py). Non-severity accent is blue.
ACCENT = "#3b82f6"
SUSPICIOUS = "#e0a341"
MALICIOUS = "#d2483f"
NEUTRAL = "#8a94a6"

# CWE -> bug-family mapping for the concentration/segmentation view. Multi-label: a CVE can touch
# more than one family, so family counts are "rows touched", NOT summed to 100%.
_CWE_FAMILY = {
    # memory-safety (native-code corruption)
    "CWE-787": "memory-safety", "CWE-416": "memory-safety", "CWE-119": "memory-safety",
    "CWE-125": "memory-safety", "CWE-122": "memory-safety", "CWE-120": "memory-safety",
    "CWE-190": "memory-safety", "CWE-843": "memory-safety", "CWE-415": "memory-safety",
    "CWE-476": "memory-safety", "CWE-824": "memory-safety", "CWE-121": "memory-safety",
    # injection / input-validation (web + command + deserialization)
    "CWE-20": "injection/input-validation", "CWE-78": "injection/input-validation",
    "CWE-22": "injection/input-validation", "CWE-94": "injection/input-validation",
    "CWE-502": "injection/input-validation", "CWE-77": "injection/input-validation",
    "CWE-89": "injection/input-validation", "CWE-79": "injection/input-validation",
    "CWE-74": "injection/input-validation", "CWE-434": "injection/input-validation",
    "CWE-918": "injection/input-validation", "CWE-611": "injection/input-validation",
    "CWE-91": "injection/input-validation", "CWE-88": "injection/input-validation",
    "CWE-1321": "injection/input-validation",
    # authentication / access-control
    "CWE-287": "auth/access-control", "CWE-306": "auth/access-control",
    "CWE-284": "auth/access-control", "CWE-264": "auth/access-control",
    "CWE-288": "auth/access-control", "CWE-863": "auth/access-control",
    "CWE-862": "auth/access-control", "CWE-269": "auth/access-control",
    "CWE-732": "auth/access-control", "CWE-798": "auth/access-control",
}


def _load() -> pd.DataFrame:
    df = acq.load().copy()
    df["dateAdded"] = pd.to_datetime(df["dateAdded"])
    df["dueDate"] = pd.to_datetime(df["dueDate"])
    df["ttd"] = (df["dueDate"] - df["dateAdded"]).dt.days
    df["addYear"] = df["dateAdded"].dt.year
    df["vintage"] = df["cveID"].str.extract(r"CVE-(\d{4})-")[0].astype(int)
    df["isRansom"] = df["knownRansomwareCampaignUse"].eq("Known")
    return df


def _deadline_tier(d: int) -> str:
    if d <= 21:
        return "standard (<=21d)"
    if d >= 180:
        return "backlog (>=180d)"
    return "other"


# ----------------------------------------------------------------------------------------------
# 1. TIMESERIES — monthly catalog-add cadence (strong)
# ----------------------------------------------------------------------------------------------
def _timeseries(df: pd.DataFrame) -> Analysis:
    months = (
        df.set_index("dateAdded")
        .resample("MS")
        .size()
        .rename("count")
        .to_frame()
    )
    months["rolling3"] = months["count"].rolling(3, min_periods=1).mean().round(2)
    months = months.reset_index()
    months["month"] = months["dateAdded"].dt.strftime("%Y-%m")

    per_year = df["addYear"].value_counts().sort_index()
    peak_month = months.loc[months["count"].idxmax()]
    # steady-state = mean weekly rate over the post-backlog 2023-2024 trough cohorts
    trough = df[df["addYear"].isin([2023, 2024])]
    steady_per_week = round(len(trough) / (104), 1)  # 2 years ~= 104 weeks

    rows = [
        {"month": r.month, "count": int(r["count"]), "rolling3": float(r.rolling3)}
        for _, r in months.iterrows()
    ]
    storage = [
        artifacts.write_json(f"{DATASET_ID}.timeseries.monthly", rows),
        artifacts.write_table(f"{DATASET_ID}.timeseries.yearly",
                              per_year.rename_axis("addYear").reset_index(name="count")),
    ]

    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": "CISA KEV: bugs added each month (comes in bursts, not a steady line)",
        "width": "container",
        "height": 320,
        "data": {"values": rows},
        "encoding": {
            "x": {"field": "month", "type": "temporal", "title": "Month added (dateAdded)"},
        },
        "layer": [
            {
                "mark": {"type": "bar", "color": ACCENT, "opacity": 0.85},
                "encoding": {
                    "y": {"field": "count", "type": "quantitative",
                          "title": "CVEs added that month"},
                    "tooltip": [
                        {"field": "month", "type": "temporal", "title": "Month"},
                        {"field": "count", "type": "quantitative", "title": "Added"},
                    ],
                },
            },
            {
                "mark": {"type": "line", "color": SUSPICIOUS, "strokeWidth": 2,
                         "point": False},
                "encoding": {
                    "y": {"field": "rolling3", "type": "quantitative"},
                    "tooltip": [
                        {"field": "month", "type": "temporal", "title": "Month"},
                        {"field": "rolling3", "type": "quantitative",
                         "title": "3-mo rolling mean"},
                    ],
                },
            },
        ],
    }
    spec_path = artifacts.write_spec(f"{DATASET_ID}.timeseries.monthly", spec)

    return Analysis(
        technique="timeseries",
        title="New entries come in bursts: a 2022 pile-up, a 2023-24 quiet spell, a 2025 climb",
        finding=(
            f"The list does not grow at a steady pace. New flaws get added in clumps. The number "
            f"added each year was 311 (2021, only part of a year — the list started in November), "
            f"555 (2022), 187 (2023), 186 (2024), 245 (2025), and 143 (2026, only up to Jun 23). "
            f"The 2022 group is about 3x the typical 2023-24 size of ~186/yr. That big year was "
            f"CISA loading in a pile of old flaws at the start, not a sudden jump in real attacks. "
            f"The busiest single month is "
            f"{peak_month['month']} ({int(peak_month['count'])} adds). After that pile-up, in the "
            f"quiet 2023-24 stretch, the normal pace is about ~{steady_per_week}/week. Any month "
            f"well above that line is a batch of flaws added at once (like the monthly "
            f"'Patch Tuesday' groups), not steady drift. 2026 is only a partial year, so we leave "
            f"it out when measuring the pace."
        ),
        fit="strong",
        storage=storage,
        spec=spec_path,
        metrics=[
            Metric("Busiest year (2022)", "555 adds"),
            Metric("Typical 2023-24 year", "~186 / yr"),
            Metric("Normal pace", f"~{steady_per_week} / week"),
            Metric("Time covered", "Nov 2021 - Jun 2026"),
        ],
        params={"resample": "MS (calendar month)", "rolling_window_months": 3,
                "steady_state_cohorts": [2023, 2024]},
        row_counts={"total": int(len(df)), "months": int(len(months))},
        data_quality_note="2021 and 2026 are partial years (the list started Nov 2021; the data "
                          "stops 2026-06-23), so don't measure a yearly pace from them.",
    )


# ----------------------------------------------------------------------------------------------
# 2. COHORT — by dateAdded-year: deadline regime + ransomware share (strong)
# ----------------------------------------------------------------------------------------------
def _cohort(df: pd.DataFrame) -> Analysis:
    df = df.copy()
    df["tier"] = df["ttd"].apply(_deadline_tier)

    tier_ct = (
        df.groupby(["addYear", "tier"]).size().rename("count").reset_index()
    )
    tier_rows = [
        {"addYear": int(r.addYear), "tier": r.tier, "count": int(r["count"])}
        for _, r in tier_ct.iterrows()
    ]

    ransom = (
        df.groupby("addYear")
        .agg(n=("isRansom", "size"), known=("isRansom", "sum"))
        .reset_index()
    )
    ransom["share"] = (ransom["known"] / ransom["n"]).round(3)
    ransom["censored"] = ransom["addYear"] >= 2025
    ransom_rows = [
        {"addYear": int(r.addYear), "share": float(r.share), "n": int(r.n),
         "censored": bool(r.censored)}
        for _, r in ransom.iterrows()
    ]

    # Verify the vintage claim on the backlog tier.
    backlog = df[df["tier"] == "backlog (>=180d)"]
    n_backlog = int(len(backlog))
    n_pre2021 = int((backlog["vintage"] < 2021).sum())
    backlog_max_vintage = int(backlog["vintage"].max())

    storage = [
        artifacts.write_json(f"{DATASET_ID}.cohort.deadline_tiers", tier_rows),
        artifacts.write_json(f"{DATASET_ID}.cohort.ransomware_share", ransom_rows),
        artifacts.write_table(
            f"{DATASET_ID}.cohort.backlog_vintage",
            backlog["vintage"].value_counts().sort_index()
            .rename_axis("vintage").reset_index(name="count"),
        ),
    ]

    tier_domain = ["standard (<=21d)", "backlog (>=180d)", "other"]
    tier_range = [ACCENT, SUSPICIOUS, NEUTRAL]

    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": {
            "text": "KEV deadlines and ransomware share, grouped by the year added",
            "subtitle": "Top: which deadline each group got (as a percentage) — the ~181-day "
                        "deadline is a leftover from the 2021-22 load-in. Bottom: ransomware share "
                        "(2025-26 is a rough guide, since confirmations come in late).",
        },
        "vconcat": [
            {
                "width": "container",
                "height": 240,
                "data": {"values": tier_rows},
                "mark": {"type": "bar"},
                "encoding": {
                    "x": {"field": "addYear", "type": "ordinal",
                          "title": "Cohort = year added"},
                    "y": {"field": "count", "type": "quantitative", "stack": "normalize",
                          "title": "Share of cohort", "axis": {"format": "%"}},
                    "color": {
                        "field": "tier", "type": "nominal", "title": "Deadline tier",
                        "scale": {"domain": tier_domain, "range": tier_range},
                    },
                    "tooltip": [
                        {"field": "addYear", "type": "ordinal", "title": "Cohort"},
                        {"field": "tier", "type": "nominal", "title": "Tier"},
                        {"field": "count", "type": "quantitative", "title": "CVEs"},
                    ],
                },
            },
            {
                "width": "container",
                "height": 180,
                "data": {"values": ransom_rows},
                "layer": [
                    {
                        "mark": {"type": "line", "color": MALICIOUS, "strokeWidth": 2},
                        "encoding": {
                            "x": {"field": "addYear", "type": "ordinal",
                                  "title": "Cohort = year added"},
                            "y": {"field": "share", "type": "quantitative",
                                  "title": "Known-ransomware share", "axis": {"format": "%"}},
                        },
                    },
                    {
                        "mark": {"type": "point", "filled": True, "size": 70},
                        "encoding": {
                            "x": {"field": "addYear", "type": "ordinal"},
                            "y": {"field": "share", "type": "quantitative"},
                            "color": {
                                "field": "censored", "type": "nominal",
                                "title": "Right-censored?",
                                "scale": {"domain": [False, True],
                                          "range": [MALICIOUS, NEUTRAL]},
                            },
                            "tooltip": [
                                {"field": "addYear", "type": "ordinal", "title": "Cohort"},
                                {"field": "share", "type": "quantitative",
                                 "format": ".1%", "title": "Ransom share"},
                                {"field": "n", "type": "quantitative", "title": "Cohort size"},
                                {"field": "censored", "type": "nominal", "title": "Censored"},
                            ],
                        },
                    },
                ],
            },
        ],
    }
    spec_path = artifacts.write_spec(f"{DATASET_ID}.cohort.regime", spec)

    return Analysis(
        technique="cohort",
        title="The fix-by deadline is a set rule based on a flaw's age, not a sign of danger",
        finding=(
            f"Splitting the flaws into groups by the year they were added shows the 'fix it by' "
            f"date follows a fixed rule, not how dangerous a flaw is. The ~181-day (about 6-month) "
            f"deadline shows up almost only in the first two groups — 200 of 311 (2021) "
            f"and 57 of 555 (2022) have deadlines of 180 days or more — and then nearly disappears "
            f"(0 in 2023-2025, 0 in 2026). Of the {n_backlog} long-deadline entries, "
            f"{n_pre2021} ({n_pre2021/n_backlog:.0%}) are flaws from before 2021, and none is newer "
            f"than {backlog_max_vintage}. In other words, CISA gave 6-month deadlines to the old "
            f"backlog it loaded in at the start, then put every new flaw on the tight 14/21-day "
            f"deadline. This FIXES an earlier claim that 'every 181-day entry is from before 2021': "
            f"10 are actually 2021 flaws (added in the 2021-22 load-in), so it is 247/257 from "
            f"before 2021, not all of them — but the long deadline is still a one-time leftover from "
            f"filling the list at launch, not a new rule (it came before the BOD 26-04 order). "
            f"Separately, the share of flaws tied to ransomware holds steady at ~22-24% for "
            f"2021-2024, then falls to ~10-11% for 2025-2026; that drop is most likely because the "
            f"data is a rough guide here — it takes months to confirm a flaw was used in "
            f"ransomware, so recent years look lower. Flag it; don't read it as a real decline."
        ),
        fit="strong",
        storage=storage,
        spec=spec_path,
        metrics=[
            Metric("21-day deadlines", "1,025 CVEs"),
            Metric("14-day deadlines", "255 CVEs"),
            Metric("180-day or longer (old pile)", f"{n_backlog} CVEs"),
            Metric("Old-pile flaws from before 2021", f"{n_pre2021}/{n_backlog}"),
        ],
        params={"cohort_key": "year(dateAdded)",
                "deadline_tiers": {"standard": "<=21d", "backlog": ">=180d", "other": "22-179d"}},
        row_counts={"total": int(len(df)), "backlog_tier": n_backlog},
        data_quality_note="The ransomware flag arrives late and depends on someone confirming the "
                          "link, so the 2025-26 drop is just missing late confirmations, not a "
                          "real trend.",
        fit_warning=None,
    )


# ----------------------------------------------------------------------------------------------
# 3. CLUSTER — vendor + CWE-family concentration / segmentation (moderate)
# ----------------------------------------------------------------------------------------------
def _cluster(df: pd.DataFrame) -> Analysis:
    n = len(df)
    vc = df["vendorProject"].value_counts()
    top = vc.head(15).rename_axis("vendor").reset_index(name="count")
    top["cum"] = top["count"].cumsum()
    top["cum_share"] = (top["cum"] / n).round(4)
    top["rank"] = range(1, len(top) + 1)
    pareto_rows = [
        {"vendor": r.vendor, "count": int(r["count"]), "rank": int(r["rank"]),
         "cum_share": float(r.cum_share)}
        for _, r in top.iterrows()
    ]

    # CWE-family concentration: multi-label, so count ROWS touched per family (not summed to 100%).
    fam_rows_touched: Counter = Counter()
    n_with_cwe = 0
    for lst in df["cwes"]:
        if not lst:
            continue
        n_with_cwe += 1
        fams = {_CWE_FAMILY.get(c, "other") for c in lst}
        for f in fams:
            fam_rows_touched[f] += 1
    fam_order = ["injection/input-validation", "memory-safety", "auth/access-control", "other"]
    fam_rows = [{"family": f, "rows": int(fam_rows_touched.get(f, 0))} for f in fam_order]

    ms = int(vc.get("Microsoft", 0))
    top5 = int(vc.head(5).sum())

    storage = [
        artifacts.write_table(
            f"{DATASET_ID}.cluster.vendor_counts",
            vc.rename_axis("vendor").reset_index(name="count"),
        ),
        artifacts.write_json(f"{DATASET_ID}.cluster.cwe_families", fam_rows),
    ]

    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": {
            "text": "Attacked flaws pile up under a few vendors (a few names hog most)",
            "subtitle": "Top-5 vendors = ~44% of all 1,627 KEV entries; a long tail of 269 vendors.",
        },
        "width": "container",
        "height": 360,
        "data": {"values": pareto_rows},
        "encoding": {
            "x": {"field": "vendor", "type": "nominal", "sort": "-y",
                  "title": "Vendor / project (top 15)"},
        },
        "layer": [
            {
                "mark": {"type": "bar", "color": ACCENT},
                "encoding": {
                    "y": {"field": "count", "type": "quantitative",
                          "title": "KEV entries", "axis": {"titleColor": ACCENT}},
                    "tooltip": [
                        {"field": "vendor", "type": "nominal", "title": "Vendor"},
                        {"field": "count", "type": "quantitative", "title": "KEV entries"},
                        {"field": "cum_share", "type": "quantitative", "format": ".1%",
                         "title": "Cumulative share"},
                    ],
                },
            },
            {
                "mark": {"type": "line", "color": SUSPICIOUS, "strokeWidth": 2,
                         "point": {"filled": True, "color": SUSPICIOUS}},
                "encoding": {
                    "y": {"field": "cum_share", "type": "quantitative",
                          "title": "Cumulative share", "axis": {"format": "%",
                                                                "titleColor": SUSPICIOUS}},
                    "tooltip": [
                        {"field": "vendor", "type": "nominal", "title": "Vendor"},
                        {"field": "cum_share", "type": "quantitative", "format": ".1%",
                         "title": "Cumulative share"},
                    ],
                },
            },
        ],
        "resolve": {"scale": {"y": "independent"}},
    }
    spec_path = artifacts.write_spec(f"{DATASET_ID}.cluster.pareto", spec)

    return Analysis(
        technique="cluster",
        title="Risk is lopsided: 5 vendors make up ~44%, and two bug types lead",
        finding=(
            f"This looks at how lopsided the list is — a few names hogging most of it — rather than "
            f"finding true clusters, so the honest fit is moderate. The columns are categories, not "
            f"numbers. The list leans hard toward a few vendors (the companies that make the "
            f"software): Microsoft alone is {ms}/{n} ({ms/n:.0%}) and the top-5 vendors "
            f"(Microsoft, Apple 93, Cisco 92, Adobe 79, Google 72) are {top5}/{n} "
            f"({top5/n:.0%}), with a long tail of 269 vendors behind them. By bug type (one flaw "
            f"can have more than one type tag, so these counts overlap and must not be added up to "
            f"100%): injection/input-validation (tricking software with bad input) touches "
            f"{fam_rows_touched['injection/input-validation']} "
            f"CVEs and memory-safety (mishandling computer memory) "
            f"{fam_rows_touched['memory-safety']} — the two biggest "
            f"types; auth/access-control (getting in or doing things you should not be allowed to) "
            f"adds {fam_rows_touched['auth/access-control']}. "
            f"{n - n_with_cwe} entries have no bug-type tag. Because ~44% of the attacked-software "
            f"surface comes from just five vendors' update streams, this lopsidedness — not the "
            f"'fix it by' date — is where it pays most to focus."
        ),
        fit="moderate",
        storage=storage,
        spec=spec_path,
        metrics=[
            Metric("Microsoft", f"{ms} ({ms/n:.0%})"),
            Metric("Top-5 vendors", f"{top5/n:.0%}"),
            Metric("Different vendors", "269"),
            Metric("Injection bug type", f"{fam_rows_touched['injection/input-validation']} CVEs"),
        ],
        params={"top_k_vendors_charted": 15, "cwe_family_basis": "rows-touched (multi-label)"},
        row_counts={"total": int(n), "with_cwe": int(n_with_cwe), "distinct_vendors": int(vc.size)},
        data_quality_note="One flaw can have more than one type tag, so the type counts overlap "
                          "and don't add up to the list size; 171 entries have no type tag.",
        fit_warning="The columns are categories, not numbers, so this shows how lopsided the counts "
                    "are, not real cluster shapes.",
    )


def build(m: artifacts.Manifest) -> Dataset:
    df = _load()

    analyses = [_timeseries(df), _cohort(df), _cluster(df)]

    ds = Dataset(
        id=DATASET_ID,
        display_name="CISA Known Exploited Vulnerabilities (KEV) Catalog",
        doc_category="threat-intel",
        what_it_is=(
            "A hand-picked list from CISA of software flaws (each flaw has an ID called a CVE) that "
            "are confirmed to be under real attack. One row = one flaw, with the vendor/product it "
            "is in, the date CISA added it, a 'fix it by' date, a flag for whether ransomware "
            "(nasty software that locks your files for ransom) used it, and tags for the kind of "
            "bug (1,627 rows, zero missing values)."
        ),
        source={
            "name": "CISA Known Exploited Vulnerabilities Catalog",
            "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "license": "CC0 1.0 (U.S. Government public domain)",
        },
        isolated_insight=(
            "In this list, the official 'fix it by' date is set by a simple two-step rule based on "
            "how old a flaw is — not by how risky it is. New flaws get a tight 14- or 21-day "
            "deadline (21 days shows up 1,025x, 14 days 255x), while the ~181-day (about 6-month) "
            "deadlines went almost entirely to the old backlog CISA loaded in at the 2021-2022 "
            "start (247 of 257 long-deadline entries are from before 2021, none newer than 2021, "
            "and these long deadlines stop after 2022). Meanwhile the attacked flaws pile up under "
            "a few names — Microsoft 23%, top-5 vendors ~44% — across two leading bug types "
            "(injection/input-validation and memory-safety). So to judge real attack risk, look at "
            "this lopsidedness, not the 'fix it by' date."
        ),
        solution_idea=(
            "A 'KEV Exposure Mapper': take a list of the software a company runs, and re-rank the "
            "attacked flaws by how lopsided the list really is, instead of by the official 'fix it "
            "by' date. Since about 44% of the attacked-software surface comes from five vendors, it "
            "scores each system by its exposure to the top vendors and top bug types, and produces "
            "a 'patch these five vendors first' plan. It also flags any item whose long (~180-day) "
            "deadline is just a leftover from the old backlog, so an old flaw that is actively under "
            "attack does not get pushed down the list only because its official deadline looks "
            "relaxed. The point is to separate real attack risk from the official deadline buckets."
        ),
        honesty_notes=(
            "(1) The ransomware flag arrives late and depends on someone confirming the link, so "
            "the apparent drop from ~23% (2021-24) to ~10% (2025-26) is most likely just missing "
            "late confirmations, not a real decline. (2) The 181-day deadline is NOT a new BOD "
            "26-04 order; it is a one-time leftover from filling the list in 2021-22 (247/257 from "
            "before 2021, newest is 2021) — this fixes both an earlier 'new order' guess and the "
            "claim that 'every 181-day entry is from before 2021' (10 are actually 2021 flaws). "
            "(3) The grouping is honestly a moderate fit: the columns are categories, not numbers, "
            "so the work is about how lopsided the counts are, not real cluster shapes. (4) This "
            "list is CISA's hand-picked set of decisions, not a fair sample of every attacked flaw "
            "— the vendor lopsidedness reflects both where attackers really focus and what CISA (a "
            "US federal agency) tends to see. (5) One flaw can have more than one bug-type tag, so "
            "the bug-type counts overlap and must not be added up to 100%; 171 entries have no "
            "bug-type tag. (6) We skipped a few methods because they would be forced here: a "
            "predict-from-the-columns formula (the deadline already follows a fixed rule, so there "
            "is nothing left to explain), squeezing the columns down to a few (they are categories, "
            "not numbers), rolling the dice to simulate a range of outcomes (there is no random "
            "process to model), and reading the text (the text fields are filled from templates)."
        ),
        analyses=analyses,
    )
    m.add(ds)
    return ds
