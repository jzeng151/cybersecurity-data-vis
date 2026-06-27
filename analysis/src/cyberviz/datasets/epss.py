"""EPSS daily snapshot — analyzed in isolation.

One row per CVE for a single score_date: cve, epss (P[exploitation in next 30 days]), percentile.
342,575 CVEs, no time dimension (one date only). The sole derivable second dimension is the CVE
vintage year parsed from the id. Three techniques fit honestly: a cross-sectional cohort by vintage
(strong), a log-linear regression of mean EPSS on vintage (moderate), and a Poisson-binomial Monte
Carlo that uses EPSS's own Bernoulli-probability semantics to quantify how concentrated the expected
exploitation mass is (moderate). Everything below is computed from this one file; no other dataset is
referenced and no cross-dataset thesis is imposed.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .. import artifacts
from ..acquire import epss as epss_acquire
from ..artifacts import Analysis, Dataset, Metric
from ..colors import ACCENT, MALICIOUS, NEUTRAL, SUSPICIOUS

DSID = "epss"
SCHEMA = "https://vega.github.io/schema/vega-lite/v5.json"


def _gini(x: np.ndarray) -> float:
    xs = np.sort(x)
    n = len(xs)
    idx = np.arange(1, n + 1)
    return float((2.0 * (idx * xs).sum()) / (n * xs.sum()) - (n + 1) / n)


def build(m: artifacts.Manifest) -> Dataset:
    df = epss_acquire.load()
    df = df.assign(year=df["cve"].str.extract(r"CVE-(\d{4})")[0].astype(int))
    p = df["epss"].to_numpy(dtype=float)
    n = len(p)

    # ---- shared cohort aggregates -------------------------------------------------
    g = (
        df.groupby("year")["epss"]
        .agg(count="count", mean="mean", median="median")
        .reset_index()
        .sort_values("year")
    )

    # ======================================================================
    # 1) COHORT (strong) — mean/median EPSS by CVE vintage year
    # ======================================================================
    cohort_tbl = g.round({"mean": 6, "median": 6})
    cohort_store = artifacts.write_table(f"{DSID}.cohort.by_year", cohort_tbl)

    bar_rows = [
        {"year": int(r.year), "count": int(r.count)} for r in g.itertuples()
    ]
    line_rows = []
    for r in g.itertuples():
        line_rows.append({"year": int(r.year), "stat": "mean EPSS", "value": float(r.mean)})
        line_rows.append({"year": int(r.year), "stat": "median EPSS", "value": float(r.median)})

    cohort_spec = {
        "$schema": SCHEMA,
        "width": "container",
        "height": 360,
        "title": {
            "text": "Older bugs are riskier one-by-one, even though there are far more new bugs",
            "subtitle": "Just one day's scores (not a history) — split by the year each bug got its ID number",
        },
        "layer": [
            {
                "data": {"values": bar_rows},
                "mark": {"type": "bar", "color": NEUTRAL, "opacity": 0.5},
                "encoding": {
                    "x": {"field": "year", "type": "ordinal", "title": "CVE vintage year"},
                    "y": {
                        "field": "count",
                        "type": "quantitative",
                        "title": "CVE count (volume)",
                        "axis": {"titleColor": NEUTRAL},
                    },
                },
            },
            {
                "data": {"values": line_rows},
                "mark": {"type": "line", "point": True},
                "encoding": {
                    "x": {"field": "year", "type": "ordinal", "title": "CVE vintage year"},
                    "y": {
                        "field": "value",
                        "type": "quantitative",
                        "title": "EPSS (log scale)",
                        "scale": {"type": "log"},
                        "axis": {"titleColor": MALICIOUS},
                    },
                    "color": {
                        "field": "stat",
                        "type": "nominal",
                        "title": "per-CVE risk",
                        "scale": {
                            "domain": ["mean EPSS", "median EPSS"],
                            "range": [MALICIOUS, SUSPICIOUS],
                        },
                        "legend": {"title": "per-CVE risk"},
                    },
                },
            },
        ],
        "resolve": {"scale": {"y": "independent"}},
    }
    cohort_spec_path = artifacts.write_spec(f"{DSID}.cohort.bar_line", cohort_spec)

    m2015 = float(g.loc[g.year == 2015, "mean"].iloc[0])
    m2026 = float(g.loc[g.year == 2026, "mean"].iloc[0])
    ratio = m2015 / m2026
    vol_recent = int(g.loc[g.year >= 2024, "count"].sum())

    cohort = Analysis(
        technique="cohort",
        title="Older bugs are much more likely to get attacked, one bug at a time",
        finding=(
            f"Splitting the {n:,} bugs into groups by the year in their ID gives 28 year-groups "
            f"(1,236-43,047 bugs each). The average EPSS score gets smaller for newer years: 0.053 (2015) -> 0.041 (2018) "
            f"-> 0.036 (2019) -> 0.023 (2022) -> 0.0155 (2024) -> 0.0089 (2025) -> 0.0064 (2026); the middle bug in "
            f"each group follows the same path (0.0196 -> 0.0027). The 2015 group's average is {ratio:.1f}x the 2026 group's, so "
            f"older bugs really are much more likely to be attacked, one bug at a time. The groups before 2017 jump around "
            f"(0.04-0.066, no clear pattern); the steady drop only kicks in after 2016. The catch goes the other way: "
            f"the 2024-2026 years alone hold {vol_recent:,} of the {n:,} bugs, "
            f"so the newest and most common bugs are the least risky each on their own. Remember, this compares bugs of "
            f"different ages on one day — it is NOT a score changing over time."
        ),
        fit="strong",
        storage=[cohort_store],
        spec=cohort_spec_path,
        metrics=[
            Metric("Average score for 2015 bugs", "0.053"),
            Metric("Average score for 2026 bugs", "0.0064"),
            Metric("Times bigger: 2015 vs 2026", f"{ratio:.1f}x"),
            Metric("Age groups (by ID year)", "28 (1999-2026)"),
        ],
        params={"vintage_key": "regexp CVE-(\\d{4})", "aggregations": ["count", "mean", "median"]},
        row_counts={"cves": n, "cohorts": int(g.shape[0])},
        data_quality_note=(
            "The 'age' here is just the year in the bug's ID (the year it was filed), which is a rough "
            "stand-in for how old it really is. It blends together how long attacks had to be built, famous "
            "old bugs that are known to be attacked pulling old groups up, and the EPSS model covering new "
            "bugs differently. This file can't pull those apart."
        ),
    )

    # ======================================================================
    # 2) REGRESSION (moderate) — log(mean EPSS) ~ vintage year, 2013-2026
    # ======================================================================
    fit = g[(g.year >= 2013) & (g.year <= 2026)]
    yrs = fit["year"].to_numpy(dtype=float)
    logmean = np.log(fit["mean"].to_numpy(dtype=float))
    slope, intercept = np.polyfit(yrs, logmean, 1)
    yhat = slope * yrs + intercept
    ss_res = float(((logmean - yhat) ** 2).sum())
    ss_tot = float(((logmean - logmean.mean()) ** 2).sum())
    r2 = 1.0 - ss_res / ss_tot
    pct_per_yr = (np.exp(slope) - 1.0) * 100.0
    # per-CVE sensitivity (raw rows, not cohort means) — same 2013-2026 window as the cohort fit
    raw_mask = ((df["year"] >= 2013) & (df["year"] <= 2026)).to_numpy()
    n_raw = int(raw_mask.sum())
    s_raw, _ = np.polyfit(df["year"].to_numpy(dtype=float)[raw_mask], np.log(p[raw_mask]), 1)
    pct_raw = (np.exp(s_raw) - 1.0) * 100.0

    reg_tbl = fit[["year", "mean"]].copy()
    reg_tbl["log_mean"] = logmean
    reg_tbl["fitted"] = np.exp(yhat)
    reg_tbl["residual"] = logmean - yhat
    reg_store = artifacts.write_table(f"{DSID}.regression.cohort_fit", reg_tbl.round(6))
    reg_params_store = artifacts.write_json(
        f"{DSID}.regression.params",
        {
            "window": [2013, 2026],
            "slope_log_per_year": round(float(slope), 5),
            "pct_change_per_year": round(float(pct_per_yr), 3),
            "r2": round(float(r2), 4),
            "per_cve_slope": round(float(s_raw), 5),
            "per_cve_pct_per_year": round(float(pct_raw), 3),
        },
    )

    pt_rows = [
        {"year": int(r.year), "mean": float(r.mean), "series": "cohort mean (per vintage year)"}
        for r in g.itertuples()
    ]
    fit_line_rows = [
        {"year": 2013.0, "fitted": float(np.exp(slope * 2013 + intercept)), "series": "log-linear fit 2013-2026"},
        {"year": 2026.0, "fitted": float(np.exp(slope * 2026 + intercept)), "series": "log-linear fit 2013-2026"},
    ]
    reg_spec = {
        "$schema": SCHEMA,
        "width": "container",
        "height": 360,
        "title": {
            "text": "You can partly guess a bug's chance of attack from its age alone",
            "subtitle": f"average score vs ID year, 2013-2026: {pct_per_yr:.1f}%/yr, R^2={r2:.2f}",
        },
        "layer": [
            {
                "data": {"values": pt_rows},
                "mark": {"type": "point", "filled": True, "size": 70},
                "encoding": {
                    "x": {"field": "year", "type": "quantitative", "title": "CVE vintage year",
                          "scale": {"zero": False}, "axis": {"format": "d"}},
                    "y": {"field": "mean", "type": "quantitative", "title": "mean EPSS (log scale)",
                          "scale": {"type": "log"}},
                    "color": {
                        "field": "series", "type": "nominal", "title": "series",
                        "scale": {
                            "domain": ["cohort mean (per vintage year)", "log-linear fit 2013-2026"],
                            "range": [ACCENT, MALICIOUS],
                        },
                    },
                    "tooltip": [
                        {"field": "year", "type": "quantitative", "title": "year"},
                        {"field": "mean", "type": "quantitative", "title": "mean EPSS", "format": ".4f"},
                    ],
                },
            },
            {
                "data": {"values": fit_line_rows},
                "mark": {"type": "line", "strokeWidth": 2.5},
                "encoding": {
                    "x": {"field": "year", "type": "quantitative"},
                    "y": {"field": "fitted", "type": "quantitative", "scale": {"type": "log"}},
                    "color": {
                        "field": "series", "type": "nominal",
                        "scale": {
                            "domain": ["cohort mean (per vintage year)", "log-linear fit 2013-2026"],
                            "range": [ACCENT, MALICIOUS],
                        },
                    },
                },
            },
        ],
    }
    reg_spec_path = artifacts.write_spec(f"{DSID}.regression.scatter_fit", reg_spec)

    regression = Analysis(
        technique="regression",
        title="The average score drops about 13% for each newer year",
        finding=(
            f"We fit a simple formula (one that learns to predict the average score from the year alone) to the "
            f"year-group averages from 2013-2026. It comes out to a slope of "
            f"{slope:.3f} per year, meaning the average chance of attack drops about {abs(pct_per_yr):.1f}% "
            f"for each newer year, with a fit score of R^2={r2:.2f} on the 14 year-group averages (this fit "
            f"score runs from 0 to 1, where 1 is a perfect match). (This fixes "
            f"an earlier first-draft guess of -0.16..-0.18/yr and R^2>0.9: the real drop is gentler "
            f"and the fit is looser, because the 2015 group sits above the line and the early-2010s years are "
            f"almost flat.) The pattern holds up when you don't group: on the {n_raw:,} single-bug rows from the same "
            f"2013-2026 window the slope softens to {s_raw:.3f}/yr ({abs(pct_raw):.1f}%/yr) but still points the "
            f"same way. Bottom line: you can guess a bug's chance of attack "
            f"pretty well from its age alone, with no other details at all."
        ),
        fit="moderate",
        storage=[reg_store, reg_params_store],
        spec=reg_spec_path,
        metrics=[
            Metric("Score change per year (log)", f"{slope:.3f}"),
            Metric("Drop in score each year", f"{pct_per_yr:.1f}%"),
            Metric("Fit score 0-1 (groups 2013-26)", f"{r2:.2f}"),
            Metric("Same drop, per single bug (check)", f"{s_raw:.3f}"),
        ],
        params={"model": "log(mean_epss) ~ year", "window": [2013, 2026]},
        row_counts={"cohort_means": int(fit.shape[0]), "raw_rows": n_raw},
        fit_warning=(
            "Just one line drawn through 14 grouped averages, using only one useful clue (age). "
            "So it's okay, not great — and the age pattern mixes several causes together (see the age-group note)."
        ),
    )

    # ======================================================================
    # 3) MONTE_CARLO (moderate) — Poisson-binomial of 342,575 Bernoulli(epss) trials
    # ======================================================================
    expected = float(p.sum())
    sd = float(np.sqrt((p * (1.0 - p)).sum()))  # exact Poisson-binomial sd
    lo, hi = expected - 1.96 * sd, expected + 1.96 * sd
    # deterministic MC confirmation (seed 0), looped to stay memory-light
    rng = np.random.default_rng(0)
    draws = np.array([(rng.random(n) < p).sum() for _ in range(2000)], dtype=float)
    mc_mean, mc_sd = float(draws.mean()), float(draws.std())

    ps = np.sort(p)[::-1]
    cum = np.cumsum(ps) / expected
    gini = _gini(p)
    share = {f: float(cum[int(f * n) - 1]) for f in (0.01, 0.05, 0.10)}
    frac_ge_50 = float((p >= 0.5).mean()) * 100
    frac_ge_90 = float((p >= 0.9).mean()) * 100
    frac_ge_05 = float((p >= 0.05).mean()) * 100

    # Lorenz / coverage curve, deterministically sampled to ~200 points
    fracs = sorted(set(np.linspace(0.0, 1.0, 200).tolist() + [0.01, 0.05, 0.10]))
    curve_rows = []
    for f in fracs:
        k = int(round(f * n))
        mass = 0.0 if k == 0 else float(cum[min(k, n) - 1])
        curve_rows.append({"cve_share": round(f, 5), "mass_share": round(mass, 5),
                           "series": "expected-exploit mass"})
    ref_rows = [
        {"cve_share": 0.0, "mass_share": 0.0, "series": "equal-share reference"},
        {"cve_share": 1.0, "mass_share": 1.0, "series": "equal-share reference"},
    ]
    anno_rows = [
        {"cve_share": 0.01, "mass_share": round(share[0.01], 3), "label": "top 1% -> 27%"},
        {"cve_share": 0.05, "mass_share": round(share[0.05], 3), "label": "top 5% -> 59%"},
        {"cve_share": 0.10, "mass_share": round(share[0.10], 3), "label": "top 10% -> 70%"},
    ]
    curve_store = artifacts.write_json(
        f"{DSID}.monte_carlo.coverage",
        {
            "expected_total": round(expected, 1),
            "sd": round(sd, 1),
            "ci95": [round(lo, 1), round(hi, 1)],
            "mc_seed0_mean": round(mc_mean, 1),
            "mc_seed0_sd": round(mc_sd, 1),
            "gini": round(gini, 4),
            "share_of_mass": {f"top_{int(k*100)}pct": round(v, 4) for k, v in share.items()},
            "frac_epss_ge": {"0.05": round(frac_ge_05, 3), "0.5": round(frac_ge_50, 3), "0.9": round(frac_ge_90, 3)},
            "curve": curve_rows,
        },
    )

    mc_spec = {
        "$schema": SCHEMA,
        "width": "container",
        "height": 360,
        "title": {
            "text": "Almost all the expected attacks pile up on a few bugs (Gini 0.77)",
            "subtitle": f"All scores added = ~{expected:,.0f} expected attacks in 30 days; the riskiest 10% of bugs hold ~70%",
        },
        "layer": [
            {
                "data": {"values": ref_rows},
                "mark": {"type": "line", "strokeDash": [5, 4], "color": NEUTRAL},
                "encoding": {
                    "x": {"field": "cve_share", "type": "quantitative"},
                    "y": {"field": "mass_share", "type": "quantitative"},
                },
            },
            {
                "data": {"values": curve_rows},
                "mark": {"type": "area", "line": {"color": MALICIOUS}, "color": MALICIOUS, "opacity": 0.25},
                "encoding": {
                    "x": {"field": "cve_share", "type": "quantitative",
                          "title": "cumulative share of CVEs (ranked by EPSS, high -> low)",
                          "axis": {"format": "%"}},
                    "y": {"field": "mass_share", "type": "quantitative",
                          "title": "cumulative share of expected exploitations",
                          "axis": {"format": "%"}},
                    "color": {
                        "field": "series", "type": "nominal", "title": "",
                        "scale": {
                            "domain": ["expected-exploit mass", "equal-share reference"],
                            "range": [MALICIOUS, NEUTRAL],
                        },
                    },
                },
            },
            {
                "data": {"values": anno_rows},
                "mark": {"type": "point", "filled": True, "size": 80, "color": ACCENT},
                "encoding": {
                    "x": {"field": "cve_share", "type": "quantitative"},
                    "y": {"field": "mass_share", "type": "quantitative"},
                    "tooltip": [{"field": "label", "type": "nominal", "title": "coverage"}],
                },
            },
            {
                "data": {"values": anno_rows},
                "mark": {"type": "text", "align": "left", "dx": 8, "dy": -6, "color": ACCENT, "fontSize": 11},
                "encoding": {
                    "x": {"field": "cve_share", "type": "quantitative"},
                    "y": {"field": "mass_share", "type": "quantitative"},
                    "text": {"field": "label", "type": "nominal"},
                },
            },
        ],
    }
    mc_spec_path = artifacts.write_spec(f"{DSID}.monte_carlo.lorenz", mc_spec)

    monte_carlo = Analysis(
        technique="monte_carlo",
        title="About 10,029 attacks expected, and 70% of them land on the riskiest 10% of bugs",
        finding=(
            f"Each EPSS score IS the chance that bug gets attacked in 30 days, so adding up each bug's own chance "
            f"across all {n:,} bugs gives the expected number of attacks. That total is {expected:,.0f} "
            f"attacks, with a spread of {sd:.0f} either way (so the answer should land in about {lo:,.0f}-{hi:,.0f} "
            f"95% of the time, a range about {200*1.96*sd/expected:.1f}% "
            f"wide). To double-check, we rolled the dice 2,000 times (using a fixed starting point, seed 0) and got "
            f"the same thing (average {mc_mean:,.0f}, spread {mc_sd:.0f}). "
            f"(This fixes an earlier guess of about 95 for the spread, down to {sd:.0f}.) The risk is piled up in "
            f"very few bugs: the lopsidedness score (Gini) is {gini:.3f}, with the riskiest 1% of bugs holding {share[0.01]*100:.0f}% of "
            f"the expected attacks, the top 5% {share[0.05]*100:.0f}%, and the top 10% {share[0.10]*100:.0f}% — while only "
            f"{frac_ge_50:.2f}% of bugs score >=0.5 and {frac_ge_90:.2f}% score >=0.9. Fixing the riskiest ~10% of "
            f"bugs removes ~{share[0.10]*100:.0f}% of the expected attacks."
        ),
        fit="moderate",
        storage=[curve_store],
        spec=mc_spec_path,
        metrics=[
            Metric("Expected attacks (all scores added)", f"~{expected:,.0f}"),
            Metric("Likely range (95%)", f"{lo:,.0f}-{hi:,.0f}"),
            Metric("Share held by riskiest 10%", f"{share[0.10]*100:.0f}%"),
            Metric("Lopsidedness (Gini)", f"{gini:.2f}"),
        ],
        params={"trials": 2000, "seed": 0, "horizon_days": 30, "method": "Poisson-binomial"},
        row_counts={"cves": n},
        fit_warning=(
            "It assumes the EPSS scores are honest chances and that each bug's outcome doesn't affect the "
            "others — neither can be checked from this file. And the counts only cover the 30-day window EPSS is built around."
        ),
    )

    ds = Dataset(
        id=DSID,
        display_name="EPSS (Exploit Prediction Scoring System) daily scores — single snapshot",
        doc_category="threat-intel",
        what_it_is="One row for each known software bug (called a CVE — a security flaw with its own ID number), all scored on one single day. The columns are the EPSS score (a guess at the chance the bug gets attacked in the next 30 days, from 0 to 1) and its percentile (its rank against all the others).",
        source={
            "name": "FIRST.org EPSS (Cyentia)",
            "url": "https://epss.cyentia.com/epss_scores-current.csv.gz",
            "license": "Free for public use (FIRST EPSS)",
        },
        isolated_insight=(
            f"In this one-day snapshot of {n:,} bugs, the chance of attack is squeezed into a tiny number of "
            f"bugs, and a bug's age alone tells you a lot. Lopsidedness: most bugs score very low and a few "
            f"score very high (the middle bug scores 0.0075, the highest scores about 1.0; the lopsidedness score, "
            f"called Gini, is {gini:.2f}, where 0 is perfectly even and 1 is one bug hogging everything). Adding up "
            f"all the EPSS scores gives about {expected:,.0f} "
            f"expected attacks, of which the riskiest 1% of bugs hold {share[0.01]*100:.0f}%, the top 5% "
            f"{share[0.05]*100:.0f}%, and the top 10% {share[0.10]*100:.0f}% — yet only {frac_ge_50:.2f}% of "
            f"all bugs score 0.5 or higher. Age pattern: the average EPSS score drops about {abs(pct_per_yr):.0f}% for each newer year a bug got its ID "
            f"(2013-2026), from about 0.053 (2015) to about 0.006 (2026), so older bugs are far more likely to be "
            f"attacked one-by-one, even with no other details about them. So the risk is not spread "
            f"evenly across all the bugs — it sits in a thin, easy-to-spot, older-leaning slice."
        ),
        solution_idea=(
            "A 'fix-the-most-with-the-least' tool. You give it the list of bugs your computers have. It sorts "
            "them by EPSS score and draws a curve showing how much of the total attack risk you remove as you "
            "fix more bugs — 'fix these N bugs to wipe out X% of your expected attack risk.' Because ~10% of bugs "
            "carry ~70% of the expected attacks, it finds the smallest set of bugs that hits a target you pick "
            "(80/90/95%), tells you how many attacks you'd expect to remove (with a range to show the wiggle room), "
            "and lets you turn on extra weight for older bugs, since older bugs tend to score higher on EPSS. It "
            "uses nothing but this one file — no severity rating, no value of the computer, no outside feeds."
        ),
        honesty_notes=(
            "(1) This is ONE day's scores, not a history — every 'pattern' here compares bugs of different ages "
            "on the same day, NOT how a score changes over time; don't read it that way. (2) The percentile is just "
            "the EPSS score turned into a rank, so it tells you nothing new. (3) There is no record of which bugs "
            "were really attacked, no severity rating, and no maker/product columns — the only extra fact we can "
            "pull out is the year in the bug's ID, so there is only so much we can dig into. (4) The age pattern "
            "mixes up several causes (older bugs had more time for attacks to be built; famous old bugs that are "
            "known to be attacked pull the old groups up; the EPSS model may cover new bugs differently) — this "
            "file can't tell them apart. (5) The dice-rolling test assumes the EPSS scores are honest chances and "
            "that each bug's outcome doesn't affect the others, neither of which can be checked here, and it only "
            "covers the 30-day window. (6) Fixes to the earlier first-draft guesses: the formula's drop is "
            "-0.143/yr (about -13%/yr) and fits with a score of R^2=0.83 (this fit score runs 0 to 1, where 1 is "
            "perfect), not -0.16..-0.18 with R^2>0.9; the spread from the dice test is 82, not ~95; bugs scoring "
            f"0.05 or higher are {frac_ge_05:.1f}% of the whole list. Grouping bugs into clusters, squeezing columns "
            "together, true sign-up-date groups, over-time charts, and reading text all don't fit a 3-column "
            "one-day number file, so they were left out."
        ),
        analyses=[cohort, regression, monte_carlo],
    )
    m.add(ds)
    return ds
