"""CTU-13 Botnet NetFlow (scenario 11 / Botnet-52) analyzed in isolation.

One ~15-minute Argus bidirectional-netflow capture, ~107k flows, per-flow Label in
{Botnet, Normal, Background}. Two techniques fit strongly and jointly say one thing:
the malicious traffic is invisible at the single-flow grain (it co-mingles with benign
ICMP) and only emerges as an aggregate per-source temporal burst.

Module contract: build(m) writes artifacts, constructs the Dataset, registers it, returns it.
Deterministic: random_state=0 everywhere; the scatter sample uses a fixed seed.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from cyberviz import artifacts
from cyberviz.artifacts import Analysis, Dataset, Metric
from cyberviz.acquire.ctu13 import load

DATASET_ID = "ctu-13"

# severity / accent hexes (mirrored from cyberviz.colors)
MALICIOUS = "#d2483f"
SUSPICIOUS = "#e0a341"
BENIGN = "#5b6b7a"
NOISE = "#8a94a6"

_VICTIM = "147.32.96.69"
_INFECTED = ["147.32.84.165", "147.32.84.191"]
_BENIGN_HOST = "147.32.84.138"  # busiest non-botnet source; steady non-bursty baseline
_BIN_SECONDS = 30


def _prepare(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["cls"] = df["Label"].str.extract(r"(Botnet|Normal|Background)", expand=False)
    t0 = df["StartTime"].min()
    df["sec"] = (df["StartTime"] - t0).dt.total_seconds()
    df["bin"] = (df["sec"] // _BIN_SECONDS).astype(int)
    return df


def _cluster(df: pd.DataFrame) -> Analysis:
    # Unsupervised segmentation on per-flow features. Label and DstAddr are NOT fed in;
    # we evaluate clusters against Label post-hoc to test per-flow separability.
    feat = pd.DataFrame(index=df.index)
    feat["logpkts"] = np.log10(df["TotPkts"] + 1)
    feat["logbytes"] = np.log10(df["TotBytes"] + 1)
    feat["logdur"] = np.log10(df["Dur"] + 1e-3)
    feat["srcratio"] = df["SrcPkts"] / df["TotPkts"].clip(lower=1)
    feat["sTtl"] = df["sTtl"].fillna(df["sTtl"].median())
    feat["sHops"] = df["sHops"].fillna(df["sHops"].median())
    for p in ("udp", "tcp", "icmp"):
        feat[f"proto_{p}"] = (df["Proto"] == p).astype(int)

    X = StandardScaler().fit_transform(feat.values)
    km = KMeans(n_clusters=7, random_state=0, n_init=10).fit(X)
    k = km.labels_

    work = df.assign(k=k)
    ct = pd.crosstab(work["k"], work["cls"]).reindex(
        columns=["Botnet", "Normal", "Background"], fill_value=0
    )
    bot_cluster = int(work.loc[work["cls"] == "Botnet", "k"].value_counts().idxmax())
    blob = work[work["k"] == bot_cluster]
    blob_size = int(len(blob))
    bot_in_blob = int((blob["cls"] == "Botnet").sum())
    normal_in_blob = int((blob["cls"] == "Normal").sum())
    bg_in_blob = int((blob["cls"] == "Background").sum())
    purity = bot_in_blob / blob_size
    blob_med_pkts = int(blob["TotPkts"].median())
    blob_med_bytes = int(blob["TotBytes"].median())

    # cluster x class composition table
    summary = ct.reset_index().rename(columns={"k": "cluster"})
    summary["size"] = summary[["Botnet", "Normal", "Background"]].sum(axis=1)
    summary["is_botnet_cluster"] = summary["cluster"] == bot_cluster
    summary_path = artifacts.write_table(f"{DATASET_ID}.cluster.summary", summary)

    # stratified, jittered scatter sample (proportional sampling would let 90% background
    # bury the blob and hide the co-mingling the chart exists to show).
    rng = np.random.default_rng(0)
    caps = {"Botnet": 500, "Normal": 400, "Background": 500}
    parts = []
    for cls, cap in caps.items():
        rows = work[work["cls"] == cls]
        if len(rows) > cap:
            rows = rows.sample(n=cap, random_state=0)
        parts.append(rows)
    samp = pd.concat(parts)
    jitter_x = rng.normal(0, 0.05, len(samp))
    jitter_y = rng.normal(0, 0.05, len(samp))
    pts = [
        {
            "x": round(float(np.log10(b + 1)) + jx, 3),
            "y": round(float(np.log10(p + 1)) + jy, 3),
            "cls": c,
        }
        for b, p, c, jx, jy in zip(
            samp["TotBytes"], samp["TotPkts"], samp["cls"], jitter_x, jitter_y
        )
    ]
    pts_path = artifacts.write_json(f"{DATASET_ID}.cluster.points", pts)

    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": {
            "text": "Looking at one connection at a time can't pick out the attack",
            "subtitle": "size in bytes vs number of packets (both on a squished log scale). The "
            "big tight clump of ICMP pings mixes attack, normal, and background traffic together "
            "(we kept a fair share of each group, with tiny random nudges so dots don't overlap)",
        },
        "width": "container",
        "height": 420,
        "data": {"values": pts},
        "mark": {"type": "point", "filled": True, "size": 28, "opacity": 0.45},
        "encoding": {
            "x": {
                "field": "x",
                "type": "quantitative",
                "title": "log₁₀(TotBytes + 1)",
                "scale": {"zero": False},
            },
            "y": {
                "field": "y",
                "type": "quantitative",
                "title": "log₁₀(TotPkts + 1)",
                "scale": {"zero": False},
            },
            "color": {
                "field": "cls",
                "type": "nominal",
                "title": "Label",
                "scale": {
                    "domain": ["Botnet", "Normal", "Background"],
                    "range": [MALICIOUS, BENIGN, NOISE],
                },
            },
            "tooltip": [
                {"field": "cls", "type": "nominal", "title": "Label"},
                {"field": "x", "type": "quantitative", "title": "log10 bytes"},
                {"field": "y", "type": "quantitative", "title": "log10 pkts"},
            ],
        },
    }
    spec_path = artifacts.write_spec(f"{DATASET_ID}.cluster.scatter", spec)

    finding = (
        f"We let the computer sort the connections into 7 groups on its own (a method called "
        f"KMeans), using only how each connection looks: how many packets and bytes it sent, "
        f"how long it lasted, what share came from the sender, two network-distance numbers, and "
        f"its protocol. We did NOT tell it which ones were attacks. It made one tight group of "
        f"ICMP pings (a ping is a tiny 'are you there?' network message) with {blob_size:,} "
        f"connections (a typical one is {blob_med_pkts} packet / {blob_med_bytes:,} bytes). This "
        f"group is supposed to be 'the botnet' (a set of hijacked computers run by an attacker) — "
        f"but it holds {bot_in_blob:,} attack connections mixed in with {normal_in_blob:,} normal, "
        f"safe ones (all from computer 147.32.84.164) and {bg_in_blob:,} background ones. So only "
        f"{purity:.0%} of the group is really attack traffic. The attack pings are blended in with "
        f"harmless pings, not off in their own group: looking at one connection at a time, you "
        f"can't tell them apart, and they even go to the same place ({_VICTIM}) as the safe "
        f"computer does. The other background traffic (web and other connections) split off into "
        f"the remaining groups."
    )

    return Analysis(
        technique="cluster",
        title="One connection alone never gives the botnet away",
        finding=finding,
        fit="strong",
        storage=[summary_path, pts_path],
        spec=spec_path,
        metrics=[
            Metric("Connections in the ICMP ping group", f"{blob_size:,}"),
            Metric("Share of that group that is really attack", f"{purity:.0%}"),
            Metric("Safe connections mixed into it", f"{normal_in_blob:,}"),
        ],
        params={
            "algo": "KMeans",
            "k": 7,
            "random_state": 0,
            "features": [
                "log10(TotPkts+1)", "log10(TotBytes+1)", "log10(Dur+1e-3)",
                "SrcPkts/TotPkts", "sTtl", "sHops", "proto_udp", "proto_tcp", "proto_icmp",
            ],
            "label_used": False,
            "dstaddr_used": False,
            "scatter_sample": "stratified (Botnet<=500, Normal<=400, Background<=500), jittered",
        },
        row_counts={
            "total_flows": int(len(df)),
            "botnet_cluster_size": blob_size,
            "scatter_points": int(len(pts)),
        },
        data_quality_note=(
            "A few connections are huge (up to 4.3 MB) while most are tiny, so we squish the "
            "byte and packet numbers onto a log scale to keep them readable. 'Background' is "
            "just a leftover bin for connections nobody labeled, so saying how 'pure' a group is "
            "against it doesn't really mean anything. In the dot chart we kept a fair number of "
            "each group (not the real proportions) so the small groups can still be seen inside "
            "the big clump."
        ),
    )


def _timeseries(df: pd.DataFrame) -> Analysis:
    nbins = int(df["bin"].max()) + 1
    hosts = _INFECTED + [_BENIGN_HOST]
    rows = []
    for h in hosts:
        s = (
            df[df["SrcAddr"] == h]
            .groupby("bin")
            .size()
            .reindex(range(nbins), fill_value=0)
        )
        role = "infected" if h in _INFECTED else "benign baseline"
        for b, c in s.items():
            rows.append(
                {
                    "host": h,
                    "role": role,
                    "minute": round(b * _BIN_SECONDS / 60.0, 2),
                    "flows": int(c),
                }
            )
    series = pd.DataFrame(rows)
    series_path = artifacts.write_table(f"{DATASET_ID}.timeseries.perhost", series)
    json_path = artifacts.write_json(
        f"{DATASET_ID}.timeseries.perhost", series.to_dict(orient="records")
    )

    # headline numbers
    peak_host = series.loc[series["flows"].idxmax()]
    peak = int(peak_host["flows"])
    peak_host_id = str(peak_host["host"])
    peak_minute = float(peak_host["minute"])
    # pre-burst activity for infected hosts (first 13 min)
    pre = series[(series["role"] == "infected") & (series["minute"] < 13.0)]["flows"]
    pre_max = int(pre.max())
    benign_med = int(series[series["role"] == "benign baseline"]["flows"].median())
    mirror_peak = int(series[series["host"] == _INFECTED[1]]["flows"].max())

    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": {
            "text": "The hijacked computers go quiet, then erupt all at once",
            "subtitle": f"Connections every {_BIN_SECONDS} seconds, per computer. Two hijacked "
            f"computers blow up after about 13 minutes; a safe computer stays flat the whole time.",
        },
        "width": "container",
        "height": 360,
        "data": {"values": series.to_dict(orient="records")},
        "mark": {"type": "line", "point": True, "interpolate": "monotone"},
        "encoding": {
            "x": {
                "field": "minute",
                "type": "quantitative",
                "title": "Minutes into capture",
            },
            "y": {
                "field": "flows",
                "type": "quantitative",
                "title": f"Flows per {_BIN_SECONDS}s bin",
            },
            "color": {
                "field": "host",
                "type": "nominal",
                "title": "Source host",
                "scale": {
                    "domain": [_INFECTED[0], _INFECTED[1], _BENIGN_HOST],
                    "range": [MALICIOUS, SUSPICIOUS, BENIGN],
                },
            },
            "tooltip": [
                {"field": "host", "type": "nominal", "title": "Host"},
                {"field": "role", "type": "nominal", "title": "Role"},
                {"field": "minute", "type": "quantitative", "title": "Minute"},
                {"field": "flows", "type": "quantitative", "title": "Flows"},
            ],
        },
    }
    spec_path = artifacts.write_spec(f"{DATASET_ID}.timeseries.burst", spec)

    finding = (
        f"Instead of looking at one connection at a time, we count how many connections each "
        f"computer makes every {_BIN_SECONDS} seconds. That shows what the one-at-a-time view "
        f"misses: the two hijacked computers (147.32.84.165, .191) stay almost silent for the "
        f"first ~13 minutes (no more than {pre_max} connections per {_BIN_SECONDS} seconds), then "
        f"blow up together at the same moment — computer {peak_host_id} jumps to {peak:,} "
        f"connections in a single {_BIN_SECONDS}-second window (around minute {peak_minute:.0f}), "
        f"and .191 does almost the same thing ({mirror_peak:,} in one window). The safe computer "
        f"we compare against, 147.32.84.138, stays flat the whole time (about {benign_med} per "
        f"window). The attack is a sudden jump from one source near the end of the recording — a "
        f"flip from quiet to loud, not a slow steady trickle. The giveaway is how many connections "
        f"one computer makes in a short window, not what any single connection looks like."
    )

    return Analysis(
        technique="timeseries",
        title="The attack is a sudden burst from the hijacked computers, all at once",
        finding=finding,
        fit="strong",
        storage=[series_path, json_path],
        spec=spec_path,
        metrics=[
            Metric("Most connections in 30s (hijacked computer)", f"{peak:,}"),
            Metric("Rate before the burst (first ~13 min)", f"≤{pre_max}/bin"),
            Metric("Safe computer's steady rate", f"~{benign_med}/bin"),
        ],
        params={
            "bin_seconds": _BIN_SECONDS,
            "infected_hosts": _INFECTED,
            "benign_host": _BENIGN_HOST,
            "n_bins": nbins,
        },
        row_counts={"series_points": int(len(series)), "n_bins": nbins},
        data_quality_note=(
            "The labels are a rough guide, not a perfect answer: the researchers marked 3 whole "
            "computers as infected and called everything from them 'attack,' rather than checking "
            "each message one by one. This loud burst is just how this one recording's attack "
            "behaves; a quieter attack that sends a little traffic over and over would look "
            "totally different (this recording has only about 6 of those quiet kind)."
        ),
    )


def build(m: artifacts.Manifest) -> Dataset:
    df = _prepare(load())

    cluster = _cluster(df)
    timeseries = _timeseries(df)

    cluster_purity = next(
        x.value for x in cluster.metrics if x.label == "Share of that group that is really attack"
    )

    ds = Dataset(
        id=DATASET_ID,
        display_name="CTU-13 Botnet NetFlow — Scenario 11 (Botnet-52)",
        doc_category="network-flow",
        what_it_is=(
            "One ~15-minute recording of network traffic (~107k connections). Each row sums up "
            "one connection between two computers, and comes with a label saying whether it is "
            "attack (Botnet), normal, or background (unlabeled) traffic."
        ),
        source={
            "name": "CTU-13 / Stratosphere IPS (CTU University) — capture Botnet-52",
            "url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/",
            "license": "Public research dataset (Stratosphere IPS); free for research use.",
        },
        isolated_insight=(
            "In this recording you cannot spot the attack by looking at any single connection. "
            "Every attack connection is just one ~1066-byte ping (one packet) that looks exactly "
            "like an ordinary harmless ping. It even goes to the same place (147.32.96.69) as "
            "2,089 perfectly normal connections from a safe computer. When we let the computer "
            f"group the traffic on its own, it dumps the attack into the same ping group as that "
            f"safe traffic ({cluster_purity} of the group is really attack). The only way to see "
            "the attack is to step back and watch the bigger pattern: two computers inside the "
            "network stay almost silent for ~13 minutes, then all at once fire off thousands of "
            "connections in a single 30s window, all aimed at one victim. The giveaway is how many "
            "connections one computer makes in a short stretch of time — not what any single "
            "connection looks like, and not where it is going."
        ),
        solution_idea=(
            "Build an alarm that watches each computer's burst of connections instead of judging "
            "one connection at a time. Keep counting how many connections each computer sends to "
            "each destination every 30s, and raise an alarm when one computer's count suddenly "
            "jumps far above its own usual level (say >5x its recent normal) while those "
            "connections are mostly tiny one-packet messages. This catches a flood from a hijacked "
            "computer inside the network — the kind that rules based on one connection's looks, or "
            "on whether the destination is 'known bad,' simply cannot see. And because each "
            "computer is compared to its own normal, you don't need to pick one cutoff for "
            "everyone."
        ),
        honesty_notes=(
            "This is just one 15-min recording from 2011. This loud-flood behavior is how this one "
            "case acts; it does NOT tell you about quieter attacks that send a little traffic over "
            "and over. The labels are a rough guide, not a perfect answer: the researchers marked 3 "
            "whole computers as infected and called everything from them 'attack' rather than "
            "checking each message, and 'background' is just a leftover bin nobody labeled, so "
            "measuring how 'pure' a group is against it doesn't mean much. We left out building a "
            "simple formula that learns to guess attack-or-not (regression), on purpose: the answer "
            "here comes down to two obvious things (it's a ping AND it's headed to the victim), so "
            "that formula would just be that rule written out — it would look impressive but prove "
            "nothing. We also skipped squeezing the columns down to a few (because there isn't much "
            "to squeeze), rolling the dice many times to see a range of outcomes (nothing random to "
            "model), splitting by sign-up groups (no such groups in a 15-min window), and reading "
            "text for mood (there's no written text here) — each would have been a forced fit."
        ),
        analyses=[cluster, timeseries],
    )

    m.add(ds)
    return ds
