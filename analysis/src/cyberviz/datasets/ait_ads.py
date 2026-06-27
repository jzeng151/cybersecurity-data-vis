"""AIT-ADS — AIT Alert Data Set (Wazuh + AMiner IDS streams), analyzed in isolation.

One row = one IDS alert. 2.66M alerts are streamed once from the 96MB zip (never extracted),
8 scenarios x 2 engines, with labels.csv giving the per-scenario kill-chain attack windows.

Three techniques, each its own Analysis:
  - cluster (strong):   2.66M raw alerts collapse to ~800 dedup (scenario,engine,signature,
                        location) groups; KMeans archetypes over per-group features.
  - timeseries (strong): hourly volume for one scenario, STL daily decomposition, attack-window
                        overlay; quantifies the one catastrophic reconnaissance volume spike.
  - cohort (moderate):  the 86 AMiner source IPs x kill-chain stage; where novelty actually fires.

Everything is deterministic (random_state=0, no random sampling). The streaming aggregates are
cached to data/interim/ so re-runs reproduce identical artifacts quickly.
"""
from __future__ import annotations

import json
import zipfile
from collections import defaultdict
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler
from statsmodels.tsa.seasonal import STL

from .. import artifacts, colors, paths
from ..acquire import ait_ads

HOUR = 3600
# Identical 10-stage kill-chain injected into every scenario, in chronological order.
STAGES = [
    "network_scans", "service_scans", "dirb", "wpscan", "webshell",
    "cracking", "reverse_shell", "privilege_escalation", "service_stop", "dnsteal",
]
TS_SCENARIO = "wilson"  # strongest daily seasonality + the clearest single attack-burst spike

_G_CACHE = paths.DATA_INTERIM / "ait_ads_groups.parquet"
_H_CACHE = paths.DATA_INTERIM / "ait_ads_hourly.parquet"
_C_CACHE = paths.DATA_INTERIM / "ait_ads_cohort.parquet"
_I_CACHE = paths.DATA_INTERIM / "ait_ads_ip.parquet"
_L_CACHE = paths.DATA_INTERIM / "ait_ads_wazuh_level.parquet"


def _iso(s: str) -> float:
    return datetime.fromisoformat(s).timestamp()


def _utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _stream() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """One bounded-memory pass over the zip -> (groups, hourly, cohort_stage, ip, wazuh_level) frames."""
    if all(p.exists() for p in (_G_CACHE, _H_CACHE, _C_CACHE, _I_CACHE, _L_CACHE)):
        return (pd.read_parquet(_G_CACHE), pd.read_parquet(_H_CACHE),
                pd.read_parquet(_C_CACHE), pd.read_parquet(_I_CACHE),
                pd.read_parquet(_L_CACHE))

    files = ait_ads.acquire()
    lab = pd.read_csv(files["labels"])
    windows: dict[str, list[tuple[float, float, str]]] = defaultdict(list)
    for r in lab.itertuples(index=False):
        windows[r.scenario].append((float(r.start), float(r.end), r.attack))

    def stage_of(scen: str, ts: float) -> str | None:
        for s, e, st in windows[scen]:
            if s <= ts <= e:
                return st
        return None

    groups: dict[tuple, dict] = {}
    hourly: dict[tuple, dict] = {}
    am_stage: dict[tuple, int] = defaultdict(int)          # (scen,ip,stage)->count (non-train, in-window)
    ip_acc: dict[tuple, dict] = {}                         # (scen,ip)->{total_nt,train,inwin,first_ts,first_stage}
    wz_level: dict[int, int] = defaultdict(int)            # wazuh rule.level -> alert count (severity histogram)

    with zipfile.ZipFile(files["zip"]) as z:
        for scen in ait_ads.SCENARIOS:
            for eng in ait_ads.IDS:
                with z.open(f"{scen}_{eng}.json") as fh:
                    for raw in fh:
                        o = json.loads(raw)
                        if eng == "wazuh":
                            ts = _iso(o["@timestamp"])
                            rule = o.get("rule", {})
                            sig = rule.get("description", "?")
                            loc = o.get("location", "?")
                            lvl = float(rule.get("level", 0) or 0)
                            wz_level[int(lvl)] += 1
                        else:
                            ld = o.get("LogData", {})
                            tss = ld.get("Timestamps") or ld.get("DetectionTimestamp") or [0.0]
                            ts = float(tss[0]) if tss else 0.0
                            ac = o.get("AnalysisComponent", {})
                            sig = ac.get("AnalysisComponentType", "?")
                            lr = ld.get("LogResources") or ["?"]
                            loc = lr[0] if lr else "?"
                            lvl = 0.0
                            training = bool(ac.get("TrainingMode", False))
                            ip = str(o.get("AMiner", {}).get("ID", "?"))
                        st = stage_of(scen, ts)
                        inwin = st is not None

                        gk = (scen, eng, sig, loc)
                        g = groups.get(gk)
                        if g is None:
                            g = {"count": 0, "level_sum": 0.0, "attack": 0, "hh": [0] * 24}
                            groups[gk] = g
                        g["count"] += 1
                        g["level_sum"] += lvl
                        if inwin:
                            g["attack"] += 1
                        g["hh"][int((ts // HOUR) % 24)] += 1

                        hk = (scen, eng, int(ts // HOUR) * HOUR)
                        h = hourly.get(hk)
                        if h is None:
                            h = {"count": 0, "attack": 0}
                            hourly[hk] = h
                        h["count"] += 1
                        if inwin:
                            h["attack"] += 1

                        if eng == "aminer":
                            ck = (scen, ip)
                            a = ip_acc.get(ck)
                            if a is None:
                                a = {"total_nt": 0, "train": 0, "inwin": 0,
                                     "first_ts": float("inf"), "first_stage": None}
                                ip_acc[ck] = a
                            if training:
                                a["train"] += 1
                            else:
                                a["total_nt"] += 1
                                if ts < a["first_ts"]:
                                    a["first_ts"] = ts
                                    a["first_stage"] = st
                                if inwin:
                                    a["inwin"] += 1
                                    am_stage[(scen, ip, st)] += 1

    gdf = pd.DataFrame([
        {"scenario": s, "engine": e, "signature": sig, "location": loc,
         "count": v["count"], "level_sum": v["level_sum"], "attack": v["attack"],
         **{f"h{i}": v["hh"][i] for i in range(24)}}
        for (s, e, sig, loc), v in groups.items()
    ])
    hdf = pd.DataFrame([
        {"scenario": s, "engine": e, "hour": h, "count": v["count"], "attack": v["attack"]}
        for (s, e, h), v in hourly.items()
    ]).sort_values(["scenario", "engine", "hour"]).reset_index(drop=True)
    cdf = pd.DataFrame([
        {"scenario": s, "ip": ip, "stage": st, "count": c}
        for (s, ip, st), c in am_stage.items()
    ])
    idf = pd.DataFrame([
        {"scenario": s, "ip": ip, "total_nt": a["total_nt"], "train": a["train"],
         "inwin": a["inwin"], "first_stage": a["first_stage"]}
        for (s, ip), a in ip_acc.items()
    ])
    ldf = pd.DataFrame(
        [{"level": lv, "count": c} for lv, c in sorted(wz_level.items())]
    ).astype({"level": int, "count": int})

    paths.ensure_dirs()
    gdf.to_parquet(_G_CACHE, index=False)
    hdf.to_parquet(_H_CACHE, index=False)
    cdf.to_parquet(_C_CACHE, index=False)
    idf.to_parquet(_I_CACHE, index=False)
    ldf.to_parquet(_L_CACHE, index=False)
    return gdf, hdf, cdf, idf, ldf


def _severity(attack_fraction: float) -> str:
    if attack_fraction >= 0.5:
        return "malicious"
    if attack_fraction > 0.0:
        return "suspicious"
    return "benign"


# --------------------------------------------------------------------------- cluster
def _cluster(gdf: pd.DataFrame) -> artifacts.Analysis:
    g = gdf.copy()
    total = int(g["count"].sum())
    g["mean_level"] = g["level_sum"] / g["count"]
    g["attack_fraction"] = g["attack"] / g["count"]
    g["severity"] = g["attack_fraction"].map(_severity)
    hh = g[[f"h{i}" for i in range(24)]].to_numpy(dtype=float)
    hh_norm = hh / g["count"].to_numpy()[:, None]          # time-of-day profile per group
    # Unsupervised features only: attack_fraction is label-derived and is deliberately EXCLUDED so
    # the clustering is genuinely unsupervised; it re-enters only as the scatter color overlay below.
    feat = np.column_stack([
        np.log1p(g["count"].to_numpy()),
        g["mean_level"].to_numpy(),
        (g["engine"] == "aminer").astype(float).to_numpy(),
        hh_norm,
    ])
    Xs = StandardScaler().fit_transform(feat)

    best_k, best_sil, best_labels = None, -1.0, None
    for k in range(6, 11):
        km = KMeans(n_clusters=k, random_state=0, n_init=10).fit(Xs)
        sil = float(silhouette_score(Xs, km.labels_))
        if sil > best_sil:
            best_k, best_sil, best_labels = k, sil, km.labels_
    g["cluster"] = best_labels
    pca = PCA(n_components=2, random_state=0).fit(Xs)
    co = pca.transform(Xs)
    g["pc1"], g["pc2"] = co[:, 0], co[:, 1]
    var_ratio = pca.explained_variance_ratio_

    sig_vol = g.groupby("signature")["count"].sum().sort_values(ascending=False)
    dom_sig, dom_share = str(sig_vol.index[0]), float(sig_vol.iloc[0]) / total
    top3_share = float(sig_vol.iloc[:3].sum()) / total

    archetypes = []
    for c in sorted(g["cluster"].unique()):
        sub = g[g["cluster"] == c]
        dom = sub.loc[sub["count"].idxmax()]
        archetypes.append({
            "cluster": int(c), "n_groups": int(len(sub)),
            "total_alerts": int(sub["count"].sum()),
            "engine": str(sub["engine"].mode().iloc[0]),
            "dominant_signature": str(dom["signature"]),
            "mean_level": round(float(sub["mean_level"].mean()), 2),
            "mean_attack_fraction": round(float(sub["attack_fraction"].mean()), 3),
        })
    archetypes.sort(key=lambda a: a["total_alerts"], reverse=True)
    af_vals = [a["mean_attack_fraction"] for a in archetypes]
    af_lo, af_hi = min(af_vals), max(af_vals)

    summary_id = artifacts.write_json("ait-ads.cluster.summary", {
        "total_alerts": total,
        "n_groups": int(len(g)),
        "reduction_pct": round((1 - len(g) / total) * 100, 4),
        "k": best_k, "silhouette": round(best_sil, 3),
        "pca_explained_2d": round(float(var_ratio[:2].sum()), 3),
        "dominant_signature": dom_sig,
        "dominant_signature_share": round(dom_share, 4),
        "top3_signature_share": round(top3_share, 4),
        "engine_groups": {k: int(v) for k, v in g["engine"].value_counts().items()},
        "archetypes": archetypes,
    })
    table_id = artifacts.write_table("ait-ads.cluster.groups", g[[
        "scenario", "engine", "signature", "location", "count",
        "mean_level", "attack_fraction", "severity", "cluster", "pc1", "pc2",
    ]])

    points = [{
        "pc1": round(float(r.pc1), 3), "pc2": round(float(r.pc2), 3),
        "engine": str(r.engine), "severity": str(r.severity),
        "log_count": round(float(np.log1p(r.count)), 2), "count": int(r.count),
        "cluster": int(r.cluster), "signature": str(r.signature)[:60],
    } for r in g.itertuples(index=False)]                  # all 817 groups, well under 1500

    spec_id = artifacts.write_spec("ait-ads.cluster.scatter", {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "width": "container", "height": 460,
        "title": "Repeated alert-groups laid out by how they behave (many columns squeezed to two), colored by attack-time overlap",
        "data": {"values": points},
        "mark": {"type": "point", "filled": True, "opacity": 0.7},
        "encoding": {
            "x": {"field": "pc1", "type": "quantitative", "title": "behavioral PC1"},
            "y": {"field": "pc2", "type": "quantitative", "title": "behavioral PC2"},
            "size": {"field": "log_count", "type": "quantitative", "title": "log(alerts in group)",
                     "scale": {"range": [15, 600]}},
            "shape": {"field": "engine", "type": "nominal", "title": "engine"},
            "color": {
                "field": "severity", "type": "nominal", "title": "attack-window linkage",
                "scale": {"domain": ["benign", "suspicious", "malicious"],
                          "range": [colors.BENIGN, colors.SUSPICIOUS, colors.MALICIOUS]},
            },
            "tooltip": [{"field": "signature"}, {"field": "engine"}, {"field": "count"},
                        {"field": "cluster"}, {"field": "severity"}],
        },
    })

    finding = (
        f"We read all {total:,} alerts (warnings the security tools raised) one at a time. Many are "
        f"exact repeats, so we group together alerts that share the same scenario, engine (the tool "
        f"that raised them), rule name, and location. That squeezes them down to just {len(g):,} "
        f"repeating groups — a {(1 - len(g)/total)*100:.2f}% drop. The alerts are very lopsided — a few "
        f"things hog most of the total: one rule, “{dom_sig}”, is {dom_share*100:.1f}% of all alerts, "
        f"and the top 3 rules are {top3_share*100:.1f}%. We then sort the groups into families with "
        f"KMeans (a tool that puts similar groups together; {best_k} families, and how cleanly they "
        f"separate is {best_sil:.2f}). It only looks at plain facts about each group [how many alerts "
        f"it holds, the average warning level, which engine, and the shape of the day across 24 hours] "
        f"— it never sees which alerts fell inside an attack, so the grouping is honest. The groups "
        f"split mostly by how big they are and what time of day they happen: the few giant Wazuh "
        f"“{dom_sig}” groups (each carrying hundreds of thousands of alerts) sit in their own dense "
        f"corners, away from the broad everyday “IDS event” baseline and from a long tail of small "
        f"groups from both engines (hundreds of alerts each). Only after grouping do we color them by "
        f"how much they overlap the attack times — that is a separate check, not something baked in: "
        f"the average overlap per family still ranges from {af_lo:.2f}–{af_hi:.2f}, so the big scan "
        f"families line up with the attack times even though the attack labels never went into the "
        f"grouping. The rare, interesting groups are a tiny low-volume tail, not high-danger ones."
    )
    return artifacts.Analysis(
        technique="cluster", fit="strong",
        title=f"{total:,} alerts → {len(g)} repeat groups → {best_k} families",
        finding=finding,
        storage=[summary_id, table_id], spec=spec_id,
        metrics=[
            artifacts.Metric("All alerts", f"{total:,}"),
            artifacts.Metric("Repeat groups", f"{len(g)}"),
            artifacts.Metric("Top rule's share", f"{dom_share*100:.0f}%"),
            artifacts.Metric("Alert families", f"{best_k}"),
        ],
        params={"dedup_key": ["scenario", "engine", "signature", "location"],
                "algo": "KMeans", "k_search": [6, 10], "k_selected": best_k,
                "features": ["log_count", "mean_level", "engine", "hour_profile_24"],
                "pca_for_display_only": True},
        row_counts={"input_alerts": total, "groups": int(len(g))},
        data_quality_note=(
            "The color shows how much each group overlaps the attack times — the share of its alerts "
            "that fall inside an attack window listed in labels.csv. This is a rough guide, not a "
            "perfect answer, because the window is just a time span for the whole scenario, not a "
            "verdict on each alert: a harmless alert that happens during a window still gets counted."),
        fit_warning=(
            f"The groups separate only so-so ({best_sil:.2f}), and the 2-column picture (made by "
            f"squeezing many columns down to the two that hold the most pattern) keeps only "
            f"{var_ratio[:2].sum()*100:.0f}% of the pattern. The split is driven mostly by a few rules "
            f"being huge and lopsided, not by neat, many-sided families."),
    )


# --------------------------------------------------------------------------- timeseries
def _robust_z(x: np.ndarray) -> np.ndarray:
    med = np.median(x)
    mad = np.median(np.abs(x - med)) or 1e-9
    return 0.6745 * (x - med) / mad


def _timeseries(hdf: pd.DataFrame) -> artifacts.Analysis:
    files = ait_ads.acquire()
    lab = pd.read_csv(files["labels"])
    wins = lab[lab.scenario == TS_SCENARIO][["attack", "start", "end"]]

    sub = hdf[hdf.scenario == TS_SCENARIO]
    # total series on a gap-free hourly grid
    tot = sub.groupby("hour", as_index=False).agg(count=("count", "sum"), attack=("attack", "sum"))
    full = np.arange(int(tot.hour.min()), int(tot.hour.max()) + HOUR, HOUR)
    s = tot.set_index("hour").reindex(full, fill_value=0)
    count = s["count"].to_numpy(dtype=float)
    attack = s["attack"].to_numpy() > 0

    y = np.log1p(count)
    stl = STL(y, period=24, robust=True).fit()
    seas_strength = max(0.0, 1.0 - np.var(stl.resid) / np.var(stl.seasonal + stl.resid))
    z = _robust_z(stl.resid)
    anomaly = np.abs(z) > 3.0
    tp = int((anomaly & attack).sum()); fp = int((anomaly & ~attack).sum()); fn = int((~anomaly & attack).sum())
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    median_hr = float(np.median(count[count > 0])) if (count > 0).any() else 0.0
    peak = int(count.max())
    spike_ratio = peak / median_hr if median_hr else 0.0

    # per-engine hourly counts for the area chart (reindexed onto the same grid)
    eng_rows = []
    for eng in ait_ads.IDS:
        es = sub[sub.engine == eng].set_index("hour")["count"].reindex(full, fill_value=0)
        for hh, cc in zip(full, es.to_numpy()):
            eng_rows.append({"t": _utc(float(hh)), "engine": eng,
                             "count": int(cc), "log_count": round(float(np.log1p(cc)), 3)})
    anomaly_rows = [{"t": _utc(float(full[i])), "log_count": round(float(y[i]), 3),
                     "count": int(count[i]), "z": round(float(z[i]), 2)}
                    for i in range(len(full)) if anomaly[i]]
    window_rows = [{"start": _utc(float(r.start)), "end": _utc(float(r.end)), "stage": str(r.attack)}
                   for r in wins.itertuples(index=False)]

    series_id = artifacts.write_json("ait-ads.timeseries.hourly", {
        "scenario": TS_SCENARIO,
        "method": {"decomp": "STL", "period_h": 24, "anomaly": "robust residual |z|>3"},
        "seasonal_strength": round(float(seas_strength), 3),
        "seasonal_amplitude": round(float(stl.seasonal.std()), 3),
        "median_hourly": round(median_hr, 1), "peak_hourly": peak,
        "peak_over_median": round(spike_ratio, 1),
        "hours": int(len(full)), "attack_hours": int(attack.sum()),
        "anomaly_hours": int(anomaly.sum()),
        "recall": round(recall, 3), "precision": round(precision, 3),
        "per_engine": eng_rows, "anomalies": anomaly_rows, "windows": window_rows,
    })

    spec_id = artifacts.write_spec("ait-ads.timeseries.hourly", {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "width": "container", "height": 320,
        "title": f"Alerts per hour with attack times shaded ({TS_SCENARIO}) — counts shown on a log scale so the giant spike doesn't squash the rest",
        "layer": [
            {"data": {"values": window_rows},
             "mark": {"type": "rect", "color": colors.MALICIOUS, "opacity": 0.18},
             "encoding": {
                 "x": {"field": "start", "type": "temporal", "title": "time (UTC)"},
                 "x2": {"field": "end"},
                 "tooltip": [{"field": "stage", "title": "attack stage"}]}},
            {"data": {"values": eng_rows},
             "mark": {"type": "area", "opacity": 0.85},
             "encoding": {
                 "x": {"field": "t", "type": "temporal", "title": "time (UTC)"},
                 "y": {"field": "log_count", "type": "quantitative", "title": "log(1 + alerts/hour)",
                       "stack": True},
                 "color": {"field": "engine", "type": "nominal", "title": "engine",
                           "scale": {"domain": ["wazuh", "aminer"],
                                     "range": [colors.NEUTRAL, colors.ACCENT]}},
                 "tooltip": [{"field": "t"}, {"field": "engine"}, {"field": "count"}]}},
            {"data": {"values": anomaly_rows},
             "mark": {"type": "point", "filled": True, "size": 60, "color": colors.SUSPICIOUS},
             "encoding": {
                 "x": {"field": "t", "type": "temporal"},
                 "y": {"field": "log_count", "type": "quantitative"},
                 "tooltip": [{"field": "t"}, {"field": "count"}, {"field": "z"}]}},
        ],
    })

    finding = (
        f"In scenario {TS_SCENARIO}, the number of alerts per hour follows a strong daily rhythm — the "
        f"regular ups and downs of a workday (we split the hourly counts into that daily rhythm and "
        f"leftover bumps; the daily-rhythm strength is {seas_strength:.2f}). On a normal day there are "
        f"about {median_hr:.0f} alerts an hour. The attacks do not last for days — they add up to only "
        f"a couple of hours — but they make one enormous scanning spike: a single hour reaches {peak:,} "
        f"alerts, about {spike_ratio:.0f}x a normal hour, almost all of them low-danger “Web server 400 "
        f"error” alerts from automated tools poking at web pages. If we flag any hour that sticks out "
        f"far from the daily rhythm (more than 3 steps away from normal), we easily catch that giant "
        f"spike. But across all {int(attack.sum())} attack-hours we only catch {recall*100:.0f}% (the "
        f"share of real attack-hours we flagged), and only {precision*100:.0f}% of our flags are real "
        f"attacks — the smaller attack-hours hide inside the normal daily ups and downs, and the regular "
        f"daily peaks set off false alarms. So by volume the attack is one deafening burst plus a quiet "
        f"tail you cannot tell apart from a normal day."
    )
    return artifacts.Analysis(
        technique="timeseries", fit="strong",
        title=f"A normal daily rhythm vs one {peak:,}-alert scanning spike ({TS_SCENARIO})",
        finding=finding,
        storage=[series_id], spec=spec_id,
        metrics=[
            artifacts.Metric("Daily-rhythm strength", f"{seas_strength:.2f}"),
            artifacts.Metric("Peak attack hour", f"{peak:,}"),
            artifacts.Metric("× a normal hour", f"{spike_ratio:.0f}×"),
            artifacts.Metric("Attack-hours caught", f"{recall*100:.0f}%"),
        ],
        params={"scenario": TS_SCENARIO, "decomp": "STL", "period_h": 24, "z_thresh": 3.0},
        row_counts={"hours": int(len(full)), "attack_hours": int(attack.sum()),
                    "anomaly_hours": int(anomaly.sum())},
        data_quality_note=(
            "The attack windows in labels.csv are rough time spans for the whole scenario (middle "
            "length ~0.7 min, longest 120 min), not a yes/no verdict on each alert. We show one typical "
            "scenario here; the daily rhythm and the one big spike show up in the other scenarios too "
            "(daily-rhythm strength 0.69-0.86 in 6 of 8)."),
    )


# --------------------------------------------------------------------------- cohort
def _cohort(cdf: pd.DataFrame, idf: pd.DataFrame) -> artifacts.Analysis:
    n_ips = int(idf.groupby("ip").ngroups)
    ip_inwin = idf.groupby("ip")["inwin"].sum()
    ip_train = idf.groupby("ip")["train"].sum()
    ip_total_nt = idf.groupby("ip")["total_nt"].sum()
    n_firing = int((ip_inwin > 0).sum())
    n_train_only = int(((ip_total_nt == 0) & (ip_train > 0)).sum())

    stage_tot = cdf.groupby("stage")["count"].sum().reindex(STAGES, fill_value=0)
    total_events = int(stage_tot.sum())
    recon = int(stage_tot[["dirb", "wpscan"]].sum())
    post = int(stage_tot[["webshell", "cracking", "reverse_shell",
                          "privilege_escalation", "service_stop", "dnsteal"]].sum())
    denom = total_events or 1                              # zero-guard: empty slice can't divide-by-zero
    recon_share = recon / denom
    post_share = post / denom
    top5_share = float(ip_inwin.sort_values(ascending=False).iloc[:5].sum()) / denom

    # heatmap: IPs that fire >=1 in-window novelty, sorted by total in-window volume
    firing_ips = ip_inwin[ip_inwin > 0].sort_values(ascending=False)
    order = list(firing_ips.index)
    cd = cdf.groupby(["ip", "stage"], as_index=False)["count"].sum()
    cd = cd[cd.ip.isin(order)].reset_index(drop=True)
    cells = [{"ip": str(ip), "stage": str(st), "count": int(c),
              "log_count": round(float(np.log10(c + 1)), 3)}
             for ip, st, c in zip(cd["ip"], cd["stage"], cd["count"])]

    summary_id = artifacts.write_json("ait-ads.cohort.summary", {
        "n_ips": n_ips, "n_ips_firing_inwindow": n_firing, "n_ips_training_only": n_train_only,
        "total_inwindow_events": total_events,
        "recon_events": recon, "recon_share": round(recon_share, 4),
        "post_exploitation_events": post, "post_exploitation_share": round(post_share, 4),
        "top5_ip_share": round(top5_share, 4),
        "events_by_stage": {st: int(stage_tot[st]) for st in STAGES},
        "top_ips": [{"ip": str(ip), "inwindow": int(v)} for ip, v in firing_ips.iloc[:8].items()],
    })
    table_id = artifacts.write_table("ait-ads.cohort.ip_stage", cd.reset_index(drop=True))

    spec_id = artifacts.write_spec("ait-ads.cohort.heatmap", {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "width": "container", "height": max(240, 14 * len(order)),
        "title": "AMiner's new-thing alerts per machine IP and attack step (during attacks, warm-up excluded)",
        "data": {"values": cells},
        "mark": {"type": "rect"},
        "encoding": {
            "x": {"field": "stage", "type": "nominal", "title": "kill-chain stage",
                  "sort": STAGES, "axis": {"labelAngle": -40}},
            "y": {"field": "ip", "type": "nominal", "title": "AMiner source IP",
                  "sort": order},
            "color": {"field": "log_count", "type": "quantitative",
                      "title": "log10(novel events)",
                      "scale": {"range": ["#eef2f7", colors.ACCENT]}},
            "tooltip": [{"field": "ip"}, {"field": "stage"}, {"field": "count"}],
        },
    })

    finding = (
        f"We split the {n_ips} AMiner machine addresses (IPs — the only “which machine” clue in the "
        f"data, since Wazuh always reports the same name) into groups by where their “I've never seen "
        f"this before” alerts land along the attack's steps (the kill-chain: the ordered stages of an "
        f"attack). We skip the warm-up rows from when AMiner was still learning what normal looks like. "
        f"Two things stand out. First, these new-thing alerts pile up at certain steps: of "
        f"{total_events:,} new-thing alerts inside the attack windows, {recon_share*100:.0f}% land in "
        f"just the two web-scanning steps (dirb + wpscan), while the whole later, more dangerous part — "
        f"webshell, cracking, reverse_shell, privilege_escalation, service_stop, dnsteal — adds up to "
        f"only {post} alerts ({post_share*100:.1f}%). Second, they pile up on a few machines: the top 5 "
        f"IPs make up {top5_share*100:.0f}% of all the in-window new-thing alerts. This corrects an "
        f"earlier guess that most IPs only fire during warm-up: really, {n_firing} of {n_ips} IPs fire "
        f"at least one new-thing alert during an attack, and only {n_train_only} fire only during "
        f"warm-up. The honest limit is coverage: AMiner shouts about scanning but barely notices the "
        f"dangerous later steps."
    )
    return artifacts.Analysis(
        technique="cohort", fit="moderate",
        title=f"AMiner spots scanning ({recon_share*100:.0f}%) but misses the later attack steps",
        finding=finding,
        storage=[summary_id, table_id], spec=spec_id,
        metrics=[
            artifacts.Metric("AMiner machine IPs", f"{n_ips}"),
            artifacts.Metric("IPs firing during attacks", f"{n_firing}"),
            artifacts.Metric("Scanning-step share", f"{recon_share*100:.0f}%"),
            artifacts.Metric("Top-5 IP share", f"{top5_share*100:.0f}%"),
        ],
        params={"entity": "AMiner.ID", "exclude_training_mode": True,
                "cohort_key": "kill-chain stage", "metric": "in-window novel-event count"},
        row_counts={"ips": n_ips, "ips_firing": n_firing, "inwindow_events": total_events},
        data_quality_note=(
            "AMiner is only ~2.1% of all the rows, and the Wazuh data never says which machine an alert "
            "came from, so this “which machine” view is stuck at 86 IPs over a short stretch (only the "
            "few hours of each attack). Which step an alert belongs to comes from the labels.csv time "
            "windows."),
        fit_warning=(
            "So-so fit: the “which machine” angle is real but thin. The point here is how much each "
            "attack step gets noticed, not learning each machine's normal behavior — there is too "
            "little history for that."),
    )


def build(m: artifacts.Manifest) -> artifacts.Dataset:
    gdf, hdf, cdf, idf, ldf = _stream()

    cluster = _cluster(gdf)
    timeseries = _timeseries(hdf)
    cohort = _cohort(cdf, idf)

    # Wazuh severity histogram (computed in the stream pass) for the isolated insight / honesty notes.
    wz_total = int(ldf["count"].sum())
    pct_3_6 = ldf.loc[ldf.level.between(3, 6), "count"].sum() / wz_total * 100 if wz_total else 0.0
    pct_ge10 = ldf.loc[ldf.level >= 10, "count"].sum() / wz_total * 100 if wz_total else 0.0
    wz = gdf[gdf.engine == "wazuh"]
    sig_vol = wz.groupby("signature")["count"].sum().sort_values(ascending=False)
    dom_sig = str(sig_vol.index[0])
    dom_share = float(sig_vol.iloc[0]) / int(gdf["count"].sum()) * 100
    dom_rows = wz[wz.signature == dom_sig]
    dom_level = int(round(float(dom_rows["level_sum"].sum() / dom_rows["count"].sum())))

    ds = artifacts.Dataset(
        id="ait-ads",
        display_name="AIT-ADS — AIT Alert Data Set",
        doc_category="host-log",
        what_it_is=(
            "2.66M time-stamped alerts (warnings raised by intrusion-detection tools — software that "
            "watches for attacks) read straight from a 96MB zip file. They come from 8 practice setups "
            "(\"scenarios\") run through 2 different tools (engines): Wazuh, which matches known attack "
            "patterns, and AMiner, which flags anything it has never seen before. One row is one alert. "
            "A file called labels.csv lists, for each scenario, the time windows of a planted 10-step "
            "attack (the kill-chain)."),
        source={
            "name": "AIT Alert Data Set (AIT-ADS), 2023",
            "url": "https://zenodo.org/records/8263181",
            "license": "CC-BY-4.0",
        },
        isolated_insight=(
            "In this practice setup, how loud and how serious the alerts are has almost nothing to do "
            "with how far the attack has gotten. About 66% of all 2.66M alerts go off inside the short "
            "attack windows (only a couple of hours per scenario), but that pile is really one big burst "
            "of automated web-scanning: a single hour can carry ~450x a normal hour's count, "
            f"{dom_share:.0f}% of all alerts are one low-danger rule ('{dom_sig}', warning level {dom_level}), "
            f"and the danger level never climbs — {pct_3_6:.1f}% of Wazuh alerts stay at level 3-6 and only "
            f"{pct_ge10:.1f}% reach level 10 or higher, "
            "even while the attacker is grabbing extra powers and stealing data. The detecting also "
            "clumps on the noisy scanning steps: AMiner's \"never seen this before\" detectors fire 97% "
            "in the dirb+wpscan scanning steps and under 1% across the whole later, more dangerous part. "
            "So the loud, huge, low-danger scanning is easy to catch but tells you nothing new, while "
            "the truly dangerous later steps are almost invisible to both tools — the pattern-matching "
            "tool never raises its danger level, and the new-thing tool sees nothing new."),
        solution_idea=(
            "Build a coverage checker for the attack steps: place every alert — each Wazuh pattern-match "
            "and each AMiner new-thing alert — onto the attack timeline, count how well each step gets "
            "noticed, then point out the blind spots, the later steps where neither the danger level nor "
            "the new-thing detector ever fires. Instead of rewarding the scan burst it already catches, a "
            "detection team gets a map of which attack steps it currently cannot see (webshell / "
            "reverse-shell / privilege escalation / data theft) and where to add more watching, such as "
            "logs of what programs run and who logs in. The warm-up (learning-mode) rows are left out of "
            "the comparison."),
        honesty_notes=(
            "The labels are rough time windows for the whole scenario, not a person's yes/no verdict on "
            "each alert — a harmless alert inside a window still gets counted — so a window is only a "
            "weak hint that something was an attack. About 66% of alerts fall inside one, which is why "
            "we do not try to fit a formula that predicts the label for each alert; it would not be "
            "fair, so we left it out. Fixes to the earlier design notes, checked against the full data "
            "on disk: (1) the attack windows are NOT '4-5 day bursts' — they are short (middle length "
            "~0.7 min, longest 120 min), adding up to ~1.4-3.5 hours per scenario, while "
            f"the alerts themselves span ~4-6 days; (2) warning level 3-6 is {pct_3_6:.1f}% of Wazuh rows, not ~99%; (3) most AMiner "
            "IPs (61 of 86) DO fire a new-thing alert during an attack — the notes guessed most fire "
            "only during warm-up; only 9 fire only during warm-up. The Wazuh data never says which "
            "machine an alert came from (the name is always the same), which is a built-in limit and "
            "keeps the \"which machine\" view stuck at AMiner's 86 IPs. Squeezing the columns down to "
            "two (PCA) is used only to draw the picture, not as a finding on its own. We skipped "
            "rolling-the-dice simulation, prediction formulas, and word/opinion analysis because they "
            "would be forced here: there is no random process to simulate, the labels are too rough for "
            "a prediction formula, and the log text is structured machine output, not anyone's opinion. "
            "This is a made-up practice setup with the same planted attack in every scenario, so the "
            "tidy daily rhythm and the \"danger and attack-progress are unlinked\" conclusion may not "
            "carry over to messier real-world data."),
        analyses=[cluster, timeseries, cohort],
    )
    m.add(ds)
    return ds
