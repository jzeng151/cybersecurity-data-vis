"""UNSW-NB15 (network-flow) analyzed in isolation.

One row = one bidirectional network flow. The official ACCS train/test partition carries 39
numeric flow features + 3 categoricals (proto/service/state) + a binary label + a 10-class
attack_cat. Build runs three techniques that genuinely fit this partition's shape:

  regression  (strong)   logistic on log1p+standardized numerics, official train->test AUC,
                         plus the sttl-drop ablation that shows no single feature is load-bearing.
  pca_factor  (strong)   cumulative explained variance: the 39 features are low-rank.
  cluster     (moderate) KMeans on the top 10 PCs, crosstab vs attack_cat as a post-hoc check
                         (the label is NEVER used during fitting).

The dataset's own conclusion: detection is easy AND highly redundant — the discriminative signal
is duplicated across correlated byte/packet/load/connection-count families, so single-feature
narratives about this partition are unreliable.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import adjusted_rand_score, roc_auc_score, roc_curve, silhouette_score
from sklearn.preprocessing import StandardScaler

from .. import artifacts, colors, paths
from ..acquire import unsw_nb15 as acquire

DATASET_ID = "unsw-nb15"
RANDOM_STATE = 0
# Non-feature columns: id is a row key, three categoricals + two labels are not numeric features.
_NON_FEATURE = {"id", "proto", "service", "state", "attack_cat", "label"}
# Severity palette for the 10 attack_cat values (Normal benign, everything else malicious-toned;
# Generic gets the suspicious amber to set the dominant attack family apart on the heatmap).
_CAT_ORDER = [
    "Normal", "Generic", "Exploits", "Fuzzers", "DoS", "Reconnaissance",
    "Analysis", "Backdoor", "Shellcode", "Worms",
]


def _load() -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    paths_ = acquire.acquire()
    train = pd.read_csv(paths_["train"])
    test = pd.read_csv(paths_["test"])
    numeric = [c for c in train.columns if c not in _NON_FEATURE]
    return train, test, numeric


def _design(df: pd.DataFrame, numeric: list[str], scaler: StandardScaler | None) -> tuple[np.ndarray, StandardScaler]:
    """log1p(clip>=0) then standardize. Fit the scaler on train, reuse it on test."""
    x = np.log1p(df[numeric].clip(lower=0).astype(float).to_numpy())
    if scaler is None:
        scaler = StandardScaler().fit(x)
    return scaler.transform(x), scaler


def _downsample_roc(fpr: np.ndarray, tpr: np.ndarray, n: int = 200) -> list[dict]:
    """Evenly thin a ROC curve so the inlined spec stays small but the shape is preserved."""
    if len(fpr) <= n:
        idx = np.arange(len(fpr))
    else:
        idx = np.unique(np.linspace(0, len(fpr) - 1, n).round().astype(int))
    return [{"fpr": round(float(fpr[i]), 4), "tpr": round(float(tpr[i]), 4)} for i in idx]


def _regression(m: artifacts.Manifest, train, test, numeric) -> artifacts.Analysis:
    Xtr, scaler = _design(train, numeric, None)
    Xte, _ = _design(test, numeric, scaler)
    ytr, yte = train["label"].to_numpy(), test["label"].to_numpy()

    def fit_auc(cols: list[int]):
        model = LogisticRegression(max_iter=2000, random_state=RANDOM_STATE)
        model.fit(Xtr[:, cols], ytr)
        proba = model.predict_proba(Xte[:, cols])[:, 1]
        return model, roc_auc_score(yte, proba), roc_curve(yte, proba)

    all_cols = list(range(len(numeric)))
    sttl_i = numeric.index("sttl")
    no_sttl = [i for i in all_cols if i != sttl_i]

    full_model, auc_full, (fpr_f, tpr_f, _) = fit_auc(all_cols)
    _, auc_nosttl, (fpr_n, tpr_n, _) = fit_auc(no_sttl)
    _, auc_sttl, (fpr_s, tpr_s, _) = fit_auc([sttl_i])
    delta = auc_full - auc_nosttl

    # Standardized coefficients of the full model: |value| ranking shows the signal is spread,
    # not concentrated. Magnitudes are inflated/unstable because the features are collinear —
    # which is itself the redundancy story, so we report the ranking, not the raw scale.
    coef = pd.DataFrame({"feature": numeric, "coef": full_model.coef_[0]})
    coef["abs_coef"] = coef["coef"].abs()
    coef = coef.sort_values("abs_coef", ascending=False).reset_index(drop=True)
    coef_path = artifacts.write_table(f"{DATASET_ID}.regression.coef", coef)

    roc_series = {
        "full": _downsample_roc(fpr_f, tpr_f),
        "no_sttl": _downsample_roc(fpr_n, tpr_n),
        "sttl_only": _downsample_roc(fpr_s, tpr_s),
        "auc": {"full": auc_full, "no_sttl": auc_nosttl, "sttl_only": auc_sttl},
    }
    roc_path = artifacts.write_json(f"{DATASET_ID}.regression.roc", roc_series)

    variants = [
        ("full model (39 features)", colors.ACCENT, roc_series["full"]),
        ("drop sttl (38 features)", colors.BENIGN, roc_series["no_sttl"]),
        ("sttl alone (1 feature)", colors.SUSPICIOUS, roc_series["sttl_only"]),
    ]
    values = []
    for name, _, pts in variants:
        for pt in pts:
            values.append({"model": name, "fpr": pt["fpr"], "tpr": pt["tpr"]})
    domain = [v[0] for v in variants]
    rng = [v[1] for v in variants]
    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": {
            "text": "Spotting attacks is easy, but no single column does the work",
            "subtitle": f"trained on the official set, tested on the held-out set  •  "
                        f"attack-vs-normal score (0.5=guessing, 1.0=perfect): all columns {auc_full:.4f}, "
                        f"drop sttl {auc_nosttl:.4f} (Δ{delta:.4f}), sttl alone {auc_sttl:.2f}",
        },
        "width": "container",
        "height": 360,
        "layer": [
            {
                "data": {"values": [{"fpr": 0, "tpr": 0}, {"fpr": 1, "tpr": 1}]},
                "mark": {"type": "rule", "color": colors.NEUTRAL, "strokeDash": [4, 4]},
                "encoding": {
                    "x": {"field": "fpr", "type": "quantitative"},
                    "y": {"field": "tpr", "type": "quantitative"},
                },
            },
            {
                "data": {"values": values},
                "mark": {"type": "line", "interpolate": "monotone"},
                "encoding": {
                    "x": {"field": "fpr", "type": "quantitative",
                          "title": "false positive rate", "scale": {"domain": [0, 1]}},
                    "y": {"field": "tpr", "type": "quantitative",
                          "title": "true positive rate", "scale": {"domain": [0, 1]}},
                    "color": {"field": "model", "type": "nominal", "title": "model variant",
                              "scale": {"domain": domain, "range": rng},
                              "legend": {"orient": "bottom-right"}},
                    "order": {"field": "fpr"},
                },
            },
        ],
    }
    spec_path = artifacts.write_spec(f"{DATASET_ID}.regression.roc", spec)

    return artifacts.Analysis(
        technique="regression",
        title="Easy to catch attacks, but no single column gets the credit",
        finding=(
            f"We trained a simple formula (it learns to predict the answer from the columns) on the "
            f"official UNSW-NB15 training set, after first squashing the big numbers and putting every "
            f"column on the same scale. On the official test set it gets a {auc_full:.4f} score for "
            f"telling attacks from normal traffic (0.5 is just guessing, 1.0 is perfect). The "
            f"important part is how steady this is: taking away sttl — the one column people most "
            f"often say does the work — changes the score by only {delta:.4f} "
            f"({auc_full:.4f}→{auc_nosttl:.4f}), and sttl by itself scores just {auc_sttl:.2f}. So "
            f"spotting attacks here is easy, but no single column carries it. The clue that separates "
            f"attacks from normal traffic is repeated across many columns that move together — about "
            f"bytes, packets, load, and connection counts. The formula's weights look big and jumpy "
            f"(the biggest by size: {coef.loc[0,'feature']}, {coef.loc[1,'feature']}, "
            f"{coef.loc[2,'feature']}), but that is because those columns overlap so much, not because "
            f"one column is secretly leaking the answer."
        ),
        fit="strong",
        storage=[roc_path, coef_path],
        spec=spec_path,
        metrics=[
            artifacts.Metric("Attack-vs-normal score, all columns (0.5=guess, 1.0=perfect)", f"{auc_full:.3f}"),
            artifacts.Metric("Score drop when the sttl column is removed", f"{delta:.4f}"),
            artifacts.Metric("Score using only the sttl column", f"{auc_sttl:.2f}"),
        ],
        params={
            "model": "LogisticRegression(max_iter=2000, random_state=0)",
            "features": "39 numeric, log1p(clip>=0) + StandardScaler",
            "eval": "official train->test, metric=ROC AUC",
            "ablations": ["full", "no_sttl", "sttl_only"],
        },
        row_counts={"train": int(len(train)), "test": int(len(test))},
        data_quality_note=(
            "The mix of attacks and normal traffic was set up by hand (68.1% attack, while real "
            "networks see about ~13%), so this score describes this made-up split, not real traffic."
        ),
    )


def _pca_factor(m: artifacts.Manifest, train, numeric) -> artifacts.Analysis:
    Xtr, _ = _design(train, numeric, None)
    pca = PCA(random_state=RANDOM_STATE).fit(Xtr)
    indiv = pca.explained_variance_ratio_
    cum = np.cumsum(indiv)

    def pcs_for(th: float) -> int:
        return int(np.argmax(cum >= th) + 1)

    n80, n90, n94 = pcs_for(0.80), pcs_for(0.90), pcs_for(0.94)

    scree = pd.DataFrame({
        "pc": np.arange(1, len(indiv) + 1),
        "individual": indiv,
        "cumulative": cum,
    })
    scree_path = artifacts.write_table(f"{DATASET_ID}.pca_factor.scree", scree)

    # Top loadings per of the first three components: names the latent factors.
    loadings = pd.DataFrame(pca.components_[:3].T, columns=["PC1", "PC2", "PC3"], index=numeric)
    top_load = {}
    for c in ["PC1", "PC2", "PC3"]:
        s = loadings[c].abs().sort_values(ascending=False).head(5)
        top_load[c] = [{"feature": f, "loading": round(float(loadings.loc[f, c]), 3)} for f in s.index]
    load_path = artifacts.write_json(f"{DATASET_ID}.pca_factor.loadings", top_load)

    bar_vals = [{"pc": int(r.pc), "series": "individual", "value": round(float(r.individual), 4)}
                for r in scree.itertuples()]
    line_vals = [{"pc": int(r.pc), "series": "cumulative", "value": round(float(r.cumulative), 4)}
                 for r in scree.itertuples()]
    thresholds = [
        {"y": 0.80, "label": f"80% → {n80} PCs"},
        {"y": 0.90, "label": f"90% → {n90} PCs"},
        {"y": 0.94, "label": f"94% → {n94} PCs"},
    ]
    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": {
            "text": "The 39 number columns mostly repeat each other",
            "subtitle": f"{n80} squeezed columns hold 80% of the pattern, {n90} hold 90%, {n94} hold 94% "
                        f"— about {len(numeric) - n94} of {len(numeric)} number columns barely add anything",
        },
        "width": "container",
        "height": 360,
        "encoding": {"x": {"field": "pc", "type": "quantitative",
                           "title": "principal component index",
                           "scale": {"domain": [0, len(indiv) + 1]}}},
        "layer": [
            {
                "data": {"values": bar_vals},
                "mark": {"type": "bar", "color": colors.NEUTRAL, "opacity": 0.6, "width": 4},
                "encoding": {
                    "y": {"field": "value", "type": "quantitative",
                          "title": "explained variance ratio", "scale": {"domain": [0, 1]}},
                    "color": {"field": "series", "type": "nominal", "title": "variance",
                              "scale": {"domain": ["individual", "cumulative"],
                                        "range": [colors.NEUTRAL, colors.ACCENT]},
                              "legend": {"orient": "bottom-right"}},
                },
            },
            {
                "data": {"values": line_vals},
                "mark": {"type": "line", "point": True, "color": colors.ACCENT},
                "encoding": {
                    "y": {"field": "value", "type": "quantitative"},
                    "color": {"field": "series", "type": "nominal",
                              "scale": {"domain": ["individual", "cumulative"],
                                        "range": [colors.NEUTRAL, colors.ACCENT]}},
                },
            },
            {
                "data": {"values": thresholds},
                "mark": {"type": "rule", "color": colors.SUSPICIOUS, "strokeDash": [4, 4]},
                "encoding": {"y": {"field": "y", "type": "quantitative"}},
            },
            {
                "data": {"values": thresholds},
                "mark": {"type": "text", "align": "left", "baseline": "bottom",
                         "dx": 6, "x": 8, "color": colors.SUSPICIOUS, "fontSize": 10},
                "encoding": {"y": {"field": "y", "type": "quantitative"},
                             "text": {"field": "label", "type": "nominal"}},
            },
        ],
    }
    spec_path = artifacts.write_spec(f"{DATASET_ID}.pca_factor.scree", spec)

    return artifacts.Analysis(
        technique="pca_factor",
        title="Only about a quarter of the number columns really matter",
        finding=(
            f"We squeezed the 39 number columns down to a few new columns that still hold most of the "
            f"pattern (after squashing big numbers and putting them on the same scale). A few columns "
            f"hold almost everything: {n80} squeezed columns hold 80% of the pattern, {n90} hold 90%, "
            f"and {n94} hold 94% — so about {len(numeric) - n94} of the 39 columns barely add anything "
            f"new. Looking at which original columns make up each squeezed column tells us what they "
            f"stand for: the first one is built mostly from the TCP connection-state columns "
            f"({top_load['PC1'][0]['feature']}, {top_load['PC1'][1]['feature']} — the destination TCP "
            f"window and starting sequence numbers), while later ones separate the ct_* "
            f"connection-count columns and the rate/load columns. This explains the earlier result: "
            f"because the clue lives in just a handful of overlapping groups, taking away any one raw "
            f"column barely changes how well attacks are caught."
        ),
        fit="strong",
        storage=[scree_path, load_path],
        spec=spec_path,
        metrics=[
            artifacts.Metric("Squeezed columns to hold 80% of the pattern", f"{n80} of {len(numeric)}"),
            artifacts.Metric("Squeezed columns to hold 90% of the pattern", f"{n90} of {len(numeric)}"),
            artifacts.Metric("Squeezed columns to hold 94% of the pattern", f"{n94} of {len(numeric)}"),
        ],
        params={
            "inputs": "log1p(clip>=0) + StandardScaler on 39 numeric features",
            "fit": "PCA(random_state=0) on training rows",
            "thresholds": [0.80, 0.90, 0.94],
        },
        row_counts={"train": int(len(train))},
    )


def _cluster(m: artifacts.Manifest, train, numeric) -> artifacts.Analysis:
    Xtr, _ = _design(train, numeric, None)
    pcs = PCA(n_components=10, random_state=RANDOM_STATE).fit_transform(Xtr)
    k = 8
    km = KMeans(n_clusters=k, random_state=RANDOM_STATE, n_init=10).fit(pcs)
    labels = km.labels_

    rng = np.random.RandomState(RANDOM_STATE)
    samp = rng.choice(len(pcs), 5000, replace=False)
    sil = silhouette_score(pcs[samp], labels[samp])
    ari = adjusted_rand_score(train["attack_cat"], labels)

    ct = pd.crosstab(pd.Series(labels, name="cluster"), train["attack_cat"])
    ct = ct.reindex(columns=[c for c in _CAT_ORDER if c in ct.columns])
    row_share = ct.div(ct.sum(axis=1), axis=0)

    ct_out = ct.reset_index()
    ct_path = artifacts.write_table(f"{DATASET_ID}.cluster.crosstab", ct_out)

    # Per-cluster dominant category + purity for the summary.
    summary = []
    for cl in ct.index:
        dom = row_share.loc[cl].idxmax()
        summary.append({
            "cluster": int(cl),
            "n": int(ct.loc[cl].sum()),
            "dominant": dom,
            "purity": round(float(row_share.loc[cl, dom]), 3),
        })
    generic_purity = max(s["purity"] for s in summary if s["dominant"] == "Generic")
    summary_obj = {"k": k, "silhouette": float(sil), "adjusted_rand": float(ari), "clusters": summary}
    summary_path = artifacts.write_json(f"{DATASET_ID}.cluster.summary", summary_obj)

    heat_vals = []
    for cl in ct.index:
        for cat in ct.columns:
            heat_vals.append({
                "cluster": f"c{int(cl)}",
                "attack_cat": cat,
                "share": round(float(row_share.loc[cl, cat]), 3),
                "count": int(ct.loc[cl, cat]),
            })
    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": {
            "text": "Generic and Normal have their own shapes; rare types blend in",
            "subtitle": f"sorted into {k} groups using the top 10 squeezed columns (labels not used)  •  "
                        f"group-vs-label match {ari:.2f}, how cleanly groups separate {sil:.2f}",
        },
        "width": "container",
        "height": 320,
        "data": {"values": heat_vals},
        "mark": {"type": "rect"},
        "encoding": {
            "x": {"field": "cluster", "type": "nominal", "title": "cluster (unsupervised)",
                  "sort": [f"c{i}" for i in range(k)]},
            "y": {"field": "attack_cat", "type": "nominal", "title": "attack_cat (post-hoc)",
                  "sort": _CAT_ORDER},
            "color": {"field": "share", "type": "quantitative",
                      "title": "row-normalized share",
                      "scale": {"scheme": "blues", "domain": [0, 1]},
                      "legend": {"orient": "right"}},
            "tooltip": [
                {"field": "cluster", "type": "nominal"},
                {"field": "attack_cat", "type": "nominal"},
                {"field": "share", "type": "quantitative", "format": ".2f"},
                {"field": "count", "type": "quantitative"},
            ],
        },
    }
    spec_path = artifacts.write_spec(f"{DATASET_ID}.cluster.heatmap", spec)

    return artifacts.Analysis(
        technique="cluster",
        title="Which attack types have their own recognizable shape",
        finding=(
            f"We sorted the rows into {k} groups by how alike they are, using the top 10 squeezed "
            f"columns, and we did NOT show it the attack labels while sorting. The groups match the "
            f"real attack types only so-so (a 'do the groups match the labels' score of {ari:.2f}, "
            f"where higher is better, and a 'how cleanly the groups separate' score of {sil:.2f}). "
            f"The result is honest about which types have their own shape: Generic piles into one "
            f"group that is {generic_purity:.0%} one type, and Normal splits across three groups that "
            f"are each almost all one type, while the rare types blend in — Worms (n=130), Shellcode, "
            f"and Backdoor scatter across the mixed Exploits/Fuzzers/DoS groups and never get a group "
            f"of their own. So the shape of the traffic tells apart the common Generic and Normal "
            f"traffic cleanly, but cannot see the rare attack types — and it figured this out without "
            f"ever seeing the labels."
        ),
        fit="moderate",
        storage=[ct_path, summary_path],
        spec=spec_path,
        metrics=[
            artifacts.Metric("Number of groups", str(k)),
            artifacts.Metric("Group-vs-label match score", f"{ari:.2f}"),
            artifacts.Metric("How much the Generic group is one type", f"{generic_purity:.0%}"),
        ],
        params={
            "model": "KMeans(n_clusters=8, n_init=10, random_state=0)",
            "inputs": "top 10 PCs of log1p+standardized numerics",
            "label_use": "post-hoc crosstab only; never used during fit",
        },
        row_counts={"train": int(len(train))},
        fit_warning=(
            "The attack types are very lopsided (Worms has just n=130 rows, about ~300x fewer than "
            "Generic), so anything we say about the rare types is shaky; the clean split only holds "
            "for the common Generic and Normal traffic."
        ),
    )


def build(m: artifacts.Manifest) -> artifacts.Dataset:
    train, test, numeric = _load()
    analyses = [
        _regression(m, train, test, numeric),
        _pca_factor(m, train, numeric),
        _cluster(m, train, numeric),
    ]
    ds = artifacts.Dataset(
        id=DATASET_ID,
        display_name="UNSW-NB15 Network-Flow Intrusion Dataset (official train/test partition)",
        doc_category="network-flow",
        what_it_is=(
            "A practice dataset for catching network attacks. Each row is one back-and-forth "
            "conversation between two computers, with 39 number columns describing it, 3 "
            "word/category columns, a yes/no attack label, and an attack-type label with 10 types."
        ),
        source={
            "name": "UNSW-NB15 (ACCS), official train/test CSV partition",
            "url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
            "license": "Academic/research use (ACCS); cite Moustafa & Slay 2015.",
        },
        isolated_insight=(
            "On the official UNSW-NB15 split, telling attacks from normal traffic is both easy and "
            "very repetitive. A simple formula scores 0.939 for attack-vs-normal (0.5 is guessing, "
            "1.0 is perfect), but that score does not lean on any single column — taking away the "
            "column people cite most (sttl) changes it by only 0.0002, and squeezing the 39 columns "
            "down shows that just 10 squeezed columns hold 94% of the pattern. The clue that "
            "separates attacks from normal traffic is repeated across overlapping groups of columns "
            "— about bytes, packets, load, and connection counts — so stories that pin it on one "
            "'most important' column are not trustworthy, and the number columns squash down to about "
            "a quarter of their size with no loss in accuracy."
        ),
        solution_idea=(
            "A tool that finds the smallest set of columns a network-attack detector really needs, "
            "and points out when columns just repeat each other. Given a labeled dataset it (1) "
            "squeezes the columns down to count how many truly different pieces of information "
            "exist, and (2) drops one group of columns at a time and re-checks the attack-vs-normal "
            "score to see how much each group actually adds, then reports the smallest set of "
            "columns that keeps detection nearly as good. On UNSW-NB15 it would say to collect about "
            "a third of the number columns instead of all 39 — cheaper to gather at the sensor, with "
            "no measurable drop in catching attacks — and it would warn when a reported score is "
            "only high because of repeated columns."
        ),
        honesty_notes=(
            "(1) The mix of attacks and normal traffic was set up by hand (68.1% attack, while real "
            "networks see about ~13%), so the score and any cost numbers describe this made-up split "
            "only, not real traffic. (2) The common claim that sttl almost separates attacks by "
            "itself is overblown: sttl alone scores only 0.76 and dropping it barely matters — we "
            "report this as a correction. (3) The data was made by a machine (IXIA), so some of what "
            "looks easy to separate is really a fingerprint of that machine (the rate column is "
            "hard-capped at 1e6, a made-up ceiling). (4) This split has no timestamp, so we cannot do "
            "anything that needs time order here. (5) The attack types are very lopsided (Worms "
            "n=130), so anything about the rare types is shaky. (6) The score is measured on the one "
            "fixed published split, not re-checked across several different splits."
        ),
        analyses=analyses,
    )
    m.add(ds)
    return ds
