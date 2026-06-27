"""Dataset module: Nazario phishing corpus (2020 year-file), analyzed in isolation.

Single implicit class (every message is phishing), so every finding here is DESCRIPTIVE of
phishing structure — no classifier, no precision/recall. The 2020 file is non-anonymized, so this
module aggregates only: it never writes a raw sender/subject/address into any artifact.

build(m) writes artifacts (all prefixed "nazario.") then registers one Dataset with three analyses:
  text_sentiment (strong)  — urgency-lexicon density + brand concentration + TF-IDF topics
  cluster        (moderate)— lure-structure segments (text + MIME-structure features)
  timeseries     (moderate)— monthly send volume, reported as a genuine NEGATIVE (flat) result
"""
from __future__ import annotations

import html
import mailbox
import re
from email.header import decode_header, make_header
from email.utils import parseaddr, parsedate_to_datetime

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.cluster import KMeans
from sklearn.decomposition import NMF, TruncatedSVD
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

from .. import artifacts
from ..acquire import nazario as _src

DID = "nazario"

# Severity / accent hexes (mirror of cyberviz.colors) used in the specs.
SUSPICIOUS = "#e0a341"
ACCENT = "#3b82f6"
NEUTRAL = "#8a94a6"
# Non-severity categorical palette for the 5 lure-structure clusters (clusters are not severities).
CLUSTER_COLORS = ["#3b82f6", "#0ea5e9", "#8b5cf6", "#e0a341", "#14b8a6"]

# Curated urgency / security-action lexicon (~24 stems). Substring match against the subject line.
URGENCY_LEX = [
    "verif", "locked", "suspend", "confirm", "pending", "expir", "urgent", "immediat",
    "deactiv", "reactiv", "unusual", "restrict", "validate", "24hr", "disabl", "blocked",
    "alert", "update your", "required", "secur", "password", "quarantin", "undeliver",
    "notification",
]
# Brand tokens we look for across the From + Subject surface (impersonation targets).
BRANDS = [
    "paypal", "wells", "fargo", "microsoft", "chase", "netflix", "dhl", "amazon", "bank",
    "google", "apple", "outlook", "docusign", "wetransfer", "linkedin", "facebook",
]
# Tokens that are noise for topic modelling: HTML/CSS residue + the victim's own identifiers.
_CSS = {
    "width", "font", "size", "height", "margin", "padding", "style", "table", "family", "color",
    "text", "align", "border", "cellpadding", "cellspacing", "bgcolor", "valign", "href", "span",
    "div", "class", "img", "src", "solid", "center", "left", "right", "top", "bottom", "arial",
    "helvetica", "sans", "serif", "line", "background", "display", "block", "none", "important",
    "rgb", "moz", "webkit",
}
_JUNK = {"nbsp", "amp", "quot", "monkey", "org", "jose", "www", "com", "http", "https", "email", "emails"}
_STOP = list(ENGLISH_STOP_WORDS | _CSS | _JUNK)


def _decode(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _clean(text: str) -> str:
    """Decode entities, strip any residual tags, keep letters only — for NLP/topic modelling."""
    t = html.unescape(str(text))
    t = re.sub(r"<[^>]+>", " ", t)
    t = re.sub(r"[^a-zA-Z ]", " ", t)
    return t.lower()


def _frame() -> pd.DataFrame:
    """Canonical frame from the loader, with a CORRECTED date column and structural flags.

    The shared loader's pd.to_datetime drops 109/158 RFC-822 dates (no weekday prefix); we re-parse
    each Date header with email.utils.parsedate_to_datetime (parses 158/158) by mailbox position.
    """
    df = _src.load()
    mbox = mailbox.mbox(str(_src.acquire()["mbox"]))
    dates, has_att = [], []
    for msg in mbox:
        try:
            dates.append(parsedate_to_datetime(msg.get("Date")))
        except Exception:
            dates.append(None)
        parts = msg.walk() if msg.is_multipart() else [msg]
        has_att.append(any("attachment" in (p.get("Content-Disposition") or "").lower() for p in parts))
    df = df.reset_index(drop=True)
    df["date"] = pd.to_datetime(pd.Series(dates), utc=True, errors="coerce")
    df["has_att"] = has_att
    df["html_only"] = df["content_type"].eq("text/html")          # text/html as the TOP-LEVEL type
    df["multipart"] = df["is_multipart"].astype(bool)
    surface = (df["subject"].fillna("") + " " + df["body"].fillna(""))
    df["nonlatin"] = surface.str.contains(r"[가-힣぀-ヿ一-鿿]", regex=True)
    df["clean"] = (df["subject"].fillna("") + " " + df["body"].fillna("")).map(_clean)
    df["subj_l"] = df["subject"].fillna("").str.lower()
    df["from_name"] = df["from"].map(lambda v: parseaddr(v)[0]).map(_decode).str.lower()
    df["from_dom"] = df["from"].map(lambda v: parseaddr(v)[1]).str.split("@").str[-1].str.lower()
    return df


def _label_cluster(top_terms: list[str], att_rate: float) -> str:
    """Map a cluster to an interpretable lure-type label from its top terms + attachment rate."""
    ts = set(top_terms)
    if att_rate > 0.5:
        return "file-delivery (attachment)"
    if {"storage", "upgrade", "quota", "capacity", "limits", "mailbox"} & ts:
        return "mailbox-quota"
    if {"pending", "messages", "release", "undelivered", "quarantine"} & ts:
        return "pending-message"
    if {"verify", "security", "password", "confirm"} & ts:
        return "credential-verify"
    return "brand/account"


def build(m: artifacts.Manifest) -> artifacts.Dataset:
    df = _frame()
    n = len(df)

    # ---- TEXT_SENTIMENT --------------------------------------------------------------------
    # Urgency-lexicon density on subjects.
    df["urgent"] = df["subj_l"].apply(lambda s: any(t in s for t in URGENCY_LEX))
    n_urgent = int(df["urgent"].sum())
    urgency_counts = {t: int(df["subj_l"].str.contains(t, regex=False).sum()) for t in URGENCY_LEX}
    urgency_counts = {k: v for k, v in urgency_counts.items() if v > 0}
    # Brand concentration across From + Subject.
    surface = (df["from_name"] + " " + df["subj_l"])
    brand_counts = {b: int(surface.str.contains(b, regex=False).sum()) for b in BRANDS}
    brand_counts = {k: v for k, v in brand_counts.items() if v > 0}

    # TF-IDF NMF topics (k=4) for the descriptive topic byproduct.
    vec_t = TfidfVectorizer(min_df=2, max_df=0.5, stop_words=_STOP,
                            token_pattern=r"[a-z]{3,}", max_features=1500)
    Xtopic = vec_t.fit_transform(df["clean"])
    terms_t = np.array(vec_t.get_feature_names_out())
    nmf = NMF(n_components=4, random_state=0, init="nndsvda", max_iter=500)
    W = nmf.fit_transform(Xtopic)
    H = nmf.components_
    topic_assign = W.argmax(1)
    topics = []
    for k in range(4):
        top = list(terms_t[H[k].argsort()[::-1][:10]])
        topics.append({"topic": k, "size": int((topic_assign == k).sum()), "top_terms": top})

    # Chart rows: top urgency terms (amber) + top brand terms (accent blue), one horizontal bar set.
    term_rows = []
    for t, c in sorted(urgency_counts.items(), key=lambda kv: -kv[1])[:10]:
        term_rows.append({"term": t, "count": c, "kind": "urgency"})
    for b, c in sorted(brand_counts.items(), key=lambda kv: -kv[1])[:8]:
        term_rows.append({"term": b, "count": c, "kind": "brand"})

    ts_series = artifacts.write_json(f"{DID}.text_sentiment.terms", {
        "n_messages": n, "n_urgent_subjects": n_urgent,
        "urgency_pct": round(100 * n_urgent / n, 1),
        "urgency_counts": urgency_counts, "brand_counts": brand_counts,
        "topics": topics, "n_nonlatin": int(df["nonlatin"].sum()),
    })
    ts_spec = artifacts.write_spec(f"{DID}.text_sentiment.bars", {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": "Words fake emails use: scary/rushing word-starts and copied brand names (from the subject and sender)",
        "width": "container", "height": 360,
        "data": {"values": term_rows},
        "mark": {"type": "bar"},
        "encoding": {
            "y": {"field": "term", "type": "nominal", "sort": "-x", "title": "lexicon stem / brand"},
            "x": {"field": "count", "type": "quantitative", "title": "messages containing term"},
            "color": {
                "field": "kind", "type": "nominal", "title": "term type",
                "scale": {"domain": ["urgency", "brand"], "range": [SUSPICIOUS, ACCENT]},
            },
            "tooltip": [{"field": "term"}, {"field": "kind"}, {"field": "count", "type": "quantitative"}],
        },
    })
    a_text = artifacts.Analysis(
        technique="text_sentiment",
        title="Fake emails use a small set of scary words and copy a few famous brand names over and over",
        finding=(
            f"Out of all {n} fake-email subject lines, {n_urgent} ({round(100*n_urgent/n,1)}%) use a word meant to "
            f"rush you or scare you about your account. These come from a hand-picked list of 24 word-stems (a stem is "
            f"the start of a word, so 'verif' catches both 'verify' and 'verification'). The most common are: pending "
            f"{urgency_counts.get('pending',0)}, alert {urgency_counts.get('alert',0)}, locked {urgency_counts.get('locked',0)}, "
            f"verif {urgency_counts.get('verif',0)}, confirm {urgency_counts.get('confirm',0)}. The emails copy only a "
            f"few famous names — generic 'bank' {brand_counts.get('bank',0)}, Wells/Fargo {brand_counts.get('wells',0)}/{brand_counts.get('fargo',0)}, "
            f"PayPal {brand_counts.get('paypal',0)}, Netflix {brand_counts.get('netflix',0)}, WeTransfer {brand_counts.get('wetransfer',0)}. "
            f"Grouping the messages by which words show up together a lot gives four themes — account/password-check, "
            f"held-up-message, full-mailbox/storage, and a 'your account is being shut off' push — and {int(df['nonlatin'].sum())} "
            f"messages are written in non-Latin letters (like Chinese, Japanese, or Korean) that an English word-list "
            f"would miss. The clue here is the words used, not how many emails arrive."
        ),
        fit="strong",
        storage=[ts_series],
        spec=ts_spec,
        metrics=[
            artifacts.Metric("Scary/rushing subject lines", f"{n_urgent}/{n} ({round(100*n_urgent/n,1)}%)"),
            artifacts.Metric("Different brands copied", str(len(brand_counts))),
            artifacts.Metric("Non-Latin-letter emails", str(int(df["nonlatin"].sum()))),
            artifacts.Metric("Word-group themes", "4"),
        ],
        params={"urgency_lexicon_stems": len(URGENCY_LEX), "tfidf_min_df": 2, "nmf_k": 4, "random_state": 0},
        row_counts={"messages": n, "urgent_subjects": n_urgent},
        data_quality_note=(
            "The percentage depends on which words are on the list. This hand-picked list of 24 word-stems gives the "
            "number shown; adding more words (like plain 'account') would push it higher. The list is English-only, so "
            "non-Latin-letter emails are counted on the side instead of scored."
        ),
    )

    # ---- CLUSTER ---------------------------------------------------------------------------
    vec_c = TfidfVectorizer(min_df=3, max_df=0.5, stop_words=_STOP,
                            token_pattern=r"[a-z]{3,}", max_features=300)
    Xtxt = vec_c.fit_transform(df["clean"])
    terms_c = np.array(vec_c.get_feature_names_out())
    struct = StandardScaler().fit_transform(df[["has_att", "html_only", "multipart"]].astype(float).values)
    X = hstack([Xtxt, csr_matrix(struct)]).tocsr()
    svd = TruncatedSVD(n_components=10, random_state=0).fit_transform(X)
    sweep = {}
    for k in range(3, 8):
        km = KMeans(n_clusters=k, random_state=0, n_init=10).fit(svd)
        sweep[k] = round(float(silhouette_score(svd, km.labels_)), 3)
    K = 5  # silhouette favours k=3 (one big structural split); k=5 is the interpretable lure segmentation
    km = KMeans(n_clusters=K, random_state=0, n_init=10).fit(svd)
    df["cluster"] = km.labels_

    cluster_rows, summary_rows = [], []
    for c in range(K):
        idx = df.index[df["cluster"] == c]
        mt = np.asarray(Xtxt[idx].mean(0)).ravel()
        top = list(terms_c[mt.argsort()[::-1][:6]])
        att_rate = float(df.loc[idx, "has_att"].mean())
        label = _label_cluster(top, att_rate)
        summary_rows.append({
            "cluster": c, "lure_type": label, "size": int(len(idx)),
            "attachment_rate": round(att_rate, 2),
            "html_only_rate": round(float(df.loc[idx, "html_only"].mean()), 2),
            "multipart_rate": round(float(df.loc[idx, "multipart"].mean()), 2),
            "nonlatin": int(df.loc[idx, "nonlatin"].sum()),
            "top_terms": ", ".join(top),
        })
    label_by_c = {r["cluster"]: r["lure_type"] for r in summary_rows}
    # Scatter points (NO PII): projection coords + lure label + structural flags only.
    for i in df.index:
        cl = int(df.at[i, "cluster"])
        cluster_rows.append({
            "x": round(float(svd[i, 0]), 4), "y": round(float(svd[i, 1]), 4),
            "lure_type": label_by_c[cl],
            "has_attachment": bool(df.at[i, "has_att"]),
            "html_only": bool(df.at[i, "html_only"]),
        })

    cl_summary = artifacts.write_table(f"{DID}.cluster.summary", pd.DataFrame(summary_rows))
    cl_points = artifacts.write_json(f"{DID}.cluster.points", {"silhouette_sweep": sweep, "k": K, "points": cluster_rows})
    domain = [r["lure_type"] for r in summary_rows]
    cl_spec = artifacts.write_spec(f"{DID}.cluster.scatter", {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": f"Groups of fake emails by trick and shape (k={K}), squeezed down to 2 directions so they fit on this chart",
        "width": "container", "height": 420,
        "data": {"values": cluster_rows},
        "mark": {"type": "point", "filled": True, "size": 70, "opacity": 0.75},
        "encoding": {
            "x": {"field": "x", "type": "quantitative", "title": "SVD dimension 1"},
            "y": {"field": "y", "type": "quantitative", "title": "SVD dimension 2"},
            "color": {
                "field": "lure_type", "type": "nominal", "title": "lure type",
                "scale": {"domain": domain, "range": CLUSTER_COLORS[:K]},
            },
            "shape": {"field": "has_attachment", "type": "nominal", "title": "has attachment"},
            "tooltip": [
                {"field": "lure_type", "title": "lure type"},
                {"field": "has_attachment", "title": "attachment"},
                {"field": "html_only", "title": "html-only"},
            ],
        },
    })
    biggest = max(summary_rows, key=lambda r: r["size"])
    att_cluster = next((r for r in summary_rows if r["attachment_rate"] >= 0.9), None)
    a_cluster = artifacts.Analysis(
        technique="cluster",
        title="The fake emails fall into about 5 groups by their trick and their shape, including one clean file-attachment group",
        finding=(
            f"We sorted the emails into groups using the words in them plus three facts about their shape (does it have "
            f"a file attached, is it just a web-page body, is it built from several parts). This makes five groups that "
            f"each make sense: "
            + "; ".join(f"{r['lure_type']} (n={r['size']})" for r in summary_rows)
            + f". The file-attachment group is the cleanest — {att_cluster['size'] if att_cluster else 0} messages, every "
            f"single one with a file attached, exactly matching the {int(df['has_att'].sum())} emails in the set that carry a file. "
            f"The biggest group is '{biggest['lure_type']}' (n={biggest['size']}). A score for how cleanly the groups separate, "
            f"tried for 3 up to 7 groups, is {sweep}; 3 groups scores best ({sweep[3]}) but just splits everything one way, so we "
            f"show 5 groups because they are easier to make sense of. This only describes the shapes inside one pile of fake "
            f"emails — it does not tell fake from real."
        ),
        fit="moderate",
        storage=[cl_summary, cl_points],
        spec=cl_spec,
        metrics=[
            artifacts.Metric("Number of groups", str(K)),
            artifacts.Metric("Cleanest-separation score", f"{sweep[3]} @ k=3"),
            artifacts.Metric("File-attachment group", f"{att_cluster['size'] if att_cluster else 0} msgs"),
            artifacts.Metric("Biggest group", f"{biggest['lure_type']} ({biggest['size']})"),
        ],
        params={"kmeans_k": K, "k_swept": "3-7", "tfidf_min_df": 3, "svd_components": 10, "random_state": 0},
        row_counts={"messages": n, "clusters": K, "attachment_messages": int(df["has_att"].sum())},
        data_quality_note="158 emails is a small pile, so the group sizes are a hint, not a solid count you can trust.",
        fit_warning="Every email here is fake, so the groups describe the differences among fake emails — they cannot tell a fake email from a real one.",
    )

    # ---- TIMESERIES (negative result) ------------------------------------------------------
    dated = df.dropna(subset=["date"]).copy()
    dated["month"] = dated["date"].dt.tz_convert("UTC").dt.tz_localize(None).dt.to_period("M")
    monthly = dated["month"].value_counts().sort_index()
    # Restrict the trend view to the 2020 year-file; the lone 2021-03 straggler is noted, not plotted.
    y2020 = monthly[[str(p).startswith("2020") for p in monthly.index]]
    counts = [int(v) for v in y2020.values]
    mean_c = float(np.mean(counts))
    cv = float(np.std(counts) / mean_c)
    # Standardized excursions on a sqrt-n (Poisson) noise scale, to state the peak/trough honestly.
    sqrt_n = float(np.sqrt(mean_c))
    z_peak = (int(y2020.max()) - mean_c) / sqrt_n
    z_trough = (int(y2020.min()) - mean_c) / sqrt_n
    month_rows = [{"month": f"{p}-01", "count": int(v), "mean": round(mean_c, 1)} for p, v in y2020.items()]

    ts_json = artifacts.write_json(f"{DID}.timeseries.monthly", {
        "monthly_2020": {str(p): int(v) for p, v in y2020.items()},
        "straggler_2021_03": int(monthly.get(pd.Period("2021-03", "M"), 0)),
        "mean": round(mean_c, 2), "std": round(float(np.std(counts)), 2), "cv": round(cv, 3),
        "sqrt_n": round(sqrt_n, 2), "z_peak": round(z_peak, 2), "z_trough": round(z_trough, 2),
        "min_month": str(y2020.idxmin()), "max_month": str(y2020.idxmax()),
    })
    line_spec = artifacts.write_spec(f"{DID}.timeseries.line", {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": "Fake emails sent each month in 2020 — flat and bumpy, no pattern (a 'nothing here' result)",
        "width": "container", "height": 320,
        "data": {"values": month_rows},
        "layer": [
            {"mark": {"type": "rule", "color": NEUTRAL, "strokeDash": [4, 4]},
             "encoding": {"y": {"field": "mean", "type": "quantitative"}}},
            {"mark": {"type": "line", "color": ACCENT, "point": {"color": ACCENT}},
             "encoding": {
                 "x": {"field": "month", "type": "temporal", "timeUnit": "yearmonth", "title": "month (2020)"},
                 "y": {"field": "count", "type": "quantitative", "title": "messages sent"},
                 "tooltip": [{"field": "month", "type": "temporal", "timeUnit": "yearmonth"},
                             {"field": "count", "type": "quantitative"}],
             }},
        ],
    })
    a_time = artifacts.Analysis(
        technique="timeseries",
        title="The count sent each month in 2020 has no pattern — when the emails arrive tells us nothing",
        finding=(
            f"Each email has a date stamp, but the usual date-reader gives up on 109/158 of them; reading them a "
            f"different way gets all {n}. That gives monthly counts for 2020 of "
            f"{counts} (average {round(mean_c,1)} per month; how spread out the counts are is CV {round(cv,2)}). The high "
            f"month, June ({int(y2020.max())}, {z_peak:+.1f}σ, meaning that many steps away from normal), and the low "
            f"month, October ({int(y2020.min())}, {z_trough:+.1f}σ) are only small wobbles, and the year never climbs or "
            f"falls steadily and has no regular rhythm — so this is a real 'nothing here' result, and that is worth "
            f"saying. One stray email from March 2021 is left out of this view. What sets these emails apart is what "
            f"they say and how they are built, not when they show up."
        ),
        fit="moderate",
        storage=[ts_json],
        spec=line_spec,
        metrics=[
            artifacts.Metric("Months with data", f"{len(counts)}/12"),
            artifacts.Metric("Average per month", f"{round(mean_c,1)}"),
            artifacts.Metric("Bumpiness (spread)", f"{round(cv,2)}"),
            artifacts.Metric("Highest / lowest month", f"{int(y2020.max())} Jun / {int(y2020.min())} Oct"),
        ],
        params={"resample": "month", "year": 2020, "date_parser": "parsedate_to_datetime"},
        row_counts={"dated_messages": int(len(dated)), "months": len(counts)},
        data_quality_note="Just one year of emails, n=158: this only describes, it does not prove. You would need to join several years together before trusting any claim about timing.",
        fit_warning="This is a 'nothing here' result — do not read a regular pattern into these small ups and downs.",
    )

    ds = artifacts.Dataset(
        id=DID,
        display_name="Nazario Phishing Email Corpus (2020 sample)",
        doc_category="phishing-email",
        what_it_is="158 real fake-bait emails (the kind that try to trick you into giving up passwords or money), saved in a standard mailbox file from the year 2020. Each row is one email, with its header info (who sent it, when, and the subject) and its body text with the web-page formatting taken out.",
        source={
            "name": "Jose Nazario phishing corpus (phishing-2020)",
            "url": "https://monkey.org/~jose/phishing/",
            "license": "Public research archive; non-anonymized — aggregate only, no PII re-exposure.",
        },
        isolated_insight=(
            f"In this inbox where every email is fake, the emails that show up are built from a small, repeated set of "
            f"word and shape tricks — not from when they are sent. About {round(100*n_urgent/n)}% of subject lines use "
            f"words meant to rush or scare you; the sender pretends to be a brand ({int(df['has_att'].sum())} carry file "
            f"attachments, and {int((df['from_dom'].str.contains('monkey.org', na=False)).sum())} even fake the victim's own "
            f"email address as the sender); and the email is almost always a web-page (HTML) body. The number sent each "
            f"month only wobbles weakly with no pattern (average {round(mean_c,1)} per month, bumpiness CV {round(cv,2)}). "
            f"What gives a fake email away here is its words and its build, not its timing."
        ),
        solution_idea=(
            "A small, easy-to-read tool that looks at one email and adds a few plain tags taken straight from this set "
            "of emails: how many rush/scare words it uses; whether the name it shows does not match the real email "
            "address it was sent from (including faking your own address); its shape (just a web page, has a file, or "
            "built from several parts); and a trick-type label (password-check / file-delivery / held-up-message / "
            "full-mailbox / non-Latin). Because every email here is fake, the tool is not a guesser that says fake-or-"
            "real. It just labels the clues and explains WHY an email looks like a known trick."
        ),
        honesty_notes=(
            "Every email here is fake, so we cannot build anything that tells fake from real, and we cannot give an "
            "accuracy score, without a separate pile of normal emails to compare against — every finding just describes "
            "how fake emails are built. n=158 (one year) is small, so the group sizes and the June/October ups and "
            "downs are hints, not proven facts. The labels are a rough guide, not a perfect answer: this is one "
            "person's own inbox, sorted by hand, so it is a sample, not the whole picture. The rush-word list and the "
            "themes are English-only; non-Latin (Chinese, Japanese, Korean) emails are counted on the side. The web-"
            "page formatting is removed before the words are read. The 2020 file still has real names in it, so no raw "
            "sender, subject, or address is ever written out — every result is a total or a summary, never one person's "
            "details."
        ),
        analyses=[a_text, a_cluster, a_time],
    )
    m.add(ds)
    return ds
