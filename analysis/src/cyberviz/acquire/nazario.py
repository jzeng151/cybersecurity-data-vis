"""Nazario phishing corpus — Jose Nazario's hand-curated archive of real phishing emails, in
Unix mbox format. One message per record: RFC-822 headers + (usually HTML) body. Single-class
(every message is phishing). Open HTTP, no auth. We pin the 2020 year-file.

Note: the 2020 file is non-anonymized (real domains/IPs). Downstream analysis must avoid
re-exposing sender/victim PII in any published artifact.
"""
from __future__ import annotations

import mailbox
from email.header import decode_header, make_header
from pathlib import Path

import pandas as pd

from .. import paths
from .registry import fetch

_URL = "https://monkey.org/~jose/phishing/phishing-2020"
_DIR = paths.DATA_RAW / "nazario"


def acquire() -> dict[str, Path]:
    return {"mbox": fetch(_URL, _DIR / "phishing-2020.mbox", "nazario.2020")}


def _decode(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _body_text(msg: mailbox.mboxMessage) -> str:
    """Best-effort plain text: prefer text/plain, else strip tags off the first text/html part."""
    parts = msg.walk() if msg.is_multipart() else [msg]
    html = None
    for part in parts:
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            payload = part.get_payload(decode=True)
            text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        except Exception:
            continue
        if ctype == "text/plain":
            return text
        html = html or text
    if html is None:
        return ""
    import re
    return re.sub(r"<[^>]+>", " ", html)


def load() -> pd.DataFrame:
    """Parse the mbox into a tidy frame: one row per message (headers + extracted body)."""
    mbox = mailbox.mbox(str(acquire()["mbox"]))
    records = []
    for msg in mbox:
        records.append({
            "from": _decode(msg.get("From")),
            "subject": _decode(msg.get("Subject")),
            "date": msg.get("Date"),
            "content_type": msg.get_content_type(),
            "is_multipart": msg.is_multipart(),
            "body": _body_text(msg),
        })
    df = pd.DataFrame(records)
    df["date"] = pd.to_datetime(df["date"], errors="coerce", utc=True)
    return df


if __name__ == "__main__":
    df = load()
    print(df.shape, df.columns.tolist())
    print(df["subject"].head(5).tolist())
