"""Checksum registry: record sha256 on first acquire, verify on every acquire after.

data/checksums.json is committed, so acquisition is reproducible and auditable without
committing the (large, gitignored) raw data itself.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import _http
from .. import paths

CHECKSUMS = paths.ANALYSIS_DIR / "data" / "checksums.json"


def _load() -> dict:
    return json.loads(CHECKSUMS.read_text()) if CHECKSUMS.exists() else {}


def _save(reg: dict) -> None:
    CHECKSUMS.write_text(json.dumps(reg, indent=2, sort_keys=True))


def fetch(url: str, dest: Path, key: str) -> Path:
    """Ensure dest exists (download only if missing), then verify-or-record its checksum."""
    reg = _load()
    rec = reg.get(key)
    if not dest.exists():
        _http.download(url, dest, expected_sha256=(rec or {}).get("sha256"))
    digest = _http.sha256_file(dest)
    if rec and rec.get("sha256") and rec["sha256"] != digest:
        raise ValueError(f"{key}: checksum mismatch on {dest.name} (expected {rec['sha256']}, got {digest})")
    if not rec:
        reg[key] = {"sha256": digest, "bytes": dest.stat().st_size, "url": url}
        _save(reg)
    return dest
