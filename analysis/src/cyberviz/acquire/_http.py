"""Shared download helper: streamed, idempotent, checksum-verified."""
from __future__ import annotations

import hashlib
from pathlib import Path

import requests
from tqdm import tqdm

CHUNK = 1 << 20  # 1 MiB


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path, *, expected_sha256: str | None = None, timeout: int = 120) -> Path:
    """Download url -> dest, streaming. Skips if dest already matches expected_sha256.

    Writes to a .part file then atomically renames, so an interrupted download never
    leaves a truncated file that looks complete.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and expected_sha256 and sha256_file(dest) == expected_sha256:
        return dest

    tmp = dest.with_suffix(dest.suffix + ".part")
    with requests.get(url, stream=True, timeout=timeout, headers={"User-Agent": "socfatigue/0.1"}) as r:
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        with open(tmp, "wb") as f, tqdm(total=total or None, unit="B", unit_scale=True, desc=dest.name) as bar:
            for chunk in r.iter_content(CHUNK):
                f.write(chunk)
                bar.update(len(chunk))
    tmp.replace(dest)

    if expected_sha256:
        actual = sha256_file(dest)
        if actual != expected_sha256:
            raise ValueError(f"checksum mismatch for {dest.name}: got {actual}, expected {expected_sha256}")
    return dest
