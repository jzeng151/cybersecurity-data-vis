"""UNSW-NB15 (train/test partition, 45 cols, labeled).

Source: Nir-J/ML-Projects GitHub mirror of the official ACCS train/test CSVs (verified to
carry the canonical 45-column schema). Non-Kaggle, directly downloadable. The official home
is research.unsw.edu.au/projects/unsw-nb15-dataset (CloudStor) and figshare 29149946 if this
mirror ever rots.
"""
from __future__ import annotations

from pathlib import Path

from .. import paths
from .registry import fetch

_BASE = "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification"
_DIR = paths.DATA_RAW / "unsw_nb15"


def acquire() -> dict[str, Path]:
    return {
        "train": fetch(f"{_BASE}/UNSW_NB15_training-set.csv", _DIR / "training-set.csv", "unsw_nb15.train"),
        "test": fetch(f"{_BASE}/UNSW_NB15_testing-set.csv", _DIR / "testing-set.csv", "unsw_nb15.test"),
    }


if __name__ == "__main__":
    for name, path in acquire().items():
        print(f"{name}: {path} ({path.stat().st_size:,} bytes)")
