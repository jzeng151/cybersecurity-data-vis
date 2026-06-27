"""Schema / round-trip tests for the dataset-centric emitter — the contract both sides depend on."""
from __future__ import annotations

import json

import pandas as pd
import pytest

from cyberviz import artifacts, paths
from cyberviz.artifacts import Analysis, Dataset, Metric


@pytest.fixture
def tmp_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "ARTIFACTS_DIR", tmp_path)
    monkeypatch.setattr(paths, "TABLES_DIR", tmp_path / "tables")
    monkeypatch.setattr(paths, "SERIES_DIR", tmp_path / "series")
    monkeypatch.setattr(paths, "SPECS_DIR", tmp_path / "specs")
    for d in (paths.TABLES_DIR, paths.SERIES_DIR, paths.SPECS_DIR):
        d.mkdir(parents=True, exist_ok=True)
    return tmp_path


def _analysis(**over) -> Analysis:
    """A valid Analysis whose referenced files have been written under tmp_artifacts."""
    sid = artifacts.write_json("ds.cluster.summary", {"a": 1})
    spid = artifacts.write_spec("ds.cluster.scatter", {"mark": "point"})
    kw = dict(
        technique="cluster", title="t", finding="f", fit="strong",
        storage=[sid], spec=spid, metrics=[Metric("n", "3")],
    )
    kw.update(over)
    return Analysis(**kw)


def _dataset(**over) -> Dataset:
    kw = dict(
        id="ds", display_name="DS", doc_category="network-flow", what_it_is="rows",
        source={"name": "src", "url": "http://x", "license": "CC0"},
        isolated_insight="this dataset says X", solution_idea="build Y", honesty_notes="caveats",
        analyses=[_analysis()],
    )
    kw.update(over)
    return Dataset(**kw)


def test_write_and_manifest_roundtrip(tmp_artifacts):
    m = artifacts.Manifest()
    m.add(_dataset())
    out = m.flush()
    doc = json.loads(out.read_text())
    assert doc["schema_version"] == artifacts.SCHEMA_VERSION
    assert "thesis" not in doc                       # the old fused-thesis field is gone
    assert doc["datasets"][0]["id"] == "ds"
    a0 = doc["datasets"][0]["analyses"][0]
    assert a0["technique"] == "cluster"
    assert a0["metrics"][0] == {"label": "n", "value": "3"}


def test_validate_rejects_bad_technique(tmp_artifacts):
    with pytest.raises(AssertionError):
        _dataset(analyses=[_analysis(technique="bogus")]).validate()


def test_validate_rejects_bad_category(tmp_artifacts):
    with pytest.raises(AssertionError):
        _dataset(doc_category="not-a-category").validate()


def test_validate_rejects_missing_file(tmp_artifacts):
    bad = Analysis(technique="cluster", title="t", finding="f", fit="strong",
                   storage=["series/nope.json"])
    with pytest.raises(AssertionError):
        _dataset(analyses=[bad]).validate()


def test_validate_requires_insight_and_solution(tmp_artifacts):
    with pytest.raises(AssertionError):
        _dataset(isolated_insight="   ").validate()
    with pytest.raises(AssertionError):
        _dataset(solution_idea="").validate()


def test_validate_rejects_duplicate_technique_within_dataset(tmp_artifacts):
    with pytest.raises(AssertionError):
        _dataset(analyses=[_analysis(), _analysis()]).validate()


def test_duplicate_dataset_ids_rejected(tmp_artifacts):
    m = artifacts.Manifest()
    m.add(_dataset())
    m.add(_dataset())
    with pytest.raises(AssertionError):
        m.flush()
