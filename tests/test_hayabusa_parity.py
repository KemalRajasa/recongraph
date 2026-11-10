"""Rule selection, sigma_ids, null semantics and run metadata used to compare ReconGraph with Hayabusa."""
import json
import sys
from pathlib import Path

import pandas as pd
import pytest
import yaml

from recongraph.recongraph import ReconGraph, SigmaLabel, SigmaMatcher, SigmaRulesLoader, main, read_rule_id_list

FIXTURES = Path(__file__).parent / "fixtures"
SYSMON_JSONL = FIXTURES / "sysmon_lsass.jsonl"

ID_A = "aaaaaaaa-0000-0000-0000-000000000001"
ID_B = "bbbbbbbb-0000-0000-0000-000000000002"
ID_C = "cccccccc-0000-0000-0000-000000000003"
ID_D = "dddddddd-0000-0000-0000-000000000004"


def _write_rule(rules, name, rule_id, status="test", title=None, detection=None):
    rules.mkdir(exist_ok=True)
    (rules / f"{name}.yml").write_text(yaml.safe_dump({
        "title": title or name, "id": rule_id, "status": status, "level": "high",
        "logsource": {"product": "windows"},
        "detection": detection or {"selection": {"EventID": "10"}, "condition": "selection"},
    }), encoding="utf-8")


@pytest.fixture
def rules(tmp_path):
    path = tmp_path / "rules"
    _write_rule(path, "active", ID_A)
    _write_rule(path, "old", ID_B, status="deprecated")
    _write_rule(path, "bad", ID_C, status="unsupported")
    _write_rule(path, "listed", ID_D)
    return path


@pytest.fixture
def exclude_file(tmp_path):
    path = tmp_path / "exclude_rules.txt"
    path.write_text(f"# Replaced by other rules:\n{ID_D} # \"listed\" with an inline comment\n\nnot-a-uuid\n#{ID_A}\n", encoding="utf-8")
    return path


def _titles(loader):
    return sorted(m["title"] for m in loader.matchers)


# --- rule selection ---

def test_exclude_list_format(exclude_file):
    assert read_rule_id_list(exclude_file) == {ID_D}


def test_all_rules_load_by_default(rules):
    loader = SigmaRulesLoader(str(rules), flexible_mode=False)
    assert _titles(loader) == ["active", "bad", "listed", "old"]
    assert loader.skip_counts == {"status": 0, "exclude_list": 0, "unsupported_modifier": 0, "invalid": 0}


def test_exclude_status(rules):
    loader = SigmaRulesLoader(str(rules), flexible_mode=False, exclude_status=["deprecated", "unsupported"])
    assert _titles(loader) == ["active", "listed"]
    assert loader.skip_counts["status"] == 2
    assert loader.summary()["skipped_by_status"] == {"deprecated": 1, "unsupported": 1}


def test_exclude_rules_file(rules, exclude_file):
    loader = SigmaRulesLoader(str(rules), flexible_mode=False, exclude_rules_file=str(exclude_file))
    assert _titles(loader) == ["active", "bad", "old"]
    assert loader.skip_counts["exclude_list"] == 1


def test_excluded_rule_counts_as_excluded_whatever_its_status(tmp_path):
    path = tmp_path / "rules"
    _write_rule(path, "both", ID_D, status="deprecated")
    exclude = tmp_path / "exclude.txt"
    exclude.write_text(f"{ID_D}\n", encoding="utf-8")
    loader = SigmaRulesLoader(str(path), flexible_mode=False, exclude_status=["deprecated"], exclude_rules_file=str(exclude))
    assert loader.skip_counts["exclude_list"] == 1 and loader.skip_counts["status"] == 0


def test_filtered_rule_is_not_counted_as_unsupported_modifier(tmp_path):
    path = tmp_path / "rules"
    wide = {"selection": {"CommandLine|wide|base64": "x"}, "condition": "selection"}
    _write_rule(path, "old_wide", ID_B, status="deprecated", detection=wide)
    _write_rule(path, "new_wide", ID_A, detection=wide)
    loader = SigmaRulesLoader(str(path), flexible_mode=False, exclude_status=["deprecated"])
    assert loader.skip_counts["status"] == 1 and loader.skip_counts["unsupported_modifier"] == 1


def test_unparsable_rule_is_counted(tmp_path):
    path = tmp_path / "rules"
    _write_rule(path, "fine", ID_A)
    (path / "broken.yml").write_text("title: [unclosed\n", encoding="utf-8")
    loader = SigmaRulesLoader(str(path), flexible_mode=False)
    assert _titles(loader) == ["fine"] and loader.skip_counts["invalid"] == 1


# --- sigma_ids ---

def _label_sysmon(rules_dir):
    return SigmaLabel(str(SYSMON_JSONL), str(rules_dir), flexible_mode=False).run()


def _hits(df):
    return df[df["sigma_ids"] != ""]


def test_sigma_ids_sorted_and_labels_unchanged(tmp_path):
    path = tmp_path / "rules"
    # same title and level: one label in sigma_all, two IDs in sigma_ids
    _write_rule(path, "z_second", ID_B, title="Same")
    _write_rule(path, "a_first", ID_D, title="Same")
    _write_rule(path, "m_other", ID_A, title="Other")
    df = _label_sysmon(path)
    assert not _hits(df).empty
    assert set(_hits(df)["sigma_ids"]) == {f"{ID_A} | {ID_B} | {ID_D}"}
    assert set(_hits(df)["sigma_all"]) == {"Other[high] | Same[high]"}
    assert set(_hits(df)["sigma"]) == {"Other[high]"}
    assert (df[df["sigma_ids"] == ""]["sigma_all"] == "").all()


def test_sigma_ids_is_added_after_the_existing_columns(rules):
    df = _label_sysmon(rules)
    assert list(df.columns)[-6:] == ["logsource", "sigma", "sigma_all", "sigma_ids", "sigma_tactics", "sigma_techniques"]


# --- null semantics ---

def _null_rule(tmp_path, condition="selection", detection=None):
    path = tmp_path / "rule.yml"
    path.write_text(yaml.safe_dump({"title": "Null", "logsource": {"product": "windows"},
                                    "detection": {"selection": {"StartModule": None}, **(detection or {}), "condition": condition}}), encoding="utf-8")
    return SigmaMatcher(str(path), flexible_mode=False)


def _entry(**fields):
    return {"desc": "x", "log_type": ["windows", "sysmon"], "EventID": "8", **fields}


def test_null_matches_missing_field_only(tmp_path):
    rule = _null_rule(tmp_path)
    assert rule.match(_entry()) is True
    assert rule.match(_entry(StartModule="")) is False
    assert rule.match(_entry(StartModule="C:\\x.dll")) is False


def test_negated_null_with_empty_field_fires(tmp_path):
    rule = _null_rule(tmp_path, condition="sel_event and not selection", detection={"sel_event": {"EventID": "8"}})
    assert rule.match(_entry(StartModule="")) is True
    assert rule.match(_entry()) is False


# --- negated selections ---

def test_negated_selection_with_missing_fields_fires(tmp_path):
    rule = _null_rule(tmp_path, condition="sel_event and not filter",
                      detection={"sel_event": {"EventID": "8"}, "filter": {"Image|endswith": "\\good.exe"}})
    assert rule.match(_entry()) is True
    assert rule.match(_entry(Image=r"C:\x\good.exe")) is False
    assert rule.match(_entry(Image=r"C:\x\evil.exe")) is True


# --- run metadata and CLI ---

def _run_cli(tmp_path, monkeypatch, *extra):
    out = tmp_path / "g.graphml"
    sigma = tmp_path / "labeled.csv"
    monkeypatch.setattr(sys, "argv", ["recongraph", "-f", str(SYSMON_JSONL), "-o", str(out), "--strict", "--export-sigma", str(sigma), *extra])
    main()
    return json.loads(Path(f"{out}.meta.json").read_text(encoding="utf-8")), pd.read_csv(sigma, dtype=str, keep_default_na=False)


def test_cli_writes_rule_selection_to_metadata(rules, exclude_file, tmp_path, monkeypatch):
    meta, df = _run_cli(tmp_path, monkeypatch, "-r", str(rules), "--exclude-status", "deprecated, unsupported",
                        "--exclude-rules-file", str(exclude_file))
    assert meta["sigma_rules_path"] == str(rules)
    assert meta["sigma_rules"] == {
        "loaded": 1,
        "skipped": {"status": 2, "exclude_list": 1, "unsupported_modifier": 0, "invalid": 0},
        "skipped_by_status": {"deprecated": 1, "unsupported": 1},
        "exclude_status": ["deprecated", "unsupported"],
        "exclude_rules_file": str(exclude_file),
    }
    assert "sigma_ids" in df.columns and set(df["sigma_ids"]) <= {"", ID_A}


def test_cli_rejects_missing_exclude_file(rules, tmp_path, monkeypatch):
    with pytest.raises(SystemExit):
        _run_cli(tmp_path, monkeypatch, "-r", str(rules), "--exclude-rules-file", str(tmp_path / "missing.txt"))


def test_metadata_defaults_without_filters(rules, tmp_path):
    out = tmp_path / "g.graphml"
    ReconGraph(str(SYSMON_JSONL), str(rules), flexible_mode=False).run_all(graph_output=str(out))
    meta = json.loads(Path(f"{out}.meta.json").read_text(encoding="utf-8"))
    assert meta["sigma_rules"]["loaded"] == 4 and meta["sigma_rules"]["exclude_status"] == []
    assert meta["sigma_rules"]["exclude_rules_file"] is None
