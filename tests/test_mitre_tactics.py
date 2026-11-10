"""ATT&CK annotations: Sigma rule tags become tactics and techniques per row and per node."""
from pathlib import Path

import pandas as pd
import pytest
import yaml

from recongraph.recongraph import EdgeGraph, MITRE_TACTICS, SigmaLabel, join_tactics, join_techniques, mitre_annotations

SYSMON_JSONL = Path(__file__).parent / "fixtures" / "sysmon_lsass.jsonl"


# --- rule tags ---

def test_annotations_follow_the_tags_of_the_rule():
    tags = ["attack.persistence", "attack.execution", "attack.t1574.001", "attack.g0069", "attack.s0002",
            "attack.ds0005", "attack.defense_evasion", "car.2019-04-001", "sysmon"]
    assert mitre_annotations(tags) == (["Persistence", "Execution"], ["T1574.001", "G0069", "S0002"])


@pytest.mark.parametrize("tag", ["attack.stealth", "attack.defense-evasion"])
def test_defense_evasion_is_stealth(tag):
    assert mitre_annotations([tag]) == (["Stealth"], [])


@pytest.mark.parametrize("tags", [None, []])
def test_rule_without_tags(tags):
    assert mitre_annotations(tags) == ([], [])


def test_table_has_every_enterprise_tactic():
    assert len(set(MITRE_TACTICS.values())) == 15


def test_joined_tactics_are_unique_in_matrix_order():
    assert join_tactics(["Impact", "Reconnaissance", "Impact", "Stealth"]) == "Reconnaissance | Stealth | Impact"


def test_joined_techniques_are_unique_and_sorted():
    assert join_techniques(["T1059", "G0069", "T1059"]) == "G0069 | T1059"


# --- rows ---

def _write_rule(path, name, tags):
    path.mkdir(exist_ok=True)
    rule = {"title": name, "level": "high", "logsource": {"product": "windows"},
            "detection": {"selection": {"EventID": "10"}, "condition": "selection"}}
    (path / f"{name}.yml").write_text(yaml.safe_dump({**rule, **({"tags": tags} if tags else {})}), encoding="utf-8")


def _label(rules):
    return SigmaLabel(str(SYSMON_JSONL), str(rules), flexible_mode=False).run()


def test_row_has_the_union_of_every_matching_rule(tmp_path):
    rules = tmp_path / "rules"
    _write_rule(rules, "first", ["attack.stealth", "attack.t1055"])
    _write_rule(rules, "second", ["attack.execution", "attack.stealth", "attack.t1003.001"])
    hits = _label(rules).query("sigma_all != ''")
    assert not hits.empty
    assert set(hits["sigma_tactics"]) == {"Execution | Stealth"}
    assert set(hits["sigma_techniques"]) == {"T1003.001 | T1055"}


def test_matching_rule_without_tags_leaves_the_row_empty(tmp_path):
    rules = tmp_path / "rules"
    _write_rule(rules, "untagged", None)
    hits = _label(rules).query("sigma_all != ''")
    assert not hits.empty and set(hits["sigma_tactics"]) == {""} and set(hits["sigma_techniques"]) == {""}


# --- nodes ---

def _frame(**columns):
    return pd.DataFrame({
        "datetime": [f"2024-01-01T00:00:0{i}+00:00" for i in range(4)],
        "parser": ["winevtx"] * 4,
        "Provider_Name": ["P", "P", "P", "Q"],
        "EventID": ["1", "1", "1", "2"],
        "message": ["a", "b", "c", "d"],
        "sigma": ["R1[high]", "", "R1[high]", ""],
        "sigma_all": ["R1[high]", "", "R1[high]", ""],
        **columns,
    })


ANNOTATED = {"sigma_tactics": ["Stealth | Execution", "", "Persistence", ""], "sigma_techniques": ["T1059", "", "T1547 | T1059", ""]}


def _nodes(tmp_path, frame, mode):
    graph = EdgeGraph(frame, node_mode=mode)
    graph.run_all(graph_output=str(tmp_path / "agg.graphml"))
    return dict(graph.G.nodes(data=True))


@pytest.mark.parametrize("mode", ["drain", "sigma"])
def test_node_has_the_union_of_its_rows(tmp_path, mode):
    node = _nodes(tmp_path, _frame(**ANNOTATED), mode)[0]
    assert node["tactics"] == "Execution | Persistence | Stealth"
    assert node["techniques"] == "T1059 | T1547"


def test_drain_node_without_annotation_is_empty(tmp_path):
    node = _nodes(tmp_path, _frame(**ANNOTATED), "drain")[1]
    assert node["tactics"] == "" and node["techniques"] == ""


@pytest.mark.parametrize("mode", ["drain", "sigma"])
def test_frame_without_the_columns_is_empty(tmp_path, mode):
    node = _nodes(tmp_path, _frame(), mode)[0]
    assert node["tactics"] == "" and node["techniques"] == ""
