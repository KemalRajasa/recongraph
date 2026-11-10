"""The CLI writes one run to one folder, with fixed file names."""
import json
import sys
from pathlib import Path

import networkx as nx
import pytest

from recongraph.recongraph import main

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE = FIXTURES / "plaso_sample.jsonl"
RULES = str(FIXTURES / "rules")
GRAPHS = {"recongraph_agg.graphml", "recongraph_temporal.graphml"}
ALWAYS = GRAPHS | {"recongraph_meta.json"}
EVENTS, SIGMA = "recongraph_events.csv", "recongraph_sigma.csv"


def _cli(monkeypatch, *args, input_file=SAMPLE):
    monkeypatch.setattr(sys, "argv", ["recongraph", "-f", str(input_file), "-r", RULES, "--strict", *args])
    main()


def _names(folder):
    return {path.name for path in folder.iterdir()}


@pytest.mark.parametrize("node_mode", ["drain", "sigma"])
def test_default_folder_has_both_graphs_and_metadata(tmp_path, monkeypatch, node_mode):
    monkeypatch.chdir(tmp_path)
    _cli(monkeypatch, "--node", node_mode)
    folder = tmp_path / "recongraph_output" / f"{SAMPLE.stem}_{node_mode}"
    assert _names(folder) == ALWAYS
    assert json.loads((folder / "recongraph_meta.json").read_text(encoding="utf-8"))["node_mode"] == node_mode
    temporal = nx.read_graphml(folder / "recongraph_temporal.graphml")
    assert temporal.number_of_edges() and all("seq" in data for *_, data in temporal.edges(data=True))


def test_output_dir_is_created_and_holds_every_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / "a" / "b"
    _cli(monkeypatch, "-o", str(folder), "--export-events", "--export-sigma")
    assert _names(folder) == ALWAYS | {EVENTS, SIGMA}
    assert _names(tmp_path) == {"a"}


def test_each_csv_needs_its_own_flag(tmp_path, monkeypatch):
    _cli(monkeypatch, "-o", str(tmp_path / "events"), "--export-events")
    _cli(monkeypatch, "-o", str(tmp_path / "sigma"), "--export-sigma")
    assert _names(tmp_path / "events") == ALWAYS | {EVENTS}
    assert _names(tmp_path / "sigma") == ALWAYS | {SIGMA}


def test_earlier_run_is_kept_without_overwrite(tmp_path, monkeypatch, capsys):
    folder = tmp_path / "run"
    _cli(monkeypatch, "-o", str(folder))
    before = {name: (folder / name).read_bytes() for name in ALWAYS}
    with pytest.raises(SystemExit):
        _cli(monkeypatch, "-o", str(folder), "--node", "sigma")
    assert "already contains output" in capsys.readouterr().err
    assert {name: (folder / name).read_bytes() for name in ALWAYS} == before


def test_other_files_in_the_folder_are_not_a_conflict(tmp_path, monkeypatch):
    (tmp_path / "notes.txt").write_text("keep", encoding="utf-8")
    _cli(monkeypatch, "-o", str(tmp_path))
    assert _names(tmp_path) == ALWAYS | {"notes.txt"}


def test_overwrite_replaces_the_run_and_keeps_other_files(tmp_path, monkeypatch):
    _cli(monkeypatch, "-o", str(tmp_path), "--export-events", "--export-sigma")
    (tmp_path / "notes.txt").write_text("keep", encoding="utf-8")
    _cli(monkeypatch, "-o", str(tmp_path), "--node", "sigma", "--overwrite")
    assert _names(tmp_path) == ALWAYS | {"notes.txt"}
    assert json.loads((tmp_path / "recongraph_meta.json").read_text(encoding="utf-8"))["node_mode"] == "sigma"


def test_run_without_detections_writes_empty_graphs(tmp_path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    folder = tmp_path / "run"
    monkeypatch.setattr(sys, "argv", ["recongraph", "-f", str(SAMPLE), "-r", str(rules), "--node", "sigma", "-o", str(folder)])
    main()
    assert _names(folder) == ALWAYS
    assert all(nx.read_graphml(folder / name).number_of_nodes() == 0 for name in GRAPHS)
    assert json.loads((folder / "recongraph_meta.json").read_text(encoding="utf-8"))["rows_in_graph"] == 0


def test_output_must_be_a_folder(tmp_path, monkeypatch, capsys):
    with pytest.raises(SystemExit):
        _cli(monkeypatch, "-o", str(tmp_path / "result.graphml"))
    assert "takes a folder" in capsys.readouterr().err
    assert not (tmp_path / "result.graphml").exists()

    taken = tmp_path / "file"
    taken.write_text("x", encoding="utf-8")
    with pytest.raises(SystemExit):
        _cli(monkeypatch, "-o", str(taken))
    assert "not a folder" in capsys.readouterr().err
    assert taken.read_text(encoding="utf-8") == "x"


@pytest.mark.parametrize("removed", [["--temporal-output", "t.graphml"], ["--export-csv"], ["--export-sigma", "labeled.csv"]])
def test_removed_arguments_are_rejected(tmp_path, monkeypatch, removed):
    with pytest.raises(SystemExit):
        _cli(monkeypatch, "-o", str(tmp_path / "run"), *removed)
    assert not (tmp_path / "run").exists()
