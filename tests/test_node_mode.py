import json
import os
import subprocess
import sys
from importlib.metadata import PackageNotFoundError
from pathlib import Path

import networkx as nx
import pandas as pd
import pytest
from drain3 import TemplateMiner
from drain3.memory_buffer_persistence import MemoryBufferPersistence

from recongraph.event_identity import (DRAIN3_CONFIG, DRAIN3_MASKING, assign_event_keys, drain3_state,
                                       new_template_miner)
from recongraph.input_adapters import load_plaso_jsonl
from recongraph.reconstruct import compare, load_graphs, main as reconstruct_main, resolve_node
from recongraph.recongraph import EdgeGraph, ReconGraph, main

FIXTURES = Path(__file__).parent / "fixtures"
PLASO = FIXTURES / "plaso"
RULES = str(FIXTURES / "rules")
SAMPLE = FIXTURES / "plaso_sample.jsonl"
REPO = Path(__file__).parents[1]
EVTX_CSV = "[39 / 0x0027] Provider identifier: {f1ef270a-0d32-4352-ba52-dbab41e1d859} Source Name: Microsoft-Windows-AppModel-Runtime " \
           "Strings: ['x'] Computer Name: WinDev2311Eval Record Number: 253 Event Level: 4"


def _keys(path):
    return assign_event_keys(load_plaso_jsonl(path))[0]


def _run(tmp_path, input_file=SAMPLE, node_mode="drain", rules=RULES, **kwargs):
    """Full pipeline, strict; returns the output paths."""
    paths = {"graph_output": str(tmp_path / "agg.graphml"), "temporal_output": str(tmp_path / "temporal.graphml"),
             "csv_output": str(tmp_path / "events.csv")}
    ReconGraph(str(input_file), rules, flexible_mode=False, node_mode=node_mode, **kwargs).run_all(**paths)
    return paths


# Identity per kind of source

def test_evtx_key_is_provider_and_event_id():
    assert _keys(FIXTURES / "sysmon_lsass.jsonl") == ["Microsoft-Windows-Sysmon:10"]
    assert set(_keys(FIXTURES / "eventlog_cleared.jsonl")) == {"Microsoft-Windows-Eventlog:104"}


def test_evtx_node_count_equals_unique_provider_event_pairs(tmp_path):
    df = load_plaso_jsonl(SAMPLE)
    evtx = df[(df["parser"] == "winevtx") & df["Provider_Name"].notna()]
    pairs = set(zip(evtx["Provider_Name"], evtx["EventID"]))
    graph = EdgeGraph(evtx, node_mode="drain")
    graph.run_all(graph_output=str(tmp_path / "agg.graphml"))
    assert graph.G.number_of_nodes() == len(pairs) > 1
    assert set(graph.events_dict) == {f"{p}:{e}" for p, e in pairs}


@pytest.mark.parametrize("row, expected", [
    ({"Provider_Name": "P", "EventID": "1", "message": EVTX_CSV}, "P:1"),
    ({"message": EVTX_CSV}, "Microsoft-Windows-AppModel-Runtime:39"),  # CSV row, or unparsable XML in JSONL
    ({"message": "[0 / 0x0000] Provider identifier: {guid} Strings: []"}, "{guid}:0"),
    ({"message": "no sentence", "Channel": "System"}, "System:unknown"),
    ({"message": ""}, "unknown:unknown"),
])
def test_evtx_key_fallbacks(row, expected):
    assert assign_event_keys(pd.DataFrame([{"parser": "winevtx", **row}]))[0] == [expected]


def test_evtx_never_uses_drain3():
    assert assign_event_keys(load_plaso_jsonl(SAMPLE))[1]["miners"] == {}


@pytest.mark.parametrize("fixture, expected", [
    ("android_sms.jsonl", {"android:messaging:sms:Creation Time"}),
    ("filestat_image_dir.jsonl", {"fs:stat:Content Modification Time"}),
    ("filestat.jsonl", {"fs:stat:Content Modification Time", "fs:stat:Metadata Modification Time", "fs:stat:Last Access Time"}),
    ("android_calls.jsonl", {"android:event:call:Start Time", "android:event:call:End Time"}),
])
def test_structured_key_is_data_type_with_timestamp_meaning(fixture, expected):
    assert set(_keys(PLASO / fixture)) == expected


def test_structured_key_does_not_depend_on_the_rest_of_the_file():
    alone = [{"data_type": "fs:stat", "timestamp_desc": "A", "message": "x"}]
    mixed = alone + [{"data_type": "fs:stat", "timestamp_desc": "B", "message": "y"}]
    assert assign_event_keys(pd.DataFrame(alone))[0][0] == assign_event_keys(pd.DataFrame(mixed))[0][0] == "fs:stat:A"


def test_structured_ssh_events_do_not_use_drain3():
    keys = _keys(PLASO / "linux_auth.jsonl")
    assert {f"syslog:ssh:{kind}:Content Modification Time" for kind in ("login", "failed_connection", "opened_connection")} <= set(keys)


@pytest.mark.parametrize("fixture, expected", [
    ("android_logcat.jsonl", "android:logcat:test of threadtime w/ UTC and year"),
    ("ios_sysdiag.jsonl", "ios:sysdiag_log:entry:containermanagerd cleanup complete"),
    ("ios_logd.jsonl", 'ios:sysdiagnose:logd:line:Migrating: "<PATH>"'),
    ("ios_lockdownd.jsonl", "ios:lockdownd_log:entry:mglog: libMobileGestalt MGBasebandSupport.c:<NUM>: No IMEI in CT mobile equipment info dictionary"),
    ("linux_auth.jsonl", "syslog:line:Server listening on <IP> port <NUM>."),
])
def test_free_text_key_is_template_of_the_raw_line(fixture, expected):
    assert expected in _keys(PLASO / fixture)


@pytest.mark.parametrize("text, template", [
    ("from {f1ef270a-0d32-4352-ba52-dbab41e1d859} ok", "from <GUID> ok"),
    ("user S-1-5-21-1-2-3-500 ok", "user <SID> ok"),
    ("code 0x1F ok", "code <HEX> ok"),
    ("hash 00aabbccddeeff11 ok", "hash <HEX> ok"),
    ("mac 00:aa:bb:cc:dd:ee ok", "mac <HEX> ok"),
    ("ip 192.168.0.1 ok", "ip <IP> ok"),
    ("ip fe80::1 ok", "ip <IP> ok"),
    ("a :: b", "a :: b"),
    ("ip 2001:db8:0:0:0:0:0:1 ok", "ip <IP> ok"),
    ("open /var/log/auth.log ok", "open <PATH> ok"),
    (r"open C:\Windows\System32\cmd.exe ok", "open <PATH> ok"),
    ("took 42 ok", "took <NUM> ok"),
    ("at 10:20:30 ok", "at <NUM>:<NUM>:<NUM> ok"),
    ("words and/or words", "words and/or words"),
])
def test_masking(text, template):
    miner = new_template_miner()
    assert miner.add_log_message(text)["template_mined"] == template


def test_drain3_is_per_data_type():
    rows = [{"data_type": dt, "message_body": f"service started on port {n}"}
            for dt, n in (("syslog:line", 1), ("android:logcat", 2))]
    keys, meta, _ = assign_event_keys(pd.DataFrame(rows))
    assert keys == ["syslog:line:service started on port <NUM>", "android:logcat:service started on port <NUM>"]
    assert sorted(meta["miners"]) == ["android:logcat", "syslog:line"]


def test_drain3_reads_the_raw_text_not_the_formatter_sentence():
    rows = [{"data_type": "syslog:line", "message": "[sshd, pid: 3] hello world", "message_body": "hello world"}]
    assert assign_event_keys(pd.DataFrame(rows))[0] == ["syslog:line:hello world"]


def test_body_column_and_formatter_fallback():
    rows = [{"data_type": "systemd:journal", "body": "a b c"}, {"data_type": "syslog:line", "message": "only formatted"}]
    assert assign_event_keys(pd.DataFrame(rows))[0] == ["systemd:journal:a b c", "syslog:line:only formatted"]


def test_two_stages_give_early_rows_the_final_template():
    # online Drain3 would give the first row the template "login user alice"
    rows = [{"data_type": "syslog:line", "message_body": f"login user {name}"} for name in ("alice", "bob", "carol")]
    assert set(assign_event_keys(pd.DataFrame(rows))[0]) == {"syslog:line:login user <*>"}


def test_template_does_not_depend_on_row_order():
    names = ("alice", "bob", "carol")
    rows = [{"data_type": "syslog:line", "message_body": f"login user {name}"} for name in names]
    assert assign_event_keys(pd.DataFrame(rows))[0] == assign_event_keys(pd.DataFrame(rows[::-1]))[0]


def test_structured_row_without_timestamp_meaning_keeps_its_source_as_key():
    df = pd.DataFrame({"data_type": ["fs:stat"] * 3, "timestamp_desc": ["A", "B", None], "message": ["x"] * 3})
    assert assign_event_keys(df)[0] == ["fs:stat:A", "fs:stat:B", "fs:stat"]


def test_row_without_text_keeps_its_source_as_key():
    assert assign_event_keys(pd.DataFrame([{"data_type": "syslog:line", "message": ""}]))[0] == ["syslog:line"]


def test_key_drops_characters_graphml_cannot_hold(tmp_path):
    df = pd.DataFrame([{"datetime": "2024-01-01T00:00:00+00:00", "data_type": "syslog:line", "message": "bad\x01text", "message_body": "bad\x01text"}])
    graph = EdgeGraph(df, node_mode="drain")
    graph.run_all(graph_output=str(tmp_path / "agg.graphml"))
    assert list(graph.events_dict) == ["syslog:line:badtext"]
    assert nx.read_graphml(tmp_path / "agg.graphml").nodes["0"]["message"] == "badtext"


# Plaso CSV and plain text input

def test_csv_evtx_uses_the_formatter_sentence_and_no_drain3():
    df = pd.DataFrame([{"parser": "winevtx", "message": EVTX_CSV, "timestamp_desc": "Creation Time"}])
    keys, meta, _ = assign_event_keys(df)
    assert keys == ["Microsoft-Windows-AppModel-Runtime:39"] and meta["miners"] == {}


def test_csv_structured_key_is_parser_and_text_parser_uses_drain3():
    df = pd.DataFrame([
        {"parser": "usnjrnl", "timestamp_desc": "Metadata Modification Time", "message": "a"},
        {"parser": "filestat", "timestamp_desc": "Last Access Time", "message": "b"},
        {"parser": "filestat", "timestamp_desc": "Creation Time", "message": "c"},
        {"parser": "text/syslog_traditional", "timestamp_desc": "Content Modification Time", "message": "listening on port 22"},
    ])
    assert assign_event_keys(df)[0] == ["usnjrnl:Metadata Modification Time", "filestat:Last Access Time", "filestat:Creation Time",
                                        "text/syslog_traditional:listening on port <NUM>"]


def test_sample_csv_maps_every_row_with_evtx_key(tmp_path):
    csv = REPO / "dataset" / "1" / "failed-login.csv"
    paths = _run(tmp_path, csv, rules=None)
    source = pd.read_csv(csv, dtype=str)
    meta = json.loads(Path(paths["graph_output"] + ".meta.json").read_text(encoding="utf-8"))
    assert meta["rows_in_graph"] == meta["rows_total"] == len(source)
    assert meta["drain3"]["miners"] == {}
    events = pd.read_csv(paths["csv_output"], dtype=str)
    evtx = events[events["row_index"].astype(int).map(source["parser"].eq("winevtx"))]
    assert evtx["event_key"].str.fullmatch(r"[^:]+:\d+").all()


def test_plain_text_input_is_free_text(tmp_path):
    log = tmp_path / "app.txt"
    log.write_text("started worker 1\nstarted worker 2\nstopped\n", encoding="utf-8")
    graph = EdgeGraph(pd.DataFrame({"description": log.read_text().splitlines()}), node_mode="drain")
    assert set(graph.df["event_key"]) == {"text:started worker <NUM>", "text:stopped"}


# --node=sigma is the base behavior

@pytest.mark.parametrize("fixture", ["sysmon_lsass", "plaso_sample"])
def test_sigma_mode_identical_to_base(tmp_path, fixture):
    """Golden: GraphML written by commit f429c3d (patch 09), before --node existed."""
    paths = _run(tmp_path, FIXTURES / f"{fixture}.jsonl", node_mode="sigma")
    golden = FIXTURES / "node_mode"
    for name, written in ((f"{fixture}.graphml", paths["graph_output"]), (f"{fixture}.temporal.graphml", paths["temporal_output"])):
        assert Path(written).read_bytes().replace(b"\r\n", b"\n") == (golden / name).read_bytes().replace(b"\r\n", b"\n")


def test_sigma_mode_maps_only_labeled_rows(tmp_path):
    paths = _run(tmp_path, node_mode="sigma")
    meta = json.loads(Path(paths["graph_output"] + ".meta.json").read_text(encoding="utf-8"))
    assert meta["rows_in_graph"] < meta["rows_total"]
    assert meta["drain3"] is None and meta["event_sources"] is None
    node = next(iter(nx.read_graphml(paths["graph_output"]).nodes(data=True)))[1]
    assert "level" in node and "row_count" not in node and "sigma_hits" not in node


def test_edge_graph_defaults_to_sigma_and_validates_node_mode():
    assert EdgeGraph(pd.DataFrame({"message": ["m"], "sigma": ["A[low]"]})).node_mode == "sigma"
    with pytest.raises(ValueError, match="node_mode"):
        EdgeGraph(pd.DataFrame(), node_mode="other")


# --node=drain: every row, Sigma as annotation

def test_drain_maps_every_row_with_temporal_edges(tmp_path):
    paths = _run(tmp_path)
    df = load_plaso_jsonl(SAMPLE)
    temporal = nx.read_graphml(paths["temporal_output"])
    assert temporal.number_of_edges() == len(df) - 1
    assert sum(d["row_count"] for _, d in temporal.nodes(data=True)) == len(df)
    edge = next(d for _, _, d in temporal.edges(data=True) if "delta_us" in d)
    assert {"seq", "src_row", "dst_row", "t_src", "t_dst", "t_src_us", "t_dst_us", "delta_us"} <= set(edge)


def _annotated_frame():
    return pd.DataFrame({
        "datetime": [f"2024-01-01T00:00:0{i}+00:00" for i in range(4)],
        "parser": ["winevtx"] * 4,
        "Provider_Name": ["P", "P", "P", "Q"],
        "EventID": ["1", "1", "1", "2"],
        "message": ["a", "b", "c", "d"],
        "sigma": ["R1[high]", "", "R3[low]", ""],
        "sigma_all": ["R0[low] | R1[high]", "", "R3[low]", ""],
    })


def test_sigma_annotation_is_aggregated_per_node(tmp_path):
    graph = EdgeGraph(_annotated_frame(), node_mode="drain")
    graph.run_all(graph_output=str(tmp_path / "agg.graphml"))
    written = nx.read_graphml(tmp_path / "agg.graphml")
    p, q = written.nodes["0"], written.nodes["1"]
    assert (p["event_key"], p["row_count"], p["log_count"], p["sigma_hits"]) == ("P:1", 3, 3, 2)
    assert p["sigma_rules"] == "R0[low] | R1[high] | R3[low]"
    assert p["sigma_max_level"] == "high"
    assert "level" not in p
    assert (q["event_key"], q["row_count"], q["sigma_hits"], q["sigma_rules"], q["sigma_max_level"]) == ("Q:2", 1, 0, "", "")


def test_sigma_annotation_stays_on_the_row(tmp_path):
    graph = EdgeGraph(_annotated_frame(), node_mode="drain")
    graph.run_all(graph_output=str(tmp_path / "agg.graphml"), temporal_output=str(tmp_path / "t.graphml"),
                  csv_output=str(tmp_path / "events.csv"))
    events = pd.read_csv(tmp_path / "events.csv", dtype=str, keep_default_na=False).sort_values("row_index")
    assert events["event_key"].tolist() == ["P:1", "P:1", "P:1", "Q:2"]
    assert events["sigma"].tolist() == ["R1[high]", "", "R3[low]", ""]
    assert events["sigma_all"].tolist() == ["R0[low] | R1[high]", "", "R3[low]", ""]
    assert events["level"].tolist() == ["high", "", "low", ""]
    edges = sorted(nx.read_graphml(tmp_path / "t.graphml").edges(data=True), key=lambda e: e[2]["seq"])
    assert [(d["src_level"], d["dst_level"]) for _, _, d in edges] == [("high", ""), ("", "low"), ("low", "")]


def test_sigma_still_runs_in_drain_mode(tmp_path):
    paths = _run(tmp_path)
    written = nx.read_graphml(paths["graph_output"])
    assert sum(d["sigma_hits"] for _, d in written.nodes(data=True)) > 0


def test_export_sigma_carries_event_key_in_drain_mode(tmp_path):
    out = tmp_path / "labeled.csv"
    ReconGraph(str(SAMPLE), RULES, flexible_mode=False).run_all(graph_output=str(tmp_path / "a.graphml"), sigma_output=str(out))
    assert {"event_key", "sigma", "sigma_all", "sigma_level"} <= set(pd.read_csv(out).columns)


def test_input_column_named_level_is_kept(tmp_path):
    graph = EdgeGraph(pd.DataFrame({"data_type": ["macos:asl:entry"], "message": ["m"], "level": ["Notice"], "sigma": ["R[high]"]}), node_mode="drain")
    assert graph.df["level"].tolist() == ["Notice"]
    assert graph.df["sigma_level"].tolist() == ["high"]


def test_export_sigma_unchanged_in_sigma_mode(tmp_path):
    out = tmp_path / "labeled.csv"
    ReconGraph(str(SAMPLE), RULES, flexible_mode=False, node_mode="sigma").run_all(graph_output=str(tmp_path / "a.graphml"), sigma_output=str(out))
    assert "event_key" not in pd.read_csv(out).columns


def test_export_has_event_key_in_sigma_mode(tmp_path):
    paths = _run(tmp_path, node_mode="sigma")
    events = pd.read_csv(paths["csv_output"])
    assert (events["event_key"] == events["event_name"]).all()


def test_source_without_sigma_rules_gets_a_graph_and_no_marker(tmp_path):
    paths = _run(tmp_path, PLASO / "android_sms.jsonl", rules=None)
    written = nx.read_graphml(paths["graph_output"])
    assert [d["event_key"] for _, d in written.nodes(data=True)] == ["android:messaging:sms:Creation Time"]
    assert next(iter(written.nodes(data=True)))[1]["sigma_hits"] == 0


# Metadata and reproducibility

def test_metadata_is_complete(tmp_path):
    paths = _run(tmp_path, PLASO / "linux_auth.jsonl", edge_order="file")
    for graph in (paths["graph_output"], paths["temporal_output"]):
        meta = json.loads(Path(graph + ".meta.json").read_text(encoding="utf-8"))
        assert meta["node_mode"] == "drain" and meta["edge_order"] == "file"
        assert meta["sigma_rules_path"] == RULES and meta["sigma_matching"] == "strict"
        assert meta["input_file"] == str(PLASO / "linux_auth.jsonl")
        assert meta["recongraph_version"] and meta["keep_all_timestamps"] is False
        assert meta["rows_in_graph"] == meta["rows_total"] == 6
        drain3 = meta["drain3"]
        assert drain3["version"] == "0.9.11"
        assert {k: drain3["config"][k] for k in DRAIN3_CONFIG} == DRAIN3_CONFIG
        assert [m["mask_with"] for m in drain3["config"]["masking"]] == [name for name, _ in DRAIN3_MASKING]
        assert list(drain3["miners"]) == ["syslog:line"]
        assert meta["event_sources"] == {
            "evtx": {},
            "structured": {"syslog:ssh:failed_connection": 1, "syslog:ssh:login": 2, "syslog:ssh:opened_connection": 1},
            "free_text": {"syslog:line": 2},
        }


def test_event_sources_account_for_every_row(tmp_path):
    paths = _run(tmp_path)
    meta = json.loads(Path(paths["graph_output"] + ".meta.json").read_text(encoding="utf-8"))
    sources = meta["event_sources"]
    assert list(sources["evtx"]) == ["windows:evtx:record"] and list(sources["structured"]) == ["fs:stat"]
    assert sum(n for counts in sources.values() for n in counts.values()) == meta["rows_total"]


def test_event_sources_of_a_csv_use_the_parser():
    df = pd.DataFrame([{"parser": "winevtx", "message": EVTX_CSV}, {"parser": "usnjrnl", "message": "a"},
                       {"parser": "text/syslog_traditional", "message": "b"}])
    assert assign_event_keys(df)[2] == {"evtx": {"winevtx": 1}, "structured": {"usnjrnl": 1}, "free_text": {"text/syslog_traditional": 1}}


def test_metadata_without_an_installed_package(tmp_path, monkeypatch):
    def not_installed(name):
        raise PackageNotFoundError(name)
    monkeypatch.setattr("recongraph.recongraph.version", not_installed)
    paths = _run(tmp_path, PLASO / "android_sms.jsonl", rules=None)
    assert json.loads(Path(paths["graph_output"] + ".meta.json").read_text(encoding="utf-8"))["recongraph_version"] == "unknown"


def test_snapshot_restores_the_miner(tmp_path):
    miner = new_template_miner()
    miner.add_log_message("login user alice")
    miner.add_log_message("login user bob")
    persistence = MemoryBufferPersistence()
    persistence.save_state(drain3_state(miner).encode("utf-8"))
    restored = TemplateMiner(persistence, new_template_miner().config)
    assert restored.match("login user carol", "always").get_template() == "login user <*>"


@pytest.mark.parametrize("input_file", [PLASO / "linux_auth.jsonl", SAMPLE, PLASO / "ios_lockdownd.jsonl"], ids=lambda p: p.stem)
def test_same_configuration_gives_the_same_output(tmp_path, input_file):
    outputs = []
    for run in ("one", "two"):
        out = tmp_path / run
        out.mkdir()
        outputs.append(_run(out, input_file))
    for name in ("graph_output", "temporal_output", "csv_output"):
        assert Path(outputs[0][name]).read_bytes() == Path(outputs[1][name]).read_bytes()
    assert Path(outputs[0]["graph_output"] + ".meta.json").read_bytes() == Path(outputs[1]["graph_output"] + ".meta.json").read_bytes()


def test_same_output_across_processes(tmp_path):
    """Hash randomization differs per process; identity and GraphML must not depend on it."""
    outputs = []
    for run in ("1", "2"):
        path = tmp_path / run / "g.graphml"
        path.parent.mkdir()
        subprocess.run([sys.executable, "-m", "recongraph.recongraph", "-f", str(PLASO / "linux_auth.jsonl"), "-o", str(path)],
                       check=True, capture_output=True, env={**os.environ, "PYTHONHASHSEED": run})
        outputs.append((path.read_bytes(), Path(f"{path}.meta.json").read_bytes()))
    assert outputs[0] == outputs[1]


# CLI

def test_cli_default_is_drain(tmp_path, monkeypatch):
    out = tmp_path / "g.graphml"
    monkeypatch.setattr(sys, "argv", ["recongraph", "-f", str(PLASO / "android_sms.jsonl"), "-o", str(out)])
    main()
    assert json.loads(Path(f"{out}.meta.json").read_text(encoding="utf-8"))["node_mode"] == "drain"


def test_cli_rejects_unknown_node_mode(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["recongraph", "-f", str(SAMPLE), "--node", "other"])
    with pytest.raises(SystemExit):
        main()
    assert "invalid choice" in capsys.readouterr().err


def test_cli_help_explains_node(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["recongraph", "--help"])
    with pytest.raises(SystemExit):
        main()
    assert "--node {drain,sigma}" in capsys.readouterr().out


# reconstruct.py on a drain graph

def test_reconstruct_on_drain_temporal_graph(tmp_path):
    paths = _run(tmp_path, PLASO / "linux_auth.jsonl")
    T, A = load_graphs(paths["temporal_output"], paths["graph_output"])
    src = resolve_node(T, "syslog:ssh:opened_connection")
    dst = resolve_node(T, "Server listening")
    result = compare(T, A, src, dst)
    assert {"dfs", "time", "replay"} <= set(result)
    out = tmp_path / "paths.json"
    assert reconstruct_main(["--temporal", paths["temporal_output"], "--agg", paths["graph_output"], "--src", "syslog:ssh:login",
                             "--dst", "syslog:ssh:failed_connection", "--out", str(out)]) == 0
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["src_label"] == "syslog:ssh:login:Content Modification Time"
    assert written["dst_label"] == "syslog:ssh:failed_connection:Content Modification Time"
    assert written["time"]["paths"]
    for path in written["time"]["paths"]:
        assert all(a["t_dst"] <= b["t_src"] for a, b in zip(path, path[1:]))
