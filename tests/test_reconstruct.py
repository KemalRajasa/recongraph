import json

import networkx as nx
import pandas as pd
import pytest

from recongraph.reconstruct import (compare, dfs_paths, is_feasible, load_graphs, main, node_sequence,
                                    parse_duration, replay_paths, resolve_node, time_respecting_paths)
from recongraph.recongraph import EdgeGraph


def _temporal(edges):
    """edges: [(u, v, t_src_us, t_dst_us, seq)]; a temporal graph shaped like EdgeGraph.T (None = no timestamp)."""
    T = nx.MultiDiGraph()
    for name in sorted({x for e in edges for x in e[:2]}):
        T.add_node(name, event=f"{name}. Event {name}[high]")
    for u, v, t_src, t_dst, seq in edges:
        attrs = {"seq": seq, "src_row": seq, "dst_row": seq + 1}
        attrs.update({k: t for k, t in (("t_src_us", t_src), ("t_dst_us", t_dst)) if t is not None})
        T.add_edge(u, v, **attrs)
    return T


def _nodes(T, paths):
    return [node_sequence(T, p) for p in paths]


def test_dfs_path_that_goes_back_in_time_is_impossible():
    T = _temporal([("A", "B", 10, 11, 1), ("B", "C", 5, 6, 0)])
    r = compare(T, nx.DiGraph(T), "A", "C")
    assert r["dfs"]["paths"] == [["A", "B", "C"]]
    assert r["time"]["paths"] == [] and r["replay"]["paths"] == []
    assert r["dfs"]["feasible"] == [False] and r["dfs_impossible_pct"] == 100.0


def test_revisiting_a_node_is_found_by_time_and_replay_not_dfs():
    T = _temporal([("A", "B", 1, 2, 0), ("B", "A", 2, 3, 1), ("A", "C", 3, 4, 2)])
    r = compare(T, nx.DiGraph(T), "A", "C")
    assert ["A", "B", "A", "C"] in _nodes(T, r["time"]["paths"])
    assert ["A", "B", "A", "C"] in _nodes(T, r["replay"]["paths"])
    assert r["dfs"]["paths"] == [["A", "C"]]


def test_dfs_has_no_path_from_a_node_to_itself():
    T = _temporal([("A", "B", 1, 2, 0), ("B", "A", 2, 3, 1)])
    assert dfs_paths(nx.DiGraph(T), "A", "A")[0] == []
    assert time_respecting_paths(T, "A", "A")[0] == [[0, 1]]


def test_max_gap_rejects_long_waits():
    T = _temporal([("A", "B", 0, 1, 0), ("B", "C", 100, 101, 1)])
    assert time_respecting_paths(T, "A", "C")[0] == [[0, 1]]
    assert time_respecting_paths(T, "A", "C", max_gap_us=99)[0] == [[0, 1]]
    assert time_respecting_paths(T, "A", "C", max_gap_us=98)[0] == []
    assert is_feasible(T, ["A", "B", "C"], max_gap_us=98) is False


def test_an_edge_is_used_at_most_once():
    one = _temporal([("A", "A", 5, 5, 0)])
    assert time_respecting_paths(one, "A", "A")[0] == [[0]]
    two = _temporal([("A", "A", 5, 5, 0), ("A", "A", 5, 5, 1)])
    assert sorted(time_respecting_paths(two, "A", "A")[0]) == [[0], [0, 1], [1], [1, 0]]


def test_max_len_limits_every_method():
    T = _temporal([("A", "B", 1, 2, 0), ("B", "C", 2, 3, 1), ("C", "D", 3, 4, 2)])
    A = nx.DiGraph(T)
    for max_len, expected in ((2, 0), (3, 1)):
        assert len(dfs_paths(A, "A", "D", max_len)[0]) == expected
        assert len(time_respecting_paths(T, "A", "D", max_len)[0]) == expected
        assert len(replay_paths(T, "A", "D", max_len)[0]) == expected


def test_cap_sets_truncated():
    T = _temporal([("A", "B", 1, 2, seq) for seq in range(5)])
    assert time_respecting_paths(T, "A", "B", cap=3) == ([[0], [1], [2]], True)
    assert time_respecting_paths(T, "A", "B", cap=5)[1] is False
    assert replay_paths(T, "A", "B", cap=3)[1] is True
    diamond = nx.DiGraph([("A", "B"), ("B", "D"), ("A", "C"), ("C", "D")])
    paths, truncated = dfs_paths(diamond, "A", "D", cap=1)
    assert len(paths) == 1 and truncated is True
    assert dfs_paths(diamond, "A", "D", cap=2)[1] is False


def test_untimed_transitions_are_skipped_by_time_but_not_replay():
    T = _temporal([("A", "B", None, 2, 0), ("B", "C", 2, 3, 1)])
    assert time_respecting_paths(T, "A", "C")[0] == []
    assert replay_paths(T, "A", "C")[0] == [[0, 1]]
    assert is_feasible(T, ["A", "B", "C"]) is False


def _edge_graph(labels, times, tmp_path):
    df = pd.DataFrame({"datetime": times, "message": [f"m{i}" for i in range(len(labels))], "sigma": labels})
    graph = EdgeGraph(df)
    graph.run_all(graph_output=str(tmp_path / "agg.graphml"), temporal_output=str(tmp_path / "temporal.graphml"))
    return graph


def test_replay_equals_time_respecting_on_a_straight_chain(tmp_path):
    labels = ["A[high]", "B[high]", "C[high]", "D[high]", "E[high]"]
    graph = _edge_graph(labels, [f"2024-01-01 10:0{i}:00" for i in range(5)], tmp_path)
    T, _ = load_graphs(graph)
    for i in range(len(labels)):
        for j in range(i + 1, len(labels)):
            src, dst = resolve_node(T, labels[i]), resolve_node(T, labels[j])
            assert time_respecting_paths(T, src, dst)[0] == replay_paths(T, src, dst)[0] != []


ROUND_TRIP = (["A[high]", "B[low]", "A[high]", "C[medium]", "B[low]", "D[high]", "A[high]"],
              ["2024-01-01 10:05:00", "2024-01-01 10:01:00", "", "2024-01-01 10:07:00",
               "2024-01-01 10:02:00", "2024-01-01 10:09:00", "2024-01-01 10:03:00"])


def _canonical(result):
    return {k: sorted(map(tuple, v["paths"])) if isinstance(v, dict) else v for k, v in result.items()}


def test_graphml_round_trip_matches_edge_graph(tmp_path):
    graph = _edge_graph(*ROUND_TRIP, tmp_path)
    from_object = load_graphs(graph)
    from_files = load_graphs(str(tmp_path / "temporal.graphml"), str(tmp_path / "agg.graphml"))
    assert sorted(from_object[0].nodes) == sorted(from_files[0].nodes)
    for src in from_object[0]:
        for dst in from_object[0]:
            a = compare(*from_object, src, dst, max_len=5)
            b = compare(*from_files, src, dst, max_len=5)
            assert _canonical(a) == _canonical(b), (src, dst)
            assert sorted(zip(map(tuple, a["dfs"]["paths"]), a["dfs"]["feasible"])) == \
                sorted(zip(map(tuple, b["dfs"]["paths"]), b["dfs"]["feasible"]))


def test_resolve_node_by_id_label_or_substring():
    T = _temporal([("A", "B", 1, 2, 0), ("B", "C", 2, 3, 1)])
    assert resolve_node(T, "A") == "A"
    assert resolve_node(T, "Event B[high]") == "B"
    assert resolve_node(T, "event c") == "C"
    with pytest.raises(ValueError, match="matches 3 nodes"):
        resolve_node(T, "Event")


def test_cli_compare_writes_json(tmp_path, capsys):
    _edge_graph(*ROUND_TRIP, tmp_path)
    out = tmp_path / "result.json"
    assert main(["--temporal", str(tmp_path / "temporal.graphml"), "--agg", str(tmp_path / "agg.graphml"),
                 "--src", "A[high]", "--dst", "D[high]", "--mode", "compare", "--max-len", "4",
                 "--max-gap", "10m", "--out", str(out)]) == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert {"dfs", "time", "replay", "dfs_impossible"} <= set(result)
    assert result["max_gap_us"] == 600_000_000
    assert all(step["t_src"] for path in result["time"]["paths"] for step in path)
    assert "A[high] -> D[high]" in capsys.readouterr().out


@pytest.mark.parametrize("text, us", [("60s", 60_000_000), ("500ms", 500_000), ("2m", 120_000_000),
                                      ("1h", 3_600_000_000), ("250us", 250), ("1.5", 1_500_000)])
def test_parse_duration(text, us):
    assert parse_duration(text) == us
