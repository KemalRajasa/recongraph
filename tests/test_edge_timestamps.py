import json
from pathlib import Path

import networkx as nx
import pandas as pd
import pytest

from recongraph.recongraph import EdgeGraph

FIXTURES = Path(__file__).parent / "fixtures"
MINUTE_US = 60_000_000


def _graph(rows, tmp_path, edge_order="time"):
    """rows: [(sigma label, datetime string)]; returns an EdgeGraph after the full pipeline."""
    df = pd.DataFrame({'datetime': [t for _, t in rows], 'message': [f"m{i}" for i in range(len(rows))],
                       'sigma': [s for s, _ in rows]})
    graph = EdgeGraph(df, edge_order=edge_order)
    graph.run_all(graph_output=str(tmp_path / "agg.graphml"), temporal_output=str(tmp_path / "temporal.graphml"),
                  csv_output=str(tmp_path / "events.csv"))
    return graph


def _named_edges(graph, edges):
    return [(graph.node_labels[u], graph.node_labels[v], d) for u, v, d in edges]


def _agg(graph, src, dst):
    return next(d for u, v, d in _named_edges(graph, graph.G.edges(data=True)) if (u, v) == (src, dst))


def _temporal(graph):
    return _named_edges(graph, graph.temporal_edges)


ABABC = [("A", "2024-01-01 10:00:00"), ("B", "2024-01-01 10:01:00"), ("A", "2024-01-01 10:05:00"),
         ("B", "2024-01-01 10:06:00"), ("C", "2024-01-01 10:10:00")]


def test_aggregate_edge_times(tmp_path):
    ab = _agg(_graph(ABABC, tmp_path), "A", "B")
    assert ab['weight'] == 2
    assert ab['first_seen'] == "2024-01-01T10:00:00.000000+00:00"
    assert ab['last_seen'] == "2024-01-01T10:05:00.000000+00:00"
    assert ab['first_seen_us'] == pd.Timestamp("2024-01-01 10:00", tz="UTC").value // 1000
    assert ab['delta_min_us'] == ab['delta_median_us'] == ab['delta_max_us'] == MINUTE_US


def test_temporal_edges_per_transition(tmp_path):
    edges = _temporal(_graph(ABABC, tmp_path))
    assert [(u, v, d['seq'], d['delta_us']) for u, v, d in edges] == [
        ("A", "B", 0, MINUTE_US), ("B", "A", 1, 4 * MINUTE_US), ("A", "B", 2, MINUTE_US), ("B", "C", 3, 4 * MINUTE_US)]
    assert [(d['src_row'], d['dst_row']) for _, _, d in edges] == [(0, 1), (1, 2), (2, 3), (3, 4)]
    assert edges[1][2]['t_src'] == "2024-01-01T10:01:00.000000+00:00"
    assert edges[1][2]['t_dst'] == "2024-01-01T10:05:00.000000+00:00"


def test_node_first_and_last_seen(tmp_path):
    graph = _graph(ABABC, tmp_path)
    a = graph.G.nodes[graph.events_dict["A"]]
    assert a['timestamp'] == "2024-01-01 10:00:00"  # unchanged: first row's raw value
    assert (a['first_seen'], a['last_seen_us']) == ("2024-01-01T10:00:00.000000+00:00",
                                                    pd.Timestamp("2024-01-01 10:05", tz="UTC").value // 1000)


UNSORTED = [("A", "2024-01-01 10:05:00"), ("B", "2024-01-01 10:00:00"), ("C", "2024-01-01 10:10:00")]


def test_time_vs_file_order(tmp_path):
    time_edges = _temporal(_graph(UNSORTED, tmp_path, "time"))
    file_edges = _temporal(_graph(UNSORTED, tmp_path, "file"))
    assert [(u, v) for u, v, _ in time_edges] == [("B", "A"), ("A", "C")]
    assert [(u, v) for u, v, _ in file_edges] == [("A", "B"), ("B", "C")]
    assert all(d['delta_us'] >= 0 for _, _, d in time_edges)
    assert file_edges[0][2]['delta_us'] == -5 * MINUTE_US


def test_offsets_are_normalized_to_utc(tmp_path):
    rows = [("A", "2024-01-01T12:00:00+02:00"), ("B", "2024-01-01T10:30:00+00:00")]
    (u, v, d), = _temporal(_graph(rows, tmp_path))
    assert (u, v, d['t_src'], d['delta_us']) == ("A", "B", "2024-01-01T10:00:00.000000+00:00", 30 * MINUTE_US)


def test_ties_keep_row_order(tmp_path):
    rows = [("C", "2024-01-01 10:01:00"), ("A", "2024-01-01 10:00:00"), ("B", "2024-01-01 10:00:00")]
    edges = _temporal(_graph(rows, tmp_path))
    assert [(u, v, d['src_row'], d['dst_row']) for u, v, d in edges] == [("A", "B", 1, 2), ("B", "C", 2, 0)]


def test_missing_and_invalid_timestamps(tmp_path, caplog):
    rows = [("A", "2024-01-01 10:05:00"), ("X", ""), ("B", "2024-01-01 10:00:00"), ("Y", "not a date")]
    with caplog.at_level("INFO"):
        graph = _graph(rows, tmp_path)
    assert "2 labeled rows have an empty or invalid timestamp" in caplog.text
    edges = _temporal(graph)
    # an untimed row stays right after the row it follows in the file: B(10:00) Y A(10:05) X
    assert [(u, v) for u, v, _ in edges] == [("B", "Y"), ("Y", "A"), ("A", "X")]
    b_y, y_a, a_x = (d for _, _, d in edges)
    assert 't_src_us' in b_y and 't_dst' not in b_y and 'delta_us' not in b_y
    assert 't_src' not in y_a and 't_dst_us' in y_a and 'delta_us' not in y_a
    assert 't_src' in a_x and 't_dst_us' not in a_x
    x = graph.G.nodes[graph.events_dict["X"]]
    assert 'first_seen' not in x and 'first_seen_us' not in x
    assert 'delta_min_us' not in _agg(graph, "A", "X")


def test_all_timestamps_invalid_falls_back_to_file_order(tmp_path):
    rows = [("A", "10:00"), ("B", "10:01"), ("A", "10:02")]
    assert [(u, v) for u, v, _ in _temporal(_graph(rows, tmp_path))] == [("A", "B"), ("B", "A")]


def test_graphml_round_trip_types(tmp_path):
    graph = _graph(ABABC, tmp_path)
    agg = nx.read_graphml(tmp_path / "agg.graphml")
    temporal = nx.read_graphml(tmp_path / "temporal.graphml")
    _, _, ab = next((u, v, d) for u, v, d in agg.edges(data=True) if d['weight'] == 2)
    assert isinstance(ab['weight'], int) and isinstance(ab['delta_median_us'], int)
    assert isinstance(ab['first_seen'], str) and isinstance(ab['first_seen_us'], int)
    assert temporal.number_of_edges() == 4 and agg.number_of_edges() == 3
    for _, _, d in temporal.edges(data=True):
        assert all(isinstance(d[k], int) for k in ('seq', 't_src_us', 't_dst_us', 'delta_us', 'src_row', 'dst_row'))
        assert isinstance(d['t_src'], str)
    xml = (tmp_path / "temporal.graphml").read_text(encoding="utf-8")
    assert 'attr.name="t_src_us" attr.type="long"' in xml
    # weights equal the old row-order counting
    old = {}
    labels = [s for s, _ in ABABC]
    for pair in zip(labels, labels[1:]):
        old[pair] = old.get(pair, 0) + 1
    assert {(u, v): d['weight'] for u, v, d in _named_edges(graph, graph.G.edges(data=True))} == old


def test_export_csv_has_row_index_and_timestamp_us(tmp_path):
    _graph([("A", "2024-01-01 10:00:00"), ("B", "")], tmp_path)
    df = pd.read_csv(tmp_path / "events.csv", dtype=str, keep_default_na=False)
    assert list(df.columns[-2:]) == ["row_index", "timestamp_us"]
    assert df[["row_index", "timestamp_us"]].values.tolist() == [
        ["0", str(pd.Timestamp("2024-01-01 10:00", tz="UTC").value // 1000)], ["1", ""]]


def test_invalid_edge_order():
    with pytest.raises(ValueError):
        EdgeGraph(pd.DataFrame(), edge_order="random")


# --- regression: dataset/1-3 aggregate graphs (sigma 3c0d351, D:\TA\sigma\rules; deselect with -k "not regression") ---

EDGE_BASELINE = json.loads((FIXTURES / "edge_baseline.json").read_text(encoding="utf-8"))


def _summary(graph):
    if not graph.events_dict:
        return {"nodes": [], "edges": []}
    return {"nodes": sorted(graph.node_labels.values()),
            "edges": sorted([u, v, d['weight']] for u, v, d in _named_edges(graph, graph.G.edges(data=True)))}


@pytest.fixture(scope="module")
def sample_graphs(labeled_sample_csvs, tmp_path_factory):
    out = tmp_path_factory.mktemp("edges")
    graphs = {}
    for i, ((csv, flexible), df) in enumerate(labeled_sample_csvs.items()):
        for order in ("file", "time"):
            graph = EdgeGraph(df, edge_order=order)
            graph.run_all(graph_output=str(out / f"{i}-{order}.graphml"))
            graphs[(f"{csv}|{'flexible' if flexible else 'strict'}", order)] = _summary(graph)
    return graphs


@pytest.mark.parametrize("key", list(EDGE_BASELINE))
def test_regression_file_order_identical(sample_graphs, key):
    assert sample_graphs[(key, "file")] == EDGE_BASELINE[key]


@pytest.mark.parametrize("key", list(EDGE_BASELINE))
def test_regression_time_order_same_nodes_and_transition_count(sample_graphs, key):
    time_graph, base = sample_graphs[(key, "time")], EDGE_BASELINE[key]
    assert time_graph["nodes"] == base["nodes"]
    assert sum(e[2] for e in time_graph["edges"]) == sum(e[2] for e in base["edges"])
