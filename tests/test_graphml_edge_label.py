"""GraphML edges carry `label` first: apoc.import.graphml drops the first <data> of an <edge> that has no label."""
import xml.etree.ElementTree as ET
from pathlib import Path

import networkx as nx
import pytest

from recongraph.recongraph import EDGE_LABEL, EdgeGraph, ReconGraph

FIXTURES = Path(__file__).parent / "fixtures"
GRAPHML = "{http://graphml.graphdrawing.org/xmlns}"
REQUIRED = {"agg": "weight", "temporal": "seq"}


@pytest.fixture
def written(tmp_path):
    paths = {name: tmp_path / f"{name}.graphml" for name in REQUIRED}
    ReconGraph(str(FIXTURES / "plaso_sample.jsonl"), str(FIXTURES / "rules"), flexible_mode=False).run_all(
        graph_output=str(paths["agg"]), temporal_output=str(paths["temporal"]))
    return paths


@pytest.mark.parametrize("name", list(REQUIRED))
def test_label_is_the_first_data_of_every_edge(written, name):
    root = ET.parse(written[name]).getroot()
    keys = [k.get("id") for k in root.iter(f"{GRAPHML}key") if k.get("for") == "edge" and k.get("attr.name") == "label"]
    edges = list(root.iter(f"{GRAPHML}edge"))
    assert len(keys) == 1 and edges
    assert all(edge[0].get("key") == keys[0] and edge[0].text == EDGE_LABEL for edge in edges)


@pytest.mark.parametrize("name", list(REQUIRED))
def test_every_edge_keeps_its_attributes(written, name):
    edges = list(nx.read_graphml(written[name]).edges(data=True))
    assert edges and all(REQUIRED[name] in data for *_, data in edges)


def test_labeling_copies_the_graph():
    graph = nx.MultiDiGraph(name="g")
    graph.add_node("a", event="A")
    graph.add_node("b", event="B")
    graph.add_edge("a", "b", key=7, seq=0)
    graph.add_edge("a", "b", key=9, seq=1)

    labeled = EdgeGraph._with_edge_labels(graph)

    assert list(graph.edges(keys=True, data=True)) == [("a", "b", 7, {"seq": 0}), ("a", "b", 9, {"seq": 1})]
    assert list(labeled.edges(keys=True, data=True)) == [("a", "b", 7, {"label": EDGE_LABEL, "seq": 0}),
                                                         ("a", "b", 9, {"label": EDGE_LABEL, "seq": 1})]
    assert list(next(iter(labeled.edges(data=True)))[2]) == ["label", "seq"]
    assert dict(labeled.nodes(data=True)) == dict(graph.nodes(data=True))
    assert labeled.graph == graph.graph
