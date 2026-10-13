import pytest
import pandas as pd
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from recongraph.recongraph import SigmaMatcher, SigmaLabel, EdgeGraph, ReconGraph

# --- TEST CASES ---

def test_log_type_detection():
    """Tests if SigmaLabel correctly identifies log types."""
    labeler = SigmaLabel(input_file="access.log")
    features = labeler.detect_log_type("GET /index.php HTTP/1.1", "access.log")
    assert 'webserver' in features['log_type']
    assert features['cs-method'] == "GET"

@pytest.fixture
def dummy_df():
    return pd.DataFrame({
        'datetime': ["2023-01-01 10:00:00", "2023-01-01 10:01:00"],
        'message': ["Log A", "Log B"],
        'sigma': ["Critical Event[critical]", "Low Event[low]"]
    })

def test_graph_nodes(dummy_df):
    """Tests if EdgeGraph creates the correct number of nodes."""
    builder = EdgeGraph(dummy_df)
    builder.define_events()
    builder.create_graph()
    # There are two unique sigma events in dummy_df
    assert builder.G.number_of_nodes() == 2

def test_sigma_matcher_logic():
    """Tests if the SigmaMatcher correctly evaluates logic conditions."""
    # Create a dummy matcher manually
    from recongraph.recongraph import SigmaMatcher
    import yaml
    import tempfile
    import os

    rule_content = {
        'title': 'Test Rule',
        'logsource': {'category': 'webserver'},
        'detection': {
            'selection': {'c-uri': '/etc/passwd'},
            'condition': 'selection'
        }
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as tf:
        yaml.dump(rule_content, tf)
        temp_name = tf.name

    try:
        matcher = SigmaMatcher(temp_name)
        
        # Positive match
        assert matcher.match({'c-uri': '/etc/passwd', 'log_type': ['webserver']}) is True
        # Negative match (wrong URI)
        assert matcher.match({'c-uri': '/index.php', 'log_type': ['webserver']}) is False
    finally:
        os.remove(temp_name)

def test_edge_weight_calculation():
    """Tests if transitions between events are counted correctly as weights."""
    from recongraph.recongraph import EdgeGraph
    import pandas as pd

    # Sequence: A -> B -> A -> B -> C
    data = {
        'datetime': ["10:00", "10:01", "10:02", "10:03", "10:04"],
        'message': ["m1", "m2", "m3", "m4", "m5"],
        'sigma': ["Event_A", "Event_B", "Event_A", "Event_B", "Event_C"]
    }
    df = pd.DataFrame(data)
    builder = EdgeGraph(df)
    builder.run_all()

    # The transition (Event_A -> Event_B) happened twice
    # Find the edge in the MultiDiGraph
    u = builder.events_dict["Event_A"]
    v = builder.events_dict["Event_B"]
    
    # Check weights in edges_weight dictionary
    assert builder.edges_weight[(u, v)] == 2

def test_graphml_export(tmp_path, dummy_df):
    """Verifies that the GraphML file is created and contains node data."""
    from recongraph.recongraph import EdgeGraph
    import os

    output_file = tmp_path / "test_graph.graphml"
    builder = EdgeGraph(dummy_df)
    builder.run_all(graph_output=str(output_file))

    assert os.path.exists(output_file)
    assert os.path.getsize(output_file) > 0


@pytest.mark.parametrize("label, expected", [
    ("SSH Brute Force[high]", "high"),
    ("Sudo Privilege Escalation[CRITICAL]", "critical"),
    ("Some Rule[informational]", "informational"),
    ("Event_A", ""),          # no bracket token
    ("", ""),                 # empty label
    ("Weird [high] middle", "high"),
])
def test_extract_level(label, expected):
    """Tests severity extraction from the trailing [level] token of a sigma label."""
    assert EdgeGraph.extract_level(label) == expected


def test_node_level_attribute_in_graph(dummy_df):
    """Verifies each node is enriched with a normalized 'level' attribute."""
    builder = EdgeGraph(dummy_df)
    builder.run_all(graph_output=str("_lvl_tmp.graphml"))
    try:
        crit_id = builder.events_dict["Critical Event[critical]"]
        low_id = builder.events_dict["Low Event[low]"]
        assert builder.G.nodes[crit_id]['level'] == "critical"
        assert builder.G.nodes[low_id]['level'] == "low"
    finally:
        import os
        if os.path.exists("_lvl_tmp.graphml"):
            os.remove("_lvl_tmp.graphml")


def test_graphml_contains_level_key(tmp_path, dummy_df):
    """The exported GraphML must declare a 'level' attribute key for consumers."""
    output_file = tmp_path / "lvl_graph.graphml"
    builder = EdgeGraph(dummy_df)
    builder.run_all(graph_output=str(output_file))
    xml = output_file.read_text(encoding="utf-8")
    assert 'attr.name="level"' in xml
    assert ">critical<" in xml


def _matcher(tmp_path, condition):
    import yaml
    rule = tmp_path / "cond.yml"
    rule.write_text(yaml.safe_dump({'title': 'Cond Rule', 'detection': {'condition': condition}}), encoding="utf-8")
    return SigmaMatcher(str(rule))


@pytest.mark.parametrize("condition, selections, expected", [
    ("selection and not filter", {'selection': True, 'filter': True}, False),
    ("selection and not filter", {'selection': False, 'filter': True}, False),
    ("selection and not filter", {'selection': True, 'filter': False}, True),
    ("selection1 and selection2", {'selection1': True, 'selection2': False}, False),
    ("selection1 and selection2", {'selection1': True, 'selection2': True}, True),
    ("1 of selection_* and not filter", {'selection_a': True, 'selection_b': False, 'filter': True}, False),
    ("1 of selection_* and not filter", {'selection_a': False, 'selection_b': True, 'filter': False}, True),
    ("1 of selection_* and not filter", {'selection_a': False, 'selection_b': False, 'filter': False}, False),
    # 'selection' is a prefix of 'selection_filter'; dict order must not matter
    ("selection and not selection_filter", {'selection': True, 'selection_filter': True}, False),
    ("selection and not selection_filter", {'selection_filter': False, 'selection': True}, True),
    ("sel and not sel2", {'sel2': True, 'sel': True}, False),
])
def test_evaluate_condition(tmp_path, condition, selections, expected):
    assert _matcher(tmp_path, condition)._evaluate_condition(condition, selections) is expected


def test_evaluate_condition_warns_on_unparsable(tmp_path, caplog):
    condition = "selection | count() > 5"
    with caplog.at_level("WARNING"):
        result = _matcher(tmp_path, condition)._evaluate_condition(condition, {'selection': True})
    assert result is True  # fallback stays any(selections)
    assert "Cond Rule" in caplog.text and condition in caplog.text