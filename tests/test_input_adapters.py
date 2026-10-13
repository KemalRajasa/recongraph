import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pandas as pd
import pytest
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from recongraph.input_adapters import (CHANNEL_SERVICES, EVENT_CATEGORIES, detect_input_format,
                                       load_plaso_jsonl)
from recongraph.recongraph import EdgeGraph, SigmaLabel

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE = FIXTURES / "plaso_sample.jsonl"
REPO = Path(__file__).parents[1]
SIGMA = REPO.parent / "sigma"


@pytest.fixture(scope="module")
def sample():
    return load_plaso_jsonl(SAMPLE)


def _by_record_id(df, rid):
    return df[df["EventRecordID"] == rid].iloc[0]


# --- format detection ---

def test_detect_by_extension(tmp_path):
    for name in ("a.jsonl", "a.json", "a.JSONL"):
        (tmp_path / name).write_text("not json\n", encoding="utf-8")
        assert detect_input_format(tmp_path / name) == "plaso_jsonl"


def test_detect_by_content(tmp_path):
    f = tmp_path / "timeline.txt"
    f.write_text('\n{"data_type": "fs:stat", "message": "x"}\n', encoding="utf-8")
    assert detect_input_format(f) == "plaso_jsonl"


@pytest.mark.parametrize("name, content, expected", [
    ("t.csv", "datetime,message\n", "plaso_csv"),
    ("t.txt", "GET /index.php HTTP/1.1\n", "text"),
    ("t.txt", '{"no_data_type": 1}\n', "text"),
    ("t.log", "", "text"),
])
def test_detect_falls_back_to_current_behavior(tmp_path, name, content, expected):
    (tmp_path / name).write_text(content, encoding="utf-8")
    assert detect_input_format(tmp_path / name) == expected


# --- XML normalization ---

def test_named_eventdata(sample):
    row = _by_record_id(sample, "7")
    assert row["EventID"] == "10"
    assert row["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert row["Provider_Name"] == "Microsoft-Windows-Sysmon"
    assert row["Computer"] == "host01.test.local"
    assert row["Security_UserID"] == "S-1-5-18"
    assert row["SourceImage"] == r"C:\Tools\dumper.exe"
    assert row["TargetImage"] == r"C:\Windows\system32\lsass.exe"
    assert row["GrantedAccess"] == "0x1010"


def test_unnamed_data_becomes_params_and_joined_data(sample):
    row = _by_record_id(sample, "9")
    assert (row["param1"], row["param2"], row["param3"]) == ("Available", "None", "HostName=ConsoleHost")
    assert row["Data"] == "Available\nNone\nHostName=ConsoleHost"


def test_named_eventdata_has_no_joined_data(sample):
    assert pd.isna(_by_record_id(sample, "7")["Data"])


def test_nested_userdata_and_system_priority(sample):
    row = _by_record_id(sample, "10")
    assert row["SubjectUserName"] == "alice"
    assert row["SubjectDomainName"] == "TEST"
    assert row["Computer"] == "host01.test.local"  # System wins over UserData <Computer>


def test_userdata_channel_used_for_matching_system_channel_for_log_type(sample):
    row = _by_record_id(sample, "10")
    assert row["Channel"] == "Windows PowerShell"  # the cleared log, from UserData
    assert row["log_type"] == ["windows", "system"]  # from System/Channel


def test_duplicate_field_keeps_first_and_warns(caplog):
    with caplog.at_level("WARNING"):
        df = load_plaso_jsonl(SAMPLE)
    assert _by_record_id(df, "30")["CommandLine"] == "cmd.exe /c whoami"
    assert "duplicate field 'CommandLine'" in caplog.text


def test_security_4688_aliases(sample):
    row = _by_record_id(sample, "30")
    assert row["Image"] == row["NewProcessName"] == r"C:\Windows\System32\cmd.exe"
    assert row["ParentImage"] == row["ParentProcessName"] == r"C:\Windows\explorer.exe"
    assert row["log_type"] == ["windows", "security", "process_creation"]


def test_malformed_xml_keeps_generic_columns(caplog):
    with caplog.at_level("WARNING"):
        df = load_plaso_jsonl(SAMPLE)
    broken = df[df["datetime"] == "2023-11-14T22:13:24.000000+00:00"].iloc[0]
    assert broken["parser"] == "winevtx" and broken["message"] == "[0] synthetic event"
    assert broken["log_type"] == ["windows"]
    assert pd.isna(broken["EventID"])
    assert "unparsable xml_string" in caplog.text


def test_illegal_xml_characters_are_stripped(caplog):
    with caplog.at_level("INFO"):
        df = load_plaso_jsonl(SAMPLE)
    row = _by_record_id(df, "20")
    assert row["PrivilegeList"] == "SeDebugPrivilege"
    assert row["log_type"] == ["windows", "security"]
    assert "1 records recovered by removing XML-illegal characters, 1 still unparsable" in caplog.text


def test_non_evtx_record_has_generic_columns_only(sample):
    row = sample[sample["parser"] == "filestat"].iloc[0]
    assert row["log_type"] is None
    assert row["message"] == r"C:\Windows\Temp\a.txt Type: file"
    assert pd.isna(row["EventID"])


# --- preprocessing ---

def test_one_row_per_record(sample):
    evtx = sample[sample["parser"] == "winevtx"]
    assert set(evtx["timestamp_desc"]) == {"Creation Time"}
    assert evtx["EventRecordID"].dropna().is_unique


def test_keep_all_timestamps():
    df = load_plaso_jsonl(SAMPLE, keep_all_timestamps=True)
    assert (df["EventRecordID"] == "7").sum() == 2
    assert set(df["timestamp_desc"]) == {"Creation Time", "Content Modification Time"}


def test_drops_timestamps_before_epoch(caplog):
    with caplog.at_level("INFO"):
        df = load_plaso_jsonl(SAMPLE)
    assert "4" not in set(df["EventRecordID"])  # its creation time is Filetime 0
    assert (df["datetime"] >= "1970").all()
    assert "dropped 1 rows" in caplog.text
    df_all = load_plaso_jsonl(SAMPLE, keep_all_timestamps=True)
    assert (df_all["datetime"] >= "1970").all()
    assert (df_all["EventRecordID"] == "5").sum() == 1  # its modification row was Filetime 0


def test_sorted_by_time_then_record_id(sample):
    assert sample["datetime"].is_monotonic_increasing
    evtx_ids = sample["EventRecordID"].dropna().tolist()
    assert evtx_ids == ["5", "7", "9", "10", "20", "30"]  # 9 before 10 at equal timestamps (numeric tie-break)


def test_datetime_is_iso_utc(sample):
    assert _by_record_id(sample, "7")["datetime"] == "2023-11-14T22:13:22.000000+00:00"


# --- logsource mapping ---

@pytest.mark.parametrize("rid, expected", [
    ("5", ["windows", "sysmon", "process_creation"]),
    ("7", ["windows", "sysmon", "process_access"]),
    ("9", ["windows", "powershell-classic", "ps_classic_start"]),
    ("10", ["windows", "system"]),
])
def test_log_type_from_channel_and_event_id(sample, rid, expected):
    assert _by_record_id(sample, rid)["log_type"] == expected


@pytest.mark.parametrize("channel, service", [
    ("Security", "security"),
    ("System", "system"),
    ("Application", "application"),
    ("Microsoft-Windows-Sysmon/Operational", "sysmon"),
    ("Microsoft-Windows-PowerShell/Operational", "powershell"),
    ("Windows PowerShell", "powershell-classic"),
    ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "firewall-as"),
    ("Microsoft-Windows-Bits-Client/Operational", "bits-client"),
    ("Microsoft-Windows-TaskScheduler/Operational", "taskscheduler"),
    ("Microsoft-Windows-Windows Defender/Operational", "windefend"),
    ("Microsoft-Windows-WMI-Activity/Operational", "wmi"),
])
def test_channel_service_mapping(channel, service):
    assert CHANNEL_SERVICES[channel] == service


@pytest.mark.parametrize("event_id, categories", [
    ("1", ["process_creation"]), ("2", ["file_change"]), ("3", ["network_connection"]),
    ("5", ["process_termination"]), ("6", ["driver_load"]), ("7", ["image_load"]),
    ("8", ["create_remote_thread"]), ("9", ["raw_access_thread"]), ("10", ["process_access"]),
    ("11", ["file_event"]), ("12", ["registry_add", "registry_delete", "registry_event"]),
    ("13", ["registry_set", "registry_event"]), ("14", ["registry_rename", "registry_event"]),
    ("15", ["create_stream_hash"]), ("17", ["pipe_created"]), ("18", ["pipe_created"]),
    ("19", ["wmi_event"]), ("20", ["wmi_event"]), ("21", ["wmi_event"]), ("22", ["dns_query"]),
    ("23", ["file_delete"]), ("25", ["process_tampering"]), ("26", ["file_delete", "file_delete_detected"]),
])
def test_sysmon_category_mapping(event_id, categories):
    assert EVENT_CATEGORIES[("Microsoft-Windows-Sysmon/Operational", event_id)] == categories


@pytest.mark.parametrize("event_id, category", [("4104", "ps_script"), ("4103", "ps_module")])
def test_powershell_category_mapping(event_id, category):
    assert EVENT_CATEGORIES[("Microsoft-Windows-PowerShell/Operational", event_id)] == [category]


@pytest.mark.skipif(not (SIGMA / "tests" / "logsource.json").exists(), reason="sigma repo not found next to recongraph")
def test_mapping_uses_sigma_taxonomy():
    windows = json.loads((SIGMA / "tests" / "logsource.json").read_text(encoding="utf-8"))["legit"]["windows"]
    assert set(CHANNEL_SERVICES.values()) <= set(windows["service"])
    # Sysmon-only taxonomy names that logsource.json does not list (it has the generic 'file_block')
    extra = {"file_delete_detected", "file_block_executable", "file_block_shredding"}
    assert {c for cats in EVENT_CATEGORIES.values() for c in cats} <= set(windows["category"]) | extra


# --- end to end: field-based rule ---

@pytest.mark.parametrize("flexible", [True, False])
def test_field_rule_matches_jsonl_but_not_equivalent_csv(flexible):
    rules = str(FIXTURES / "rules")
    jsonl = SigmaLabel(str(FIXTURES / "sysmon_lsass.jsonl"), rules, flexible_mode=flexible).run()
    csv = SigmaLabel(str(FIXTURES / "sysmon_lsass.csv"), rules, flexible_mode=flexible).run()
    assert jsonl["sigma"].tolist() == ["Synthetic LSASS Access[high]"]
    assert csv["sigma"].tolist() == ["", ""]


def test_event_id_compared_as_string(tmp_path):
    rule = {'title': 'EID Rule', 'level': 'low', 'logsource': {'product': 'windows', 'service': 'sysmon'},
            'detection': {'selection': {'EventID': 10, 'GrantedAccess': '0x1010'}, 'condition': 'selection'}}
    (tmp_path / "eid.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    df = SigmaLabel(str(FIXTURES / "sysmon_lsass.jsonl"), str(tmp_path), flexible_mode=False).run()
    assert df["sigma"].tolist() == ["EID Rule[low]"]


@pytest.mark.parametrize("flexible", [True, False])
def test_data_contains_rule_matches_unnamed_data(flexible):
    df = SigmaLabel(str(SAMPLE), str(FIXTURES / "rules"), flexible_mode=flexible).run()
    labels = dict(zip(df["EventRecordID"], df["sigma"]))
    assert labels["9"] == "Synthetic Classic PowerShell Data[low]"
    assert "Synthetic Classic PowerShell Data[low]" not in [v for k, v in labels.items() if k != "9"]


EVENTLOG_RULES = SIGMA / "rules" / "windows" / "builtin" / "system" / "microsoft_windows_eventlog"


@pytest.mark.skipif(not EVENTLOG_RULES.exists(), reason="sigma rules not found next to recongraph")
@pytest.mark.parametrize("flexible", [True, False])
def test_event_104_matches_on_cleared_channel(tmp_path, flexible):
    for name in ("win_system_eventlog_cleared.yml", "win_system_susp_eventlog_cleared.yml"):
        (tmp_path / name).write_bytes((EVENTLOG_RULES / name).read_bytes())
    df = SigmaLabel(str(FIXTURES / "eventlog_cleared.jsonl"), str(tmp_path), flexible_mode=flexible).run()
    labels = dict(zip(df["Channel"], df["sigma"]))
    assert labels["Microsoft-Windows-PowerShell/Operational"].startswith("Important Windows Eventlog Cleared[")
    assert labels["Microsoft-Windows-Bits-Client/Operational"].startswith("Eventlog Cleared[")


def test_jsonl_entry_excludes_generic_columns(tmp_path):
    # display_name contains 'synthetic'; a keyword rule must not match on metadata columns
    rule = {'title': 'Keyword', 'level': 'low', 'logsource': {'product': 'windows'},
            'detection': {'keywords': ['synthetic.evtx'], 'condition': 'keywords'}}
    (tmp_path / "kw.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    df = SigmaLabel(str(FIXTURES / "sysmon_lsass.jsonl"), str(tmp_path), flexible_mode=True).run()
    assert df["sigma"].tolist() == [""]


# --- regression: CSV path unchanged (sigma 3c0d351, D:\TA\sigma\rules; ~6 min, deselect with -k "not regression") ---

# Recorded on the step-0 code (regex fix, before the JSONL adapter): (rows, labeled, nodes, edges).
CSV_BASELINE = {
    ("1/failed-login.csv", True): (2001, 2001, 2, 4),
    ("1/failed-login.csv", False): (2001, 0, 0, 0),
    ("2/windows-firewall-disabled-evtx.csv", True): (2000, 2000, 5, 14),
    ("2/windows-firewall-disabled-evtx.csv", False): (2000, 0, 0, 0),
    ("3/4616-with-regex.csv", True): (2001, 2001, 6, 19),
    ("3/4616-with-regex.csv", False): (2001, 2, 1, 1),
}


def _csv_counts(args):
    csv, flexible, out = args
    df = SigmaLabel(str(REPO / "dataset" / csv), str(SIGMA / "rules"), flexible_mode=flexible).run()
    graph = EdgeGraph(df)
    graph.run_all(graph_output=out)
    return len(df), int((df["sigma"] != "").sum()), graph.G.number_of_nodes(), graph.G.number_of_edges()


@pytest.fixture(scope="module")
def csv_results(tmp_path_factory):
    out = tmp_path_factory.mktemp("regression")
    jobs = [(csv, flexible, str(out / f"{i}.graphml")) for i, (csv, flexible) in enumerate(CSV_BASELINE)]
    with ProcessPoolExecutor() as pool:
        return dict(zip(CSV_BASELINE, pool.map(_csv_counts, jobs)))


@pytest.mark.skipif(not (SIGMA / "rules").exists(), reason="sigma rules not found next to recongraph")
@pytest.mark.parametrize("key", list(CSV_BASELINE), ids=[f"{c}-{'flex' if f else 'strict'}" for c, f in CSV_BASELINE])
def test_regression_csv_graph_unchanged(csv_results, key):
    assert csv_results[key] == CSV_BASELINE[key]
