"""Generic Plaso JSONL adapter: non-winevtx data_types, log_type tokens, hex normalization, winevtx unchanged.

Fixtures in tests/fixtures/plaso/ are cut from Plaso test_data parsed with log2timeline/plaso:20260720 (see README.md).
"""
import json
from pathlib import Path

import pytest
import yaml

from recongraph.input_adapters import GENERIC_COLUMNS, _unpad_hex, load_plaso_jsonl
from recongraph.recongraph import SigmaLabel

FIXTURES = Path(__file__).parent / "fixtures"
PLASO = FIXTURES / "plaso"


def _rows(name):
    return load_plaso_jsonl(PLASO / name).to_dict("records")


# --- per data_type: columns, log_type, timestamps ---

@pytest.mark.parametrize("name, data_type, log_type, columns", [
    ("linux_auth.jsonl", "syslog:line", ["linux", "auth", "sshd"],
     {"hostname": "ubuntu2015", "reporter": "sshd", "pid": "3", "message_body": "Server listening on 0.0.0.0 port 22.",
      "source_path": "/p3/plaso/src/auth.log"}),
    ("linux_auth.jsonl", "syslog:ssh:login", ["linux", "auth", "sshd"],
     {"username": "plaso", "ip_address": "192.168.0.1", "port": "59229", "authentication_method": "publickey"}),
    ("linux_auth.jsonl", "syslog:ssh:failed_connection", ["linux", "auth", "sshd"], {"port": "8759"}),
    ("linux_auth.jsonl", "syslog:ssh:opened_connection", ["linux", "auth", "sshd"], {"ip_address": "188.124.3.41"}),
    ("linux_syslog.jsonl", "syslog:line", ["linux", "syslog"], {"reporter": "client", "pid": "30840"}),
    ("linux_syslog.jsonl", "syslog:cron:task_run", ["linux", "syslog", "cron"],
     {"reporter": "CRON", "username": "root", "command": "touch /var/run/crond.somecheck"}),
    ("linux_syslog_gz.jsonl", "syslog:line", ["linux", "syslog"], {"source_path": "/p3/plaso/src/syslog.gz"}),
    ("android_logcat.jsonl", "android:logcat", ["android"],
     {"component_tag": "App", "priority": "E", "pid": "1885", "thread_identifier": "3066"}),
    ("android_sms.jsonl", "android:messaging:sms", ["android"],
     {"address": "1 555-521-5554", "sms_type": "2", "message_body": "Yo Fred this is my new number."}),
    ("android_calls.jsonl", "android:event:call", ["android"], {"number": "5404561685", "name": "Barney", "call_type": "3"}),
    ("ios_lockdownd.jsonl", "ios:lockdownd_log:entry", ["ios"], {"process_identifier": "69"}),
    ("ios_sysdiag.jsonl", "ios:sysdiag_log:entry", ["ios"], {"severity": "notice", "process_identifier": "66"}),
    ("ios_logd.jsonl", "ios:sysdiagnose:logd:line", ["ios"], {"logger": "logd_helper[85]"}),
    ("filestat.jsonl", "fs:stat", [], {"filename": "/p3/plaso/src/auth.log", "is_allocated": "true", "file_size": "1026"}),
])
def test_data_type_columns_and_log_type(name, data_type, log_type, columns):
    row = next(r for r in _rows(name) if r["data_type"] == data_type)
    assert row["log_type"] == log_type
    assert {k: row[k] for k in columns} == columns
    assert row["datetime"].endswith("+00:00") and row["timestamp_desc"]


@pytest.mark.parametrize("name, descs", [
    ("filestat.jsonl", ["Content Modification Time", "Metadata Modification Time", "Last Access Time"]),
    ("android_calls.jsonl", ["Start Time", "End Time"]),
])
def test_non_evtx_keeps_every_timestamp_of_a_record(name, descs):
    rows = _rows(name)
    assert [r["timestamp_desc"] for r in rows] == descs
    assert len({r.get("inode") or r.get("number") for r in rows}) == 1


def test_plaso_internals_are_not_columns():
    df = load_plaso_jsonl(PLASO / "linux_auth.jsonl")
    assert not {"__container_type__", "__type__", "date_time", "pathspec", "timestamp"} & set(df.columns)
    assert all(isinstance(v, str) for c in df.columns if c not in GENERIC_COLUMNS for v in df[c].dropna())


def test_source_path_is_innermost_location_and_absent_without_pathspec():
    assert _rows("linux_syslog_gz.jsonl")[0]["source_path"] == "/p3/plaso/src/syslog.gz"  # GZIP spec -> its OS parent
    assert "source_path" not in load_plaso_jsonl(PLASO / "filestat_image_dir.jsonl").columns


def test_attribute_named_like_an_adapter_column_gets_prefix(tmp_path):
    record = {"data_type": "android:logcat", "parser": "text/android_logcat", "timestamp": 1700000000000000,
              "timestamp_desc": "Recorded Time", "message": "m", "display_name": "OS:/x.log",
              "datetime": "spoofed", "log_type": "spoofed", "source_path": "/attr", "pathspec": {"location": "/x.log"},
              "strings": ["a", "b"]}
    (tmp_path / "c.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    row = load_plaso_jsonl(tmp_path / "c.jsonl").iloc[0]
    assert row["datetime"] == "2023-11-14T22:13:20.000000+00:00" and row["log_type"] == ["android"]
    assert (row["plaso_datetime"], row["plaso_log_type"], row["plaso_source_path"]) == ("spoofed", "spoofed", "/attr")
    assert row["source_path"] == "/x.log" and "strings" not in row


@pytest.mark.parametrize("path, expected", [
    ("/var/log/auth.log", ["linux", "auth"]), ("/var/log/auth.log.2.gz", ["linux", "auth"]),
    ("/var/log/secure-20240101", ["linux", "auth"]), ("/var/log/syslog.1", ["linux", "syslog"]),
    ("/var/log/messages", ["linux", "syslog"]), (r"C:\cases\var\log\auth.log", ["linux", "auth"]),
    ("/var/log/kern.log", ["linux"]), ("/var/log/authlog_backup", ["linux"]),
])
def test_linux_service_from_source_file_name(tmp_path, path, expected):
    record = {"data_type": "syslog:line", "parser": "text/syslog_traditional", "timestamp": 1700000000000000,
              "timestamp_desc": "Content Modification Time", "message": "m", "reporter": "kernel",
              "pathspec": {"location": path}}
    (tmp_path / "s.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    assert load_plaso_jsonl(tmp_path / "s.jsonl").iloc[0]["log_type"] == expected


def test_unmapped_data_type_is_kept_and_logged(caplog):
    with caplog.at_level("INFO"):
        df = load_plaso_jsonl(PLASO / "filestat.jsonl")
    assert len(df) == 3 and df["log_type"].tolist() == [[], [], []]
    assert "rows without Sigma logsource tokens (log_type []): {'fs:stat': 3}" in caplog.text


def test_csv_auth_log_gets_auth_token():
    assert SigmaLabel("x.csv").detect_log_type("sshd: Accepted", "/var/log/auth.log")["log_type"] == ["linux", "auth", "sshd"]


# --- Sigma logsource (strict) ---

def _rule(tmp_path, logsource, keyword):
    rule = {"title": "Synthetic", "level": "low", "logsource": logsource,
            "detection": {"keywords": [keyword], "condition": "keywords"}}
    (tmp_path / "r.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    return str(tmp_path)


@pytest.mark.parametrize("name, logsource, hits", [
    ("linux_auth.jsonl", {"product": "linux", "service": "auth"}, 1),
    ("linux_auth.jsonl", {"product": "linux", "service": "sshd"}, 1),
    ("linux_syslog.jsonl", {"product": "linux", "service": "auth"}, 0),
    ("android_logcat.jsonl", {"product": "linux"}, 0),
])
def test_strict_logsource_for_linux_events(tmp_path, name, logsource, hits):
    keyword = "server listening" if "auth" in name else "test of threadtime"
    df = SigmaLabel(str(PLASO / name), _rule(tmp_path, logsource, keyword), flexible_mode=False).run()
    assert (df["sigma"] == "Synthetic[low]").sum() == hits


# --- hex normalization (winevtx) ---

@pytest.mark.parametrize("value, expected", [
    ("0x0000002d", "0x2d"), ("0x00000000", "0x0"), ("0x0000000000000000", "0x0"), ("0x00000000000003e7", "0x3e7"),
    ("0x000000007612ABC0", "0x7612ABC0"), ("0x0", "0x0"), ("0x2d", "0x2d"), ("0xc000006d", "0xc000006d"),
    ("DWORD (0x00000001)", "DWORD (0x00000001)"), ("0x00zz", "0x00zz"), ("", ""),
])
def test_unpad_hex(value, expected):
    assert _unpad_hex(value) == expected


def _security_4663(tmp_path, access_mask):
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
           '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4663</EventID><Level>0</Level>'
           '<EventRecordID>1</EventRecordID><Channel>Security</Channel><Computer>host01</Computer></System>'
           f'<EventData><Data Name="AccessMask">{access_mask}</Data><Data Name="ObjectName">C:\\x</Data></EventData>'
           '<UserData><R><Mask>0x00000040</Mask></R></UserData></Event>')
    record = {"data_type": "windows:evtx:record", "parser": "winevtx", "timestamp": 1700000000000000,
              "timestamp_desc": "Creation Time", "message": "[4663]", "xml_string": xml}
    (tmp_path / "e.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    return tmp_path / "e.jsonl"


def test_padded_hex_eventdata_matches_unpadded_rule(tmp_path):
    path = _security_4663(tmp_path, "0x0000002d")
    row = load_plaso_jsonl(path).iloc[0]
    assert (row["AccessMask"], row["Mask"]) == ("0x2d", "0x40")
    rule = {"title": "Mask", "level": "low", "logsource": {"product": "windows", "service": "security"},
            "detection": {"selection": {"EventID": 4663, "AccessMask": "0x2d"}, "condition": "selection"}}
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "m.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    assert SigmaLabel(str(path), str(tmp_path / "rules"), flexible_mode=False).run()["sigma"].tolist() == ["Mask[low]"]


# --- winevtx unchanged ---

@pytest.mark.parametrize("key", json.loads((PLASO / "winevtx_golden_e9b07b9.json").read_text(encoding="utf-8")))
def test_winevtx_rows_identical_to_e9b07b9(key):
    """Golden = the e9b07b9 adapter on the existing fixtures (no padded hex values in them)."""
    name, keep = key.split("|keep_all=")
    df = load_plaso_jsonl(FIXTURES / name, keep_all_timestamps=keep == "True")
    rows = [{k: v for k, v in r.items() if isinstance(v, (str, list))} for r in df[df["parser"] == "winevtx"].to_dict("records")]
    golden = json.loads((PLASO / "winevtx_golden_e9b07b9.json").read_text(encoding="utf-8"))[key]
    assert rows == golden
