import base64
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd
import pytest
import yaml

from recongraph.recongraph import (EdgeGraph, SigmaLabel, SigmaMatcher, SigmaRulesLoader, UnsupportedModifierError,
                                   _base64offset, _windash)
from tests.conftest import SIGMA_RULES

FIXTURES = Path(__file__).parent / "fixtures"


def _rule(tmp_path, selection, logsource=None, condition="selection", flexible=False, title="Synthetic", level="medium",
          name="rule.yml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump({"title": title, "level": level, "logsource": logsource or {"product": "windows"},
                                    "detection": {"selection": selection, "condition": condition}}), encoding="utf-8")
    return SigmaMatcher(str(path), flexible_mode=flexible)


def _entry(log_type=("windows", "sysmon", "process_creation"), desc="synthetic", **fields):
    return {"desc": desc, "log_type": list(log_type), **fields}


def test_contains_all_needs_every_value(tmp_path):
    rule = _rule(tmp_path, {"CommandLine|contains|all": ["vssadmin", "delete", "shadows"]})
    assert rule.match(_entry(CommandLine="vssadmin.exe Delete Shadows /all")) is True
    assert rule.match(_entry(CommandLine="vssadmin.exe list shadows")) is False


def test_without_all_one_value_is_enough(tmp_path):
    rule = _rule(tmp_path, {"CommandLine|contains": ["vssadmin", "wbadmin"]})
    assert rule.match(_entry(CommandLine="wbadmin delete catalog")) is True
    assert rule.match(_entry(CommandLine="bcdedit")) is False


def test_windash_variants():
    variants = _windash(" -enc ")
    assert set(variants) == {" -enc ", " /enc ", " \u2013enc ", " \u2014enc ", " \u2015enc "}
    assert len(_windash(" -nop -w hidden")) == 25
    assert _windash("a-b") == ["a-b"]  # a dash inside a word is not a flag


@pytest.mark.parametrize("cmd, expected", [("powershell /enc ZQBj", True), ("powershell \u2013enc ZQBj", True),
                                           ("powershell -enc ZQBj", True), ("powershell xenc ZQBj", False)])
def test_contains_windash(tmp_path, cmd, expected):
    rule = _rule(tmp_path, {"CommandLine|contains|windash": " -enc "})
    assert rule.match(_entry(CommandLine=cmd)) is expected


def test_base64_is_case_sensitive(tmp_path):
    rule = _rule(tmp_path, {"CommandLine|base64|contains": "http://"})
    encoded = base64.b64encode(b"http://").decode()
    assert rule.match(_entry(CommandLine=f"powershell -e {encoded}")) is True
    assert rule.match(_entry(CommandLine=f"powershell -e {encoded.lower()}")) is False


@pytest.mark.parametrize("prefix", [b"", b"x", b"xy", b"abc", b"abcd"])
def test_base64offset_contains_finds_every_alignment(tmp_path, prefix):
    rule = _rule(tmp_path, {"CommandLine|base64offset|contains": "IEX (New-Object"})
    blob = base64.b64encode(prefix + b"IEX (New-Object Net.WebClient)").decode()
    assert rule.match(_entry(CommandLine=f"powershell -enc {blob}")) is True
    assert rule.match(_entry(CommandLine="powershell -enc " + base64.b64encode(prefix + b"Get-Process").decode())) is False


def test_base64offset_matches_pysigma_reference():
    # pySigma SigmaBase64OffsetModifier output for 'sigma'
    assert _base64offset("sigma") == ["c2lnbW", "NpZ21h", "zaWdtY"]


@pytest.mark.parametrize("ip, expected", [("10.0.2.18", True), ("8.8.8.8", False), ("fe80::1", True),
                                          ("2001:db8::1", False), ("not-an-ip", False), ("", False)])
def test_cidr_ipv4_and_ipv6(tmp_path, ip, expected):
    rule = _rule(tmp_path, {"DestinationIp|cidr": ["10.0.0.0/8", "fe80::/10"]})
    assert rule.match(_entry(DestinationIp=ip)) is expected


def test_fieldref(tmp_path):
    rule = _rule(tmp_path, {"User|fieldref": "ParentUser"})
    assert rule.match(_entry(User="CORP\\alice", ParentUser="corp\\ALICE")) is True
    assert rule.match(_entry(User="CORP\\alice", ParentUser="CORP\\bob")) is False
    assert rule.match(_entry(User="CORP\\alice")) is False  # referenced field missing


def test_exists(tmp_path):
    present = _rule(tmp_path, {"ParentUser|exists": True}, name="present.yml")
    absent = _rule(tmp_path, {"ParentUser|exists": False}, name="absent.yml")
    assert present.match(_entry(ParentUser="x")) is True and present.match(_entry()) is False
    assert absent.match(_entry()) is True and absent.match(_entry(ParentUser="")) is False


@pytest.mark.parametrize("modifier, value, expected", [("lt", "4", True), ("lt", "5", False), ("lte", "5", True),
                                                       ("gt", "6", True), ("gt", "5", False), ("gte", "5", True),
                                                       ("gt", "abc", False)])
def test_numeric_comparisons(tmp_path, modifier, value, expected):
    rule = _rule(tmp_path, {f"LogonType|{modifier}": 5})
    assert rule.match(_entry(LogonType=value)) is expected


def test_regex_is_case_sensitive_unless_i(tmp_path):
    plain = _rule(tmp_path, {"Image|re": r"\\Temp\\[A-Z]+\.exe$"}, name="plain.yml")
    insensitive = _rule(tmp_path, {"Image|re|i": r"\\temp\\[a-z]+\.exe$"}, name="i.yml")
    assert plain.match(_entry(Image=r"C:\Temp\EVIL.exe")) is True
    assert plain.match(_entry(Image=r"C:\temp\evil.exe")) is False
    assert insensitive.match(_entry(Image=r"C:\TEMP\EVIL.EXE")) is True


def test_regex_pattern_is_not_lowercased(tmp_path):
    rule = _rule(tmp_path, {"CommandLine|re": r"^\S+$"})  # lowercasing would turn \S into \s
    assert rule.match(_entry(CommandLine="whoami")) is True
    assert rule.match(_entry(CommandLine="whoami /all")) is False


def test_unknown_modifier_skips_rule_with_warning(tmp_path, caplog):
    with pytest.raises(UnsupportedModifierError, match="utf16le"):
        _rule(tmp_path, {"CommandLine|utf16le|base64": "x"}, title="Wide Rule")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "wide.yml").write_text((tmp_path / "rule.yml").read_text(encoding="utf-8"), encoding="utf-8")
    (rules / "ok.yml").write_text(yaml.safe_dump({"title": "Fine", "logsource": {"product": "windows"},
                                                  "detection": {"keywords": ["x"], "condition": "keywords"}}), encoding="utf-8")
    with caplog.at_level("WARNING"):
        loader = SigmaRulesLoader(str(rules), flexible_mode=False)
    assert [m["title"] for m in loader.matchers] == ["Fine"]
    assert len(loader.skipped) == 1 and "Wide Rule" in caplog.text and "utf16le" in caplog.text


@pytest.mark.skipif(not SIGMA_RULES.exists(), reason="sigma rules not found (set SIGMA_RULES_PATH)")
@pytest.mark.parametrize("ip, expected", [("10.0.2.18", False), ("93.184.216.34", True)])
def test_real_rundll32_rule_uses_cidr(ip, expected):
    rule = SigmaMatcher(str(SIGMA_RULES / "windows/network_connection/net_connection_win_rundll32_net_connections.yml"),
                        flexible_mode=False)
    entry = _entry(("windows", "sysmon", "network_connection"), EventID="3", Image=r"C:\Windows\System32\rundll32.exe",
                   Initiated="true", DestinationIp=ip, DestinationPort="8181")
    assert rule.match(entry) is expected


def _labels(loader, entries):
    labels = []
    for entry in entries:
        found = " | ".join(sorted({f"{m['rule_title']}[{m['rule_level']}]" for m in loader.check_row(entry)}))
        labels.append((loader.extract_sigma_priority(found), found))
    return labels


def test_labels_do_not_depend_on_rule_load_order(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    for title, level in (("Zeta Access", "high"), ("Alpha Access", "high"), ("Beta Access", "medium")):
        (rules / f"{title}.yml").write_text(yaml.safe_dump({
            "title": title, "level": level, "logsource": {"product": "windows"},
            "detection": {"selection": {"TargetImage|endswith": "\\lsass.exe"}, "condition": "selection"}}), encoding="utf-8")
    loader = SigmaRulesLoader(str(rules), flexible_mode=False)
    entries = [_entry(TargetImage=r"C:\Windows\system32\lsass.exe"), _entry(TargetImage=r"C:\x.exe")]
    forward = _labels(loader, entries)
    loader.matchers.reverse()
    assert _labels(loader, entries) == forward
    assert forward[0] == ("Alpha Access[high]", "Alpha Access[high] | Beta Access[medium] | Zeta Access[high]")
    assert forward[1] == ("", "")
    df = SigmaLabel(str(FIXTURES / "sysmon_lsass.jsonl"), str(rules), flexible_mode=False).run()
    assert df[["sigma", "sigma_all"]].values.tolist() == [list(forward[0])]


@pytest.mark.skipif(not SIGMA_RULES.exists(), reason="sigma rules not found (set SIGMA_RULES_PATH)")
def test_flexible_linux_keyword_rule_needs_linux_product():
    rule = SigmaMatcher(str(SIGMA_RULES / "linux/builtin/lnx_file_copy.yml"), flexible_mode=True)
    desc = "scp payload.bin admin@10.0.0.5:/tmp"
    assert rule.match(_entry(desc=desc)) is False
    assert rule.match(_entry(("linux",), desc=desc)) is True


def test_flexible_field_selection_does_not_fall_back_to_the_message(tmp_path):
    rule = _rule(tmp_path, {"Image|endswith": "\\evil.exe"}, flexible=True)
    assert rule.match(_entry(desc=r"process C:\x\evil.exe started")) is False
    assert rule.match(_entry(Image=r"C:\x\evil.exe")) is True
    keyword = tmp_path / "kw.yml"
    keyword.write_text(yaml.safe_dump({"title": "KW", "logsource": {"category": "process_creation"},
                                       "detection": {"keywords": ["evil.exe"], "condition": "keywords"}}), encoding="utf-8")
    assert SigmaMatcher(str(keyword), flexible_mode=True).match(_entry(("unknown",), desc="ran evil.exe")) is True


def test_temporal_graphml_edge_ids_are_seq(tmp_path):
    labels = ["A[high]", "B[low]", "A[high]", "B[low]", "A[high]", "C[medium]"]
    df = pd.DataFrame({"datetime": [f"2024-01-01 10:0{i}:00" for i in range(len(labels))],
                       "message": [f"m{i}" for i in range(len(labels))], "sigma": labels})
    EdgeGraph(df).run_all(graph_output=str(tmp_path / "agg.graphml"), temporal_output=str(tmp_path / "temporal.graphml"))
    root = ET.parse(tmp_path / "temporal.graphml").getroot()
    ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
    seq_key = next(k.get("id") for k in root.iterfind("g:key", ns) if k.get("attr.name") == "seq")
    edges = list(root.iterfind(".//g:edge", ns))
    ids = [e.get("id") for e in edges]
    assert len(ids) == len(set(ids)) == len(labels) - 1
    assert ids == [e.find(f"g:data[@key='{seq_key}']", ns).text for e in edges]
