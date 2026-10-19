import pytest
import yaml

from recongraph.recongraph import SigmaMatcher
from tests.conftest import SIGMA_RULES

pytestmark = pytest.mark.skipif(not SIGMA_RULES.exists(), reason="sigma rules not found (set SIGMA_RULES_PATH)")

SYSMON_PC = ["windows", "sysmon", "process_creation"]


def _rule(rel):
    return SigmaMatcher(str(SIGMA_RULES / rel), flexible_mode=False)


def _synthetic(tmp_path, logsource, detection):
    path = tmp_path / "rule.yml"
    path.write_text(yaml.safe_dump({"title": "Synthetic", "logsource": logsource, "detection": detection}), encoding="utf-8")
    return SigmaMatcher(str(path), flexible_mode=False)


def _entry(log_type, desc="", **fields):
    """Shaped like a SigmaLabel log_entry built from the JSONL adapter: System fields + EventData fields."""
    return {"desc": desc, "log_type": log_type, "Computer": "host01", "EventRecordID": "1", **fields}


def _sysmon_1(**fields):
    return _entry(SYSMON_PC, "[1 / 0x0001] synthetic", EventID="1", Channel="Microsoft-Windows-Sysmon/Operational",
                  Provider_Name="Microsoft-Windows-Sysmon", **fields)


# --- logsource ---

def test_linux_product_rule_does_not_match_windows():
    rule = _rule("linux/builtin/lnx_file_copy.yml")
    desc = "scp payload.bin admin@10.0.0.5:/tmp"
    assert rule.match(_entry(SYSMON_PC, desc)) is False
    assert rule.match(_entry(["linux"], desc)) is True


def test_application_service_rule_needs_application_log():
    rule = _rule("windows/builtin/application/Other/win_av_relevant_match.yml")
    sysmon_10 = _entry(["windows", "sysmon", "process_access"],
                       r"[10 / 0x000a] Strings: ['C:\Tools\mimikatz.exe', 'C:\Windows\system32\lsass.exe']",
                       EventID="10", Channel="Microsoft-Windows-Sysmon/Operational", Provider_Name="Microsoft-Windows-Sysmon",
                       SourceImage=r"C:\Tools\mimikatz.exe", TargetImage=r"C:\Windows\system32\lsass.exe")
    assert rule.match(sysmon_10) is False
    application = _entry(["windows", "application"], "Threat HackTool:Win32/Mimikatz detected", EventID="1116",
                         Channel="Application", Provider_Name="Windows Defender", Level="2")
    assert rule.match(application) is True


def test_firewall_service_rule_ignores_other_channels():
    rule = _rule("windows/builtin/firewall_as/win_firewall_as_delete_rule.yml")
    fields = dict(EventID="2006", ModifyingApplication=r"C:\Users\Public\evil.exe")
    store = _entry(["windows"], "[2006] synthetic", Channel="Microsoft-Windows-Store/Operational",
                   Provider_Name="Microsoft-Windows-Store", **fields)
    firewall = _entry(["windows", "firewall-as"], "[2006] synthetic",
                      Channel="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
                      Provider_Name="Microsoft-Windows-Windows Firewall With Advanced Security", **fields)
    assert rule.match(store) is False
    assert rule.match(firewall) is True


@pytest.mark.parametrize("service, wrong, right", [
    ("wmi", ["windows", "sysmon", "wmi_event"], ["windows", "wmi"]),
    ("powershell", ["windows", "powershell-classic"], ["windows", "powershell"]),
])
def test_service_tokens_match_exactly(tmp_path, service, wrong, right):
    rule = _synthetic(tmp_path, {"product": "windows", "service": service},
                      {"keywords": ["evil"], "condition": "keywords"})
    assert rule.match(_entry(wrong, "evil things")) is False
    assert rule.match(_entry(right, "evil things")) is True


def test_logsource_tokens_are_case_insensitive(tmp_path):
    rule = _synthetic(tmp_path, {"product": "Windows", "category": "Process_Creation"},
                      {"keywords": ["evil"], "condition": "keywords"})
    assert rule.match(_entry(["WINDOWS", "Sysmon", "PROCESS_CREATION"], "evil")) is True


def test_process_creation_rule_matches_sysmon_1_and_security_4688():
    rule = _rule("windows/process_creation/proc_creation_win_lolbin_pcalua.yml")
    cmd = r'"C:\Windows\System32\pcalua.exe" -a C:\Windows\system32\calc.exe'
    assert rule.match(_sysmon_1(Image=r"C:\Windows\System32\pcalua.exe", CommandLine=cmd)) is True
    security_4688 = _entry(["windows", "security", "process_creation"], "[4688] synthetic", EventID="4688",
                           Channel="Security", Provider_Name="Microsoft-Windows-Security-Auditing",
                           NewProcessName=r"C:\Windows\System32\pcalua.exe", Image=r"C:\Windows\System32\pcalua.exe",
                           CommandLine=cmd)
    assert rule.match(security_4688) is True


# --- field availability for negated selections ---

def test_negation_only_rule_needs_its_fields():
    rule = _rule("windows/process_creation/proc_creation_win_susp_image_missing.yml")
    # logsource forced to match: only the field-availability check can reject it
    security_4624 = _entry(["windows", "security", "process_creation"], "[4624] An account was successfully logged on",
                           EventID="4624", Channel="Security", Provider_Name="Microsoft-Windows-Security-Auditing",
                           TargetUserName="alice", LogonType="3")
    assert rule._check_logsource(security_4624) is True
    assert rule.match(security_4624) is False


def test_negation_only_rule_still_detects_image_without_path():
    rule = _rule("windows/process_creation/proc_creation_win_susp_image_missing.yml")
    assert rule.match(_sysmon_1(Image="MsMpEng.exe", CommandLine="MsMpEng.exe")) is True
    assert rule.match(_sysmon_1(Image=r"C:\Windows\System32\cmd.exe", CommandLine="cmd.exe")) is False


def test_missing_negated_field_only_blocks_the_branch_that_negates_it():
    # condition: selection1 or (selection2 and not selection3 and not filter_null); selection3/filter_null use SidHistory
    rule = _rule("windows/builtin/security/win_security_susp_add_sid_history.yml")
    security = dict(Channel="Security", Provider_Name="Microsoft-Windows-Security-Auditing")
    assert rule.match(_entry(["windows", "security"], "[4765] synthetic", EventID="4765", **security)) is True
    assert rule.match(_entry(["windows", "security"], "[4738] synthetic", EventID="4738", **security)) is False
    assert rule.match(_entry(["windows", "security"], "[4738] synthetic", EventID="4738",
                             SidHistory="S-1-5-21-1-2-3-500", **security)) is True


def test_zeek_rule_does_not_match_windows():
    rule = _rule("network/zeek/zeek_rdp_public_listener.yml")
    entry = _sysmon_1(Image=r"C:\Windows\System32\mstsc.exe")
    assert rule.match(entry) is False
    rule.logsource = {}  # even without the logsource gate, `not selection` needs id.orig_h
    assert rule.match(entry) is False


def test_positive_field_rule_unchanged(tmp_path):
    rule = _synthetic(tmp_path, {"product": "windows"}, {"selection": {"Image|endswith": "\\evil.exe"},
                                                         "condition": "selection"})
    assert rule.match(_sysmon_1(Image=r"C:\x\evil.exe")) is True
    assert rule.match(_sysmon_1(CommandLine="evil.exe")) is False  # field missing: False, as before


def test_keyword_negation_is_not_field_gated(tmp_path):
    rule = _synthetic(tmp_path, {"product": "windows"}, {"keywords": ["evil"], "filter": ["benign"],
                                                         "condition": "keywords and not filter"})
    assert rule.match(_entry(["windows"], "evil tool")) is True
    assert rule.match(_entry(["windows"], "evil but benign")) is False


def test_flexible_mode_unchanged():
    rule = SigmaMatcher(str(SIGMA_RULES / "network/zeek/zeek_rdp_public_listener.yml"), flexible_mode=True)
    assert rule.match(_sysmon_1(Image=r"C:\Windows\System32\mstsc.exe")) is True  # known flexible FP, Phase 2b


@pytest.mark.parametrize("condition, expected", [
    ("selection and not filter", [["filter"]]),
    ("selection and not 1 of filter_*", [["filter_a", "filter_b"]]),
    ("selection and not all of filter_*", [["filter_a", "filter_b"]]),
    ("not 1 of them", [["selection", "filter", "filter_a", "filter_b", "sel2"]]),
    ("selection and not (filter_a or filter_b)", [["filter_a"], ["filter_b"]]),
    ("1 of filter_* and selection", []),
    ("selection and not sel2", [["sel2"]]),
    ("not (selection and not filter)", [["selection"], ["filter"]]),  # limitation: double negation still counts
    ("selection | count() by Image > 5", []),
])
def test_negated_group_parsing(tmp_path, condition, expected):
    detection = {name: {"Image": "x"} for name in ("selection", "filter", "filter_a", "filter_b", "sel2")}
    rule = _synthetic(tmp_path, {"product": "windows"}, {**detection, "condition": condition})
    assert rule._negated_groups(list(detection)) == expected


# --- null semantics ---

def test_null_matches_missing_or_empty_field(tmp_path):
    rule = _synthetic(tmp_path, {"product": "windows"}, {"selection": {"ParentUser": None}, "condition": "selection"})
    assert rule.match(_sysmon_1(User="alice")) is True
    assert rule.match(_sysmon_1(User="alice", ParentUser="")) is True
    assert rule.match(_sysmon_1(User="alice", ParentUser="bob")) is False


def test_null_does_not_skip_the_other_fields_of_its_selection(tmp_path):
    rule = _synthetic(tmp_path, {"product": "windows"}, {"selection": {"ParentUser": None, "Image|endswith": "\\evil.exe"},
                                                         "condition": "selection"})
    assert rule.match(_sysmon_1(Image=r"C:\x\evil.exe")) is True
    assert rule.match(_sysmon_1(Image=r"C:\x\calc.exe")) is False


def test_cross_user_rule_does_not_fire_without_parent_user():
    rule = _rule("windows/process_creation/proc_creation_win_susp_cross_user_process_spawn.yml")
    entry = _sysmon_1(Image=r"C:\Windows\System32\calc.exe", ParentImage=r"C:\Windows\System32\services.exe",
                      CommandLine="calc.exe", User=r"NT AUTHORITY\SYSTEM")
    assert rule.match(entry) is False


# --- per-group field availability ---

def test_remote_thread_rule_matches_with_empty_or_missing_optional_field():
    rule = _rule("windows/create_remote_thread/create_remote_thread_win_susp_uncommon_target_image.yml")
    entry = _entry(["windows", "sysmon", "create_remote_thread"], "[8] synthetic", EventID="8",
                   Channel="Microsoft-Windows-Sysmon/Operational", Provider_Name="Microsoft-Windows-Sysmon",
                   SourceImage=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                   TargetImage=r"C:\Windows\System32\notepad.exe", StartModule="")
    assert rule.match({**entry, "StartFunction": ""}) is True  # present but empty, as the adapter now emits it
    assert rule.match(entry) is True  # absent: the group still has SourceImage/TargetImage


def test_rundll32_network_rule_matches_without_command_line():
    rule = _rule("windows/network_connection/net_connection_win_rundll32_net_connections.yml")
    entry = _entry(["windows", "sysmon", "network_connection"], "[3] synthetic", EventID="3",
                   Channel="Microsoft-Windows-Sysmon/Operational", Provider_Name="Microsoft-Windows-Sysmon",
                   Image=r"C:\Windows\System32\rundll32.exe", Initiated="true", DestinationIp="93.184.216.34",
                   DestinationPort="8181")
    assert rule.match(entry) is True
