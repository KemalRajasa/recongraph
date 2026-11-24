"""Input adapters that normalize Plaso output into the columns SigmaLabel expects."""
import json
import logging
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)

GENERIC_COLUMNS = ["datetime", "timestamp_desc", "message", "parser", "display_name", "data_type", "log_type"]
SYSTEM_FIELDS = ["EventID", "Channel", "Provider_Name", "Computer", "EventRecordID", "Security_UserID", "Level"]
_XML_ILLEGAL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")
_PADDED_HEX = re.compile(r"0x0+([0-9a-fA-F]+)")

# Plaso event attributes the generic columns are read from.
_PLASO_GENERIC = {"timestamp", "timestamp_desc", "message", "parser", "display_name", "data_type"}

# Non-winevtx events: Plaso data_type prefix -> Sigma `product:`; unlisted prefixes get an empty log_type.
DATA_TYPE_PRODUCTS = {"syslog": "linux", "linux": "linux", "systemd": "linux", "selinux": "linux",
                      "android": "android", "ios": "ios"}
# Linux source file name (rotated or compressed copies included) -> Sigma `service:` (sigma tests/thor.yml).
LINUX_FILE_SERVICES = [(re.compile(r"(auth\.log|secure)([.-]\d+)*(\.(gz|bz2|xz))?"), "auth"),
                       (re.compile(r"(syslog|messages)([.-]\d+)*(\.(gz|bz2|xz))?"), "syslog")]
# Linux syslog/journal `reporter` (program name) -> Sigma `service:`.
LINUX_REPORTER_SERVICES = {"sshd": "sshd", "cron": "cron", "crond": "cron", "vsftpd": "vsftpd"}

# Plaso's selinux parser reads the Linux audit log; one audit event (an audit_serial at one time) is several records.
AUDIT_DATA_TYPE = "selinux:line"
# The order auditd writes an event's records in, after the record that triggered the event (CONFIG_CHANGE, LOGIN, ...),
# with PROCTITLE last; psort output does not keep it. Checked on every event of the CAM-LDS videoserver audit.log.
AUDIT_RECORD_ORDER = ("SYSCALL", "BPRM_FCAPS", "EXECVE", "SOCKADDR", "CWD", "PATH")
# PATH records follow their item number, EXECVE records (long argument lists are split) their first argument.
_AUDIT_RECORD_NUMBER = re.compile(r"\b(?:item=|a)(\d+)\b")
# auditd fields holding text: quoted, or hex-encoded when unquoted (text with a space, quote or control character), and
# (null) when empty; so are the arguments aN of EXECVE records. The aN of SYSCALL records are numbers and stay as written.
# Checked on the CAM-LDS videoserver audit.log: these are the fields it ever quotes, and their unquoted values are hex.
AUDIT_TEXT_FIELDS = {"proctitle", "cmd", "comm", "exe", "cwd", "name", "key", "acct"}
# name=value with a "double", 'single' quoted or bare value, or a bare word that continues the previous value
_AUDIT_FIELD = re.compile(r"""([^\s=]+)=("[^"]*"|'[^']*'|\S*)|(\S+)""")
# an EXECVE argument, or a piece of one (a1[0], a1[1], ... after a1_len) when it is too long for one record
_EXECVE_ARGUMENT = re.compile(r"(a\d+)(\[\d+\])?")
_HEX_TEXT = re.compile(r"(?:[0-9A-Fa-f]{2})+")

# EVTX Channel -> Sigma `service:` (names as used in sigma/rules/windows/builtin).
CHANNEL_SERVICES = {
    "Security": "security",
    "System": "system",
    "Application": "application",
    "Microsoft-Windows-Sysmon/Operational": "sysmon",
    "Microsoft-Windows-PowerShell/Operational": "powershell",
    "PowerShellCore/Operational": "powershell",
    "Windows PowerShell": "powershell-classic",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall": "firewall-as",
    "Microsoft-Windows-Bits-Client/Operational": "bits-client",
    "Microsoft-Windows-TaskScheduler/Operational": "taskscheduler",
    "Microsoft-Windows-Windows Defender/Operational": "windefend",
    "Microsoft-Windows-WMI-Activity/Operational": "wmi",
    "Microsoft-Windows-CodeIntegrity/Operational": "codeintegrity-operational",
    "Microsoft-Windows-AppXDeploymentServer/Operational": "appxdeployment-server",
    "Microsoft-Windows-AppxPackaging/Operational": "appxpackaging-om",
    "Microsoft-Windows-AppModel-Runtime/Admin": "appmodel-runtime",
    "MSExchange Management": "msexchange-management",
    "Microsoft-Windows-DNS Client Events/Operational": "dns-client",
    "DNS Server": "dns-server",
    "Microsoft-IIS-Configuration/Operational": "iis-configuration",
    "Microsoft-Windows-NTLM/Operational": "ntlm",
    "Microsoft-Windows-AppLocker/EXE and DLL": "applocker",
    "Microsoft-Windows-AppLocker/MSI and Script": "applocker",
    "Microsoft-Windows-AppLocker/Packaged app-Deployment": "applocker",
    "Microsoft-Windows-AppLocker/Packaged app-Execution": "applocker",
    "Microsoft-Windows-Security-Mitigations/KernelMode": "security-mitigations",
    "Microsoft-Windows-Security-Mitigations/UserMode": "security-mitigations",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": "terminalservices-localsessionmanager",
    "Microsoft-Windows-SMBServer/Connectivity": "smbserver-connectivity",
    "Microsoft-Windows-SmbClient/Security": "smbclient-security",
    "Microsoft-Windows-Shell-Core/Operational": "shell-core",
    "OpenSSH/Operational": "openssh",
    "Microsoft-ServiceBus-Client": "microsoft-servicebus-client",
    "Microsoft-Windows-LSA/Operational": "lsa-server",
    "Microsoft-Windows-LDAP-Client/Debug": "ldap",
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational": "driver-framework",
    "Microsoft-Windows-Diagnosis-Scripted/Operational": "diagnosis-scripted",
    "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational": "certificateservicesclient-lifecycle-system",
    "Microsoft-Windows-CAPI2/Operational": "capi2",
}

_SYSMON = {
    "1": ["process_creation"], "2": ["file_change"], "3": ["network_connection"], "4": ["sysmon_status"],
    "5": ["process_termination"], "6": ["driver_load"], "7": ["image_load"], "8": ["create_remote_thread"],
    "9": ["raw_access_thread"], "10": ["process_access"], "11": ["file_event"],
    "12": ["registry_add", "registry_delete", "registry_event"], "13": ["registry_set", "registry_event"],
    "14": ["registry_rename", "registry_event"], "15": ["create_stream_hash"], "16": ["sysmon_status"],
    "17": ["pipe_created"], "18": ["pipe_created"], "19": ["wmi_event"], "20": ["wmi_event"], "21": ["wmi_event"],
    "22": ["dns_query"], "23": ["file_delete"], "24": ["clipboard_capture"], "25": ["process_tampering"],
    "26": ["file_delete", "file_delete_detected"], "27": ["file_block_executable"], "28": ["file_block_shredding"],
    "29": ["file_executable_detected"], "255": ["sysmon_error"],
}
_POWERSHELL = {"4103": ["ps_module"], "4104": ["ps_script"]}

# (Channel, EventID) -> Sigma `category:` values.
EVENT_CATEGORIES = {
    **{("Microsoft-Windows-Sysmon/Operational", eid): cats for eid, cats in _SYSMON.items()},
    **{("Microsoft-Windows-PowerShell/Operational", eid): cats for eid, cats in _POWERSHELL.items()},
    **{("PowerShellCore/Operational", eid): cats for eid, cats in _POWERSHELL.items()},
    ("Windows PowerShell", "400"): ["ps_classic_start"],
    ("Windows PowerShell", "600"): ["ps_classic_provider_start"],
    ("Security", "4688"): ["process_creation"],
}

# (Channel, EventID) -> {source field: Sigma field}; the source field is kept as well.
FIELD_ALIASES = {
    ("Security", "4688"): {"NewProcessName": "Image", "ParentProcessName": "ParentImage"},
}


def detect_input_format(path) -> str:
    """Return "plaso_jsonl", "plaso_csv" or "text" for an input file."""
    path = Path(path)
    if path.suffix.lower() in (".jsonl", ".json"):
        return "plaso_jsonl"
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            first = next((line for line in f if line.strip()), "")
        if isinstance(obj := json.loads(first), dict) and "data_type" in obj:
            return "plaso_jsonl"
    except (OSError, ValueError):
        pass
    return "plaso_csv" if str(path).endswith(".csv") else "text"


def _local(tag: str) -> str:
    return tag.rpartition("}")[2]


def _unpad_hex(value: str) -> str:
    """0x0000002d -> 0x2d: libevtx zero-pads HexInt values, Windows (and Sigma rules) do not."""
    m = _PADDED_HEX.fullmatch(value)
    return f"0x{m.group(1)}" if m else value


def _parse_event_xml(xml: str, where: str) -> tuple[dict, str | None]:
    """Flatten an EVTX XML event into ({field: value}, UserData Channel); System fields win on name clashes."""
    root = ET.fromstring(xml)
    system = root.find("{*}System")
    fields = {}
    if system is not None:
        provider = system.find("{*}Provider")
        security = system.find("{*}Security")
        fields = {
            "EventID": system.findtext("{*}EventID"),
            "Channel": system.findtext("{*}Channel"),
            "Provider_Name": provider.get("Name") if provider is not None else None,
            "Computer": system.findtext("{*}Computer"),
            "EventRecordID": system.findtext("{*}EventRecordID"),
            "Security_UserID": security.get("UserID") if security is not None else None,
            "Level": system.findtext("{*}Level"),
        }
    reserved = set(SYSTEM_FIELDS) | set(GENERIC_COLUMNS)

    def add(name, value):
        if name in reserved:
            return
        if name in fields:
            logger.warning("%s: duplicate field %r, keeping the first value", where, name)
            return
        fields[name] = value

    unnamed = []
    for data in root.iterfind("{*}EventData/{*}Data"):
        name, text = data.get("Name"), _unpad_hex(data.text or "")
        if not name:
            unnamed.append(text)
            name = f"param{len(unnamed)}"
        add(name, text)
    if unnamed:
        add("Data", "\n".join(unnamed))
    for el in root.iterfind("{*}UserData//*"):
        if len(el) == 0:
            add(_local(el.tag), _unpad_hex(el.text or ""))
    return fields, root.findtext("{*}UserData//{*}Channel")


def _log_type(fields: dict) -> list:
    channel, event_id = fields.get("Channel") or "", fields.get("EventID") or ""
    service = CHANNEL_SERVICES.get(channel)
    return ["windows", *([service] if service else []), *EVENT_CATEGORIES.get((channel, event_id), [])]


def _source_path(pathspec) -> str | None:
    """Path of the parsed file: the innermost path spec with a location (a file inside an image or archive)."""
    while isinstance(pathspec, dict):
        if pathspec.get("location"):
            return pathspec["location"]
        pathspec = pathspec.get("parent")
    return None


def _event_attributes(obj: dict, row: dict, stats: Counter) -> dict:
    """Scalar Plaso event attributes as string columns, plus `source_path` from the nested pathspec.

    Plaso bookkeeping (``__*__``) and nested values (``date_time``, ``pathspec``, others counted in ``stats``)
    are not columns; an attribute named like a column the adapter sets itself gets a ``plaso_`` prefix.
    """
    fields = {}
    for key, value in obj.items():
        if key in _PLASO_GENERIC or key.startswith("__") or value is None:
            continue
        if isinstance(value, (dict, list)):
            stats["nested", key] += key not in ("date_time", "pathspec")
            continue
        name = f"plaso_{key}" if key in row or key == "source_path" else key
        # strings like the EVTX fields: SigmaLabel only matches str columns, and pandas turns int columns with gaps into floats
        fields[name] = value if isinstance(value, str) else json.dumps(value)
    if path := _source_path(obj.get("pathspec")):
        fields["source_path"] = path
    return fields


def _generic_log_type(row: dict) -> list:
    """Sigma logsource tokens for a non-winevtx event; see load_plaso_jsonl for the table."""
    product = DATA_TYPE_PRODUCTS.get(str(row.get("data_type") or "").partition(":")[0])
    if product != "linux":
        return [product] if product else []
    name = re.split(r"[\\/]", row.get("source_path") or "")[-1].lower()
    services = [service for pattern, service in LINUX_FILE_SERVICES if pattern.fullmatch(name)]
    reporter = LINUX_REPORTER_SERVICES.get(str(row.get("reporter") or "").lower())
    auditd = ["auditd"] if row.get("data_type") == AUDIT_DATA_TYPE else []
    return ["linux", *services, *([reporter] if reporter else []), *auditd]


def _iso(timestamp) -> str | None:
    if not isinstance(timestamp, int):
        return None
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=timestamp)).isoformat(timespec="microseconds")


def _record(obj: dict, where: str, stats: Counter) -> dict:
    row = {
        "datetime": _iso(obj.get("timestamp")),
        "timestamp_desc": obj.get("timestamp_desc"),
        "message": obj.get("message"),
        "parser": obj.get("parser"),
        "display_name": obj.get("display_name"),
        "data_type": obj.get("data_type"),
        "log_type": None,
        "_ts": obj.get("timestamp"),
    }
    if obj.get("parser") != "winevtx":
        row = {**row, **_event_attributes(obj, row, stats)}
        log_type = _generic_log_type(row)
        stats["unmapped", row["data_type"]] += not log_type
        return {**row, "log_type": log_type}
    raw = obj.get("xml_string") or ""
    xml = _XML_ILLEGAL_CHARS.sub("", raw)
    try:
        fields, userdata_channel = _parse_event_xml(xml, where)
    except ET.ParseError as e:
        stats["failed"] += 1
        logger.warning("%s: unparsable xml_string (%s); keeping generic columns only", where, e)
        return {**row, "log_type": ["windows"]}
    stats["recovered"] += xml != raw
    key = (fields.get("Channel"), fields.get("EventID"))
    aliases = {dst: fields[src] for src, dst in FIELD_ALIASES.get(key, {}).items() if src in fields}
    # log_type follows the System channel; rules such as EventID 104 match `Channel` against the cleared log
    matching_channel = {"Channel": userdata_channel} if userdata_channel else {}
    return {**row, **fields, **aliases, **matching_channel, "log_type": _log_type(fields)}


def _audit_record_rank(row: dict) -> tuple:
    kind = row.get("audit_type")
    if kind == "PROCTITLE":
        position = len(AUDIT_RECORD_ORDER) + 1
    else:
        position = AUDIT_RECORD_ORDER.index(kind) + 1 if kind in AUDIT_RECORD_ORDER else 0
    number = _AUDIT_RECORD_NUMBER.search(row.get("message_body") or "")
    return position, int(number.group(1)) if number else 0, row.get("message") or ""


def _audit_text(value: str) -> str | None:
    """A text field as auditd means it: quotes removed, hex decoded (NUL separators become spaces), None for (null)."""
    if value.startswith('"'):
        return value[1:-1]
    if value == "(null)":
        return None
    if _HEX_TEXT.fullmatch(value):
        return bytes.fromhex(value).decode("utf-8", errors="replace").replace("\x00", " ")
    return value


def _audit_fields(audit_type: str, body: str) -> dict:
    """The fields of one audit record, by their auditd names, from its text after ``msg=audit(...):``.

    The fields inside ``msg='...'`` (user space records such as USER_CMD) are fields of the record; on a name clash the
    outer field wins. Text fields are decoded (``_audit_text``), other quoted values lose their quotes.
    """
    fields, last = {}, None
    for match in _AUDIT_FIELD.finditer(body):
        name, value, word = match.groups()
        if word:  # a value with a space, e.g. subj==/usr/sbin/chronyd (enforce)
            if last:
                fields[last] += " " + word
            continue
        last = None
        if name == "msg" and value.startswith("'"):
            for key, inner in _audit_fields(audit_type, value[1:-1]).items():
                fields.setdefault(key, inner)
            continue
        argument = _EXECVE_ARGUMENT.fullmatch(name) if audit_type == "EXECVE" else None
        if argument or name in AUDIT_TEXT_FIELDS:
            value = _audit_text(value)
            if value is None:
                continue
        elif value[:1] in "\"'":
            value = value[1:-1]
        if argument and argument.group(2):
            fields[argument.group(1)] = fields.get(argument.group(1), "") + value
        elif name not in fields:
            fields[name] = value
            last = name
    return fields


def _audit_record(row: dict) -> dict:
    """What Sigma rules for auditd see of one record: ``type``, its fields, ``SYSCALL`` (the syscall name, which Plaso
    reads from the part of the line it leaves out of ``message_body``) and the record's ``message``."""
    record = {"type": row.get("audit_type"), **_audit_fields(row.get("audit_type"), row.get("message_body") or "")}
    if row.get("system_call"):
        record["SYSCALL"] = row["system_call"]
    record["message"] = row.get("message")
    return {key: value for key, value in record.items() if value is not None}


def _audit_event(records: list) -> dict:
    """One row for the records of one audit event, in the order auditd wrote them.

    Columns come from the records in that order, the first value winning, so the record that triggered the event (or
    SYSCALL) sets ``audit_type``; ``message`` and ``message_body`` are the records' values joined with newlines.
    ``audit_records`` is a JSON list of ``_audit_record`` per record, in the same order.
    """
    records = sorted(records, key=_audit_record_rank)
    event = {}
    for record in records:
        for key, value in record.items():
            event.setdefault(key, value)
    for column in ("message", "message_body"):
        event[column] = "\n".join(record[column] for record in records if record.get(column))
    event["audit_records"] = json.dumps([_audit_record(record) for record in records], ensure_ascii=False)
    return event


def load_plaso_jsonl(path, keep_all_timestamps: bool = False) -> pd.DataFrame:
    """Load `psort -o json_line` output: one row per event, event fields as columns, sorted by time.

    winevtx: EVTX XML fields as columns, one row per record (its "Creation Time" event) unless
    ``keep_all_timestamps``; log_type from Channel/EventID (CHANNEL_SERVICES, EVENT_CATEGORIES).

    Other parsers: scalar event attributes as string columns plus ``source_path``, every event kept (e.g. the
    three filestat timestamps, a call's start and end); log_type tokens:

    ==========================================  =========================================================
    data_type prefix                            log_type
    ==========================================  =========================================================
    syslog, linux, systemd, selinux             linux, + auth if the source file is auth.log* or secure*,
                                                + syslog if it is syslog* or messages*,
                                                + sshd / cron / vsftpd from the syslog ``reporter``,
                                                + auditd for the Linux audit log (``selinux:line``)
    android                                     android
    ios                                         ios
    anything else (fs:stat, windows:*, ...)     [] (rows kept, count logged; strict mode then matches
                                                only rules without a logsource)
    ==========================================  =========================================================

    Linux audit log (``selinux:line``): the records of one audit event (same source file, timestamp and
    ``audit_serial``) become one row, see ``_audit_event``, with the fields of each record in ``audit_records`` for
    Sigma rules (``_audit_record``). Rows with one timestamp follow the EVTX record number or the audit serial number.
    """
    rows = []
    audit_events = defaultdict(list)
    stats = Counter()
    with Path(path).open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except ValueError as e:
                logger.warning("%s:%d: invalid JSON line skipped (%s)", path, lineno, e)
                continue
            if not isinstance(obj, dict):
                logger.warning("%s:%d: JSON line is not an object, skipped", path, lineno)
                continue
            if not keep_all_timestamps and obj.get("parser") == "winevtx" and obj.get("timestamp_desc") != "Creation Time":
                continue
            row = _record(obj, f"{path}:{lineno}", stats)
            if row["data_type"] == AUDIT_DATA_TYPE and row.get("audit_serial"):
                audit_events[row.get("source_path") or row["display_name"], row["_ts"], row["audit_serial"]].append(row)
            elif row["data_type"] == AUDIT_DATA_TYPE:
                rows.append(_audit_event([row]))
            else:
                rows.append(row)
    rows += [_audit_event(records) for records in audit_events.values()]

    if audit_events:
        logger.info("%s: %d audit records merged into %d audit events",
                    path, sum(map(len, audit_events.values())), len(audit_events))
    if stats["recovered"] or stats["failed"]:
        logger.info("%s: %d records recovered by removing XML-illegal characters, %d still unparsable",
                    path, stats["recovered"], stats["failed"])
    for kind, text in (("unmapped", "rows without Sigma logsource tokens (log_type [])"),
                       ("nested", "nested attributes not kept as columns")):
        if counts := {k[1]: n for k, n in stats.items() if isinstance(k, tuple) and k[0] == kind and n}:
            logger.info("%s: %s: %s", path, text, counts)
    df =pd.DataFrame(rows, columns=None if rows else GENERIC_COLUMNS + ["_ts"])
    before_epoch = pd.to_numeric(df["_ts"], errors="coerce") < 0
    if before_epoch.any():
        logger.info("%s: dropped %d rows with timestamps before 1970-01-01", path, int(before_epoch.sum()))
    df = df[~before_epoch]
    # ties on the timestamp: EVTX record number or audit serial number, columns that no row has both of
    record_id = pd.Series(float("nan"), index=df.index)
    for column in ("EventRecordID", "audit_serial"):
        if column in df:
            record_id = record_id.fillna(pd.to_numeric(df[column], errors="coerce"))
    df = (df.assign(_ts=pd.to_numeric(df["_ts"], errors="coerce"), _rid=record_id)
            .sort_values(["_ts", "_rid"], kind="stable", na_position="last")
            .drop(columns=["_ts", "_rid"])
            .reset_index(drop=True))
    return df
