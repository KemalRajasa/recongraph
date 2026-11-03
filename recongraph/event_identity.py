"""Event identity for ``--node=drain``: which kind of event a timeline row is, for every row.

=====================  ======================================================  ===================================
Row                    Identity (``event_key``)                                Example
=====================  ======================================================  ===================================
EVTX                   ``Provider:EventID``                                    ``Microsoft-Windows-Sysmon:1``
structured artefact    ``data_type:timestamp_desc``, or ``data_type`` for a    ``fs:stat:Last Access Time``,
                       row without ``timestamp_desc``                          ``syslog:ssh:login:Content Modification Time``
free text              ``data_type:template``, template mined by Drain3        ``syslog:line:Server listening on
                                                                               <IP> port <NUM>.``
=====================  ======================================================  ===================================

Plaso CSV has no ``data_type``: ``parser`` takes its place, and ``text/*`` parsers count as free text.
Input with neither (a plain text log) is free text with the source ``text``.
"""
import json
import logging
import re
from collections import Counter, defaultdict
from importlib.metadata import version

import pandas as pd
from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.memory_buffer_persistence import MemoryBufferPersistence
from drain3.template_miner_config import TemplateMinerConfig

logging.getLogger("drain3").setLevel(logging.WARNING)

# Plaso data_types whose rows are log lines of varying shape. Everything else keeps one node per data_type, which never
# merges two data_types; add an entry once a real sample shows the type needs templates.
FREE_TEXT_DATA_TYPES = frozenset({
    "android:logcat",
    "ios:lockdownd_log:entry",
    "ios:sysdiag_log:entry",
    "ios:sysdiagnose:logd:line",
    "syslog:line",
    "systemd:journal",
})
# The raw log line, without the sentence Plaso's formatter builds around it.
RAW_TEXT_COLUMNS = ("message_body", "body")
_COLUMNS = ("parser", "data_type", "timestamp_desc", "message", "Provider_Name", "EventID", "Channel", *RAW_TEXT_COLUMNS)

DRAIN3_CONFIG = {"sim_th": 0.4, "depth": 4, "max_children": 100, "mask_prefix": "<", "mask_suffix": ">"}
# Order matters: a path or IP holds numbers, and a GUID holds hex.
DRAIN3_MASKING = (
    ("GUID", r"\{?\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b\}?"),
    ("SID", r"\bS-1-\d+(?:-\d+)+\b"),
    ("PATH", r"(?<![\w\\])(?:[A-Za-z]:)?\\{1,2}[^\s\"'<>|,;]+|(?<![\w/:.])(?:/[\w.\-]+)+/?"),
    # IPv6 needs "::" or all 8 groups, so file.c:183: and 10:20:30 stay out
    ("IP", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
           r"|(?<![\w:.])(?=[0-9a-fA-F:]*[0-9a-fA-F])(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?(?![\w:.])"
           r"|(?<![\w:.])(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?![\w:.])"),
    ("HEX", r"\b0[xX][0-9a-fA-F]+\b|\b(?=[0-9a-fA-F]*\d)[0-9a-fA-F]{8,}\b|\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5,}\b"),
    ("NUM", r"\b\d+(?:\.\d+)?\b"),
)

# The fixed sentence Plaso's winevtx formatter writes (data/formatters/windows.yaml), the only EVTX source in a CSV.
_EVTX_ID = re.compile(r"\[(\d+) / 0x[0-9a-fA-F]+\]")
_EVTX_SOURCE = re.compile(r"Source Name: (.+?)(?: Strings:| Hostname:| Computer Name:| Record Number:| Event Level:| Message string:|$)")
_EVTX_PROVIDER = re.compile(r"Provider identifier: (\S+)")
# Characters GraphML (XML 1.0) cannot hold.
_XML_UNSAFE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")


def xml_safe(text: str) -> str:
    return _XML_UNSAFE.sub("", text)


def new_template_miner() -> TemplateMiner:
    """A TemplateMiner with the pipeline's configuration and no persistence; save its state with drain3_state()."""
    config = TemplateMinerConfig()
    config.drain_sim_th = DRAIN3_CONFIG["sim_th"]
    config.drain_depth = DRAIN3_CONFIG["depth"]
    config.drain_max_children = DRAIN3_CONFIG["max_children"]
    config.mask_prefix = DRAIN3_CONFIG["mask_prefix"]
    config.mask_suffix = DRAIN3_CONFIG["mask_suffix"]
    config.masking_instructions = [MaskingInstruction(pattern, name) for name, pattern in DRAIN3_MASKING]
    config.snapshot_compress_state = False
    return TemplateMiner(config=config)


def drain3_state(miner: TemplateMiner) -> str:
    """The miner's state as jsonpickle text; TemplateMiner.load_state restores it through a persistence handler."""
    miner.persistence_handler = MemoryBufferPersistence()
    miner.save_state("final")
    return miner.persistence_handler.state.decode("utf-8")


def _source(row: dict) -> str:
    return row["data_type"] or row["parser"] or "text"


def _is_free_text(row: dict) -> bool:
    if row["data_type"]:
        return row["data_type"] in FREE_TEXT_DATA_TYPES
    return not row["parser"] or row["parser"].startswith("text/")


def _raw_text(row: dict) -> str:
    return next((row[column] for column in RAW_TEXT_COLUMNS if row[column]), row["message"])


def _evtx_key(row: dict) -> str:
    """Provider_Name:EventID; a CSV row or an event with unparsable XML has them only in the formatter's sentence."""
    message = row["message"]
    source, provider = _EVTX_SOURCE.search(message), _EVTX_PROVIDER.search(message)
    event_id = _EVTX_ID.match(message)
    name = (row["Provider_Name"] or (source and source.group(1)) or (provider and provider.group(1))
            or row["Channel"] or "unknown")
    return f"{name}:{row['EventID'] or (event_id and event_id.group(1)) or 'unknown'}"


def assign_event_keys(df: pd.DataFrame) -> tuple[list, dict, dict]:
    """(event key per row, Drain3 metadata, rows per source for evtx/structured/free_text); every row gets a key.

    Drain3 runs per data_type in two stages, so a row's template does not depend on when it arrived: first all rows
    train the miner, then ``match`` assigns each row to the final clusters.
    """
    rows = [{column: value.strip() if isinstance(value, str) else "" for column, value in row.items()}
            for row in df.reindex(columns=list(_COLUMNS)).to_dict("records")]

    miners = defaultdict(new_template_miner)
    sources = {"evtx": Counter(), "structured": Counter(), "free_text": Counter()}
    for row in rows:
        if row["parser"] == "winevtx":
            sources["evtx"][_source(row)] += 1
        elif not _is_free_text(row):
            sources["structured"][_source(row)] += 1
        else:
            sources["free_text"][_source(row)] += 1
            if text := _raw_text(row):
                miners[_source(row)].add_log_message(text)

    templates = {}

    def key(row: dict) -> str:
        source = _source(row)
        if row["parser"] == "winevtx":
            return _evtx_key(row)
        if not _is_free_text(row):
            return f"{source}:{row['timestamp_desc']}" if row["timestamp_desc"] else source
        text = _raw_text(row)
        if not text:
            return source
        if (source, text) not in templates:
            # "always": the best of all clusters, not the first the tree search finds
            templates[source, text] = miners[source].match(text, "always").get_template()
        return f"{source}:{templates[source, text]}"

    keys = [xml_safe(key(row)) for row in rows]
    metadata = {
        "version": version("drain3"),
        "config": {**DRAIN3_CONFIG, "masking": [{"mask_with": name, "pattern": pattern} for name, pattern in DRAIN3_MASKING]},
        "miners": {source: {"clusters": len(miner.drain.clusters), "snapshot": drain3_state(miner)}
                   for source, miner in sorted(miners.items())},
    }
    return keys, metadata, {kind: dict(sorted(counts.items())) for kind, counts in sources.items()}
