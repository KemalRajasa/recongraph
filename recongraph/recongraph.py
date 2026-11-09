import base64
import csv
import ipaddress
import itertools
import json
import logging
import re
import yaml
from pathlib import Path
from datetime import datetime, timedelta, timezone
from importlib.metadata import PackageNotFoundError, version
from statistics import median_low
from typing import List, Dict, Any
from collections import Counter, defaultdict
import networkx as nx
from collections import defaultdict
import os
import argparse
import pandas as pd
import re
import yaml
from typing import List, Dict, Any
from pathlib import Path

from recongraph.event_identity import assign_event_keys, xml_safe
from recongraph.input_adapters import GENERIC_COLUMNS, detect_input_format, load_plaso_jsonl

logger = logging.getLogger(__name__)

NODE_MODES = ("drain", "sigma")
SIGMA_LEVELS = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
_WINDASH = ("-", "/", "\u2013", "\u2014", "\u2015")  # Sigma windash: -, /, en dash, em dash, horizontal bar


def _windash(pattern: str) -> List[str]:
    """Every combination of the windash characters for each dash/slash that starts a command-line flag."""
    pieces = re.split(r"\B[-/]\b", pattern)
    return [pieces[0] + "".join(d + p for d, p in zip(dashes, pieces[1:]))
            for dashes in itertools.product(_WINDASH, repeat=len(pieces) - 1)]


def _base64(pattern: str) -> List[str]:
    return [base64.b64encode(pattern.encode()).decode()]


def _base64offset(pattern: str) -> List[str]:
    """The three base64 renderings of pattern at byte offsets 0/1/2 of a longer string (as in pySigma)."""
    data = pattern.encode()
    return [base64.b64encode(b" " * i + data).decode()[(0, 2, 3)[i]:(None, -3, -2)[(len(data) + i) % 3]]
            for i in range(3)]


_TRANSFORMS = {"windash": _windash, "base64": _base64, "base64offset": _base64offset}
SUPPORTED_MODIFIERS = frozenset({"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cidr", "fieldref",
                                 "exists", "lt", "lte", "gt", "gte", *_TRANSFORMS})


_RULE_ID = re.compile(r"[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}")


def read_rule_id_list(path) -> set:
    """Rule IDs of a list in the format of Hayabusa's exclude_rules.txt: one per line, ``#`` starts a comment, other lines are ignored."""
    with open(path, 'r', encoding='utf-8') as f:
        return {rule_id for rule_id in (line.split('#', 1)[0].strip() for line in f) if _RULE_ID.fullmatch(rule_id)}


class UnsupportedModifierError(ValueError):
    """A rule uses a field modifier the matcher does not implement."""


class SigmaMatcher:
    """
    Handles parsing Sigma rules from YAML files and evaluating them 
    against normalized log entries.

    This class processes Sigma rule detection logic, logsource requirements, 
    and metadata. It provides an evaluation engine that determines if a 
    specific log entry matches the rule's criteria, supporting field 
    modifiers and complex boolean conditions.
    """
    def __init__(self, rule_file: str, flexible_mode: bool = True, rule_data: Dict[str, Any] = None):
        if rule_data is None:
            with open(rule_file, 'r', encoding='utf-8') as f:
                rule_data = yaml.safe_load(f)
        self.rule_data = rule_data

        self.rule_id = str(self.rule_data.get('id', ''))
        self.title = self.rule_data.get('title', 'Unknown')
        self.description = self.rule_data.get('description', '')
        self.level = self.rule_data.get('level', 'medium')
        self.tags = self.rule_data.get('tags', [])
        self.detection = self.rule_data.get('detection', {})
        self.logsource = self.rule_data.get('logsource', {})
        self.flexible_mode = flexible_mode
        self._condition_warned = False
        self._negated_fields = self._negated_selection_fields()
        unsupported = sorted({m for key in self._field_keys() for m in str(key).split("|")[1:]} - SUPPORTED_MODIFIERS)
        if unsupported:
            raise UnsupportedModifierError(f"rule '{self.title}' uses unsupported modifier(s) {unsupported}")

    def _field_keys(self):
        """Every ``Field|modifier`` key of every map-shaped selection."""
        for key, value in self.detection.items():
            if key != 'condition':
                for item in (value if isinstance(value, list) else [value]):
                    if isinstance(item, dict):
                        yield from item

    def match(self, log_entry: Dict[str, Any]) -> bool:
        """
        Check if log entry matches rule.

        This function checks if a given log entry matches the Sigma rule's detection logic.
        It evaluates the conditions defined in the rule against the fields in the log entry.
        """
        if not log_entry:
            return False
            
        if self.logsource:
            # flexible mode only checks the product (a Linux rule must not match a Windows log)
            if not self._check_logsource(log_entry, ("product",) if self.flexible_mode else ("category", "product", "service")):
                return False    
    
        condition = self.detection.get('condition', '').lower().strip()
    
        selections = {}
        for key, value in self.detection.items():
            if key == 'condition':
                continue
            selections[key.lower()] = self._match_selection(value, log_entry)
    
        return self._evaluate_condition(condition, selections)

    def _check_logsource(self, log_entry: Dict[str, Any], keys=("category", "product", "service")) -> bool:
        """
        Check if log_entry match with the rule's expected logsource.

        This function validates whether the log entry originates from the log source
        specified in the Sigma rule: every one of ``keys`` (category, product, service)
        the rule names must appear as an exact (case-insensitive) element of ``log_type``.
        """
        log_types = log_entry.get("log_type", [])
        if isinstance(log_types, str):
            log_types = [log_types]
        log_types_lower = {lt.lower() for lt in log_types}

        return all(str(self.logsource[key]).lower() in log_types_lower for key in keys if self.logsource.get(key))

    def _negated_groups(self, names: List[str]) -> List[List[str]]:
        """
        Selections the condition negates, grouped the way they are negated.

        ``not 1 of X*`` / ``not all of X*`` / ``not 1 of them`` give one group holding every
        matching selection; ``not X`` gives a one-selection group; each reference inside a
        ``not ( ... )`` is its own group. Double negation (``not (a and not b)``) still counts
        ``b`` as negated.
        """
        condition = self.detection.get('condition', '')
        if isinstance(condition, list):
            condition = " or ".join(map(str, condition))
        tokens = re.findall(r"[()]|[\w*]+", str(condition).lower())
        groups, group_negated, pending_not = [], [False], False
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token == "not":
                pending_not = True
            elif token == "(":
                group_negated.append(group_negated[-1] or pending_not)
                pending_not = False
            elif token == ")":
                if len(group_negated) > 1:
                    group_negated.pop()
            elif token not in ("and", "or"):
                if i + 2 < len(tokens) and tokens[i + 1] == "of":
                    target, i = tokens[i + 2], i + 2
                    refs = names if target == "them" else (
                        [n for n in names if n.startswith(target[:-1])] if target.endswith("*") else [target])
                else:
                    refs = [token]
                group = [r for r in refs if r in names]
                if group and (pending_not or group_negated[-1]):
                    groups.append(group)
                pending_not = False
            i += 1
        return groups

    def _negated_selection_fields(self) -> List[tuple]:
        """[(field-based selections of a negated group, field names they reference)]; keyword-only selections are skipped."""
        fields = {}
        for key, value in self.detection.items():
            if key == 'condition':
                continue
            maps = value if isinstance(value, list) else [value]
            refs = {f.split('|')[0] for m in maps if isinstance(m, dict) for f in m if not str(f).startswith('|')}
            if refs:
                fields[key.lower()] = refs
        names = [k.lower() for k in self.detection if k != 'condition']
        negated = []
        for group in self._negated_groups(names):
            members = [n for n in group if n in fields]
            if members:
                negated.append((members, set().union(*(fields[n] for n in members))))
        return negated

    def _unavailable_negations(self, log_entry: Dict[str, Any]) -> List[str]:
        """Selections of negated groups whose fields are all absent from the entry (an empty value counts as present, a fallback does not)."""
        return [name for members, refs in self._negated_fields
                if not any(log_entry.get(f) is not None for f in refs) for name in members]

    @staticmethod
    def _is_null(pattern) -> bool:
        """Sigma `null` (YAML null, or the literal 'null'): the field is missing. As in Hayabusa, a present but empty field is not null."""
        return pattern is None or str(pattern).lower() == "null"

    def _match_selection(self, selection, log_entry: Dict) -> bool:
        """
        Match selection with log entry.

        This function iterates through the selection criteria (strings, lists, or dictionaries)
        and checks if the log entry satisfies them. in flexible mode, it searches broadly.
        """
        search_fields = self._get_search_fields(log_entry)
        
        if isinstance(selection, list):
            for pattern in selection:
                if isinstance(pattern, dict):  # a list of maps is an OR of map selections
                    if self._match_selection(pattern, log_entry):
                        return True
                    continue
                pattern_lower = str(pattern).lower()
                if self._match_simple_pattern(pattern_lower, search_fields):
                    return True
            return False 

        if isinstance(selection, str):
            pattern_lower = str(selection).lower()
            return self._match_simple_pattern(pattern_lower, search_fields)

        if not isinstance(selection, dict):
            return False

        for field, patterns in selection.items():
            if field == '|all':
                patterns = patterns if isinstance(patterns, list) else [patterns]
                for pattern in patterns:
                    pattern_lower = str(pattern).lower()
                    if not self._match_simple_pattern(pattern_lower, search_fields):
                        return False
                return True
            
            if field == '|any':
                patterns = patterns if isinstance(patterns, list) else [patterns]
                for pattern in patterns:
                    pattern_lower = str(pattern).lower()
                    if self._match_simple_pattern(pattern_lower, search_fields):
                        return True
                return False

            field_name, modifiers = self._parse_field(field)
            patterns = patterns if isinstance(patterns, list) else [patterns]
            if not self._match_field(log_entry, field_name, modifiers, patterns):
                return False

        return True

    def _match_field(self, log_entry: Dict, field_name: str, modifiers: List[str], patterns: list) -> bool:
        """
        Match one ``Field|modifier|...`` key against its patterns.

        Transform modifiers (windash, base64, base64offset) expand each pattern into variants first;
        a pattern matches when one of its variants matches. ``all`` requires every pattern to match,
        otherwise one is enough. A null pattern matches only a missing field, not an empty one.
        """
        value = self._get_field_value(log_entry, field_name)
        if "exists" in modifiers:
            return all(str(p).lower() not in ("false", "no", "0") for p in patterns) == (value is not None)
        results = []
        for p in patterns:
            if self._is_null(p):
                results.append(value is None)
                continue
            variants = [str(p)]
            for m in modifiers:
                if m in _TRANSFORMS:
                    variants = [v for x in variants for v in _TRANSFORMS[m](x)]
            results.append(value is not None and any(self._match_value(value, v, modifiers, log_entry) for v in variants))
        return all(results) if "all" in modifiers else any(results)

    def _match_simple_pattern(self, pattern: str, search_fields: List[str]) -> bool:
        """
        Matches a simple pattern string against a list of search fields.

        This function checks if the pattern exists as a substring in any of the provided search fields.
        """
        return any(pattern in field for field in search_fields)

    def _get_search_fields(self, log_entry: Dict) -> List[str]:
        """
        Get all searchable fields from log entry.

        This function gathers values from various fields in the log entry to form a list
        of text strings to search against. In flexible mode, it includes almost all values.
        """
        search_fields = []
        if 'desc' in log_entry:
            search_fields.append(str(log_entry.get('desc', '')).lower())
        
        if self.flexible_mode:
             for k, v in log_entry.items():
                 if k not in ['log_type'] and v:
                     search_fields.append(str(v).lower())
        else:
            http_fields = ['c-uri', 'cs-uri-query', 'cs-user-agent', 'cs-referer', 'cs-method']
            for field in http_fields:
                if field in log_entry and log_entry[field]:
                    search_fields.append(str(log_entry[field]).lower())
            
            extra_fields =  ['command', 'commandline', 'process', 'image', 'parentimage']
            for field in extra_fields:
                if field in log_entry and log_entry[field]:
                    search_fields.append(str(log_entry[field]).lower())
        
        return search_fields if search_fields else ['']

    def _get_field_value(self, log_entry: Dict, field_name: str):
        """
        Get the value of a field from the log entry, or None when it is absent.

        This function retrieves the raw value of a specific field from the log entry,
        handling field mapping (e.g., 'uri' -> 'c-uri'). Only strict mode maps
        CommandLine/command onto the whole message.
        """
        if field_name in log_entry:
            return None if log_entry[field_name] is None else str(log_entry[field_name])
        
        field_mappings = {
            'uri': 'c-uri',
            'url': 'c-uri',
            'query': 'cs-uri-query',
            'useragent': 'cs-user-agent',
            'user_agent': 'cs-user-agent',
            'method': 'cs-method',
            'status': 'sc-status',
            'message': 'desc',
            'msg': 'desc',
            'commandline': 'desc',
            'command': 'desc',
        }

        mapped_field = field_mappings.get(field_name.lower())
        if self.flexible_mode and field_name.lower() in ('commandline', 'command'):
            mapped_field = None  # flexible mode falls back to the message only for keyword selections
        if mapped_field and mapped_field in log_entry:
            return str(log_entry[mapped_field])
        
        return None

    def _parse_field(self, field: str):
        """
        Parse a field string into (field_name, [modifier, ...]).

        This function splits a field string like 'fieldname|contains|all' into the field
        name and its whole modifier chain.
        """
        name, *modifiers = str(field).split("|")
        return name, modifiers

    def _match_value(self, value: str, pattern: str, modifiers: List[str], log_entry: Dict = None) -> bool:
        """
        Match a pattern against a field value under a modifier chain.

        String comparisons are case-insensitive, except after base64/base64offset and for
        ``re`` without ``i`` (Sigma semantics). cidr, lt/lte/gt/gte and fieldref do not match
        values they cannot interpret.
        """
        if "re" in modifiers:
            flags = sum(f for m, f in (("i", re.IGNORECASE), ("m", re.MULTILINE), ("s", re.DOTALL)) if m in modifiers)
            return bool(re.search(pattern, value, flags))
        if "cidr" in modifiers:
            try:
                return ipaddress.ip_address(value.strip()) in ipaddress.ip_network(pattern, strict=False)
            except ValueError:
                return False
        for m, compare in (("lt", float.__lt__), ("lte", float.__le__), ("gt", float.__gt__), ("gte", float.__ge__)):
            if m in modifiers:
                try:
                    return compare(float(value), float(pattern))
                except ValueError:
                    return False
        if "fieldref" in modifiers:
            pattern = self._get_field_value(log_entry or {}, pattern)
            if pattern is None:
                return False
        if not ({"base64", "base64offset"} & set(modifiers)):
            value, pattern = value.lower(), pattern.lower()
        if "contains" in modifiers: return pattern in value
        if "startswith" in modifiers: return value.startswith(pattern)
        if "endswith" in modifiers: return value.endswith(pattern)
        return value == pattern

    def _evaluate_condition(self, condition: str, selections: Dict[str, bool]) -> bool:
        """
        Evaluate a condition based on the selections.

        This function evaluates the logical condition string (e.g., 'selection1 and not selection2')
        using the results of the selection matching.
        """
        if not condition:
            return any(selections.values())
    
        condition = " ".join(condition.lower().split())
        
        def replace_x_of(match):
            count_str = match.group(1) 
            prefix = match.group(2)
            
            matching_vals = [v for k, v in selections.items() if k.startswith(prefix)]
            if not matching_vals: return "False"

            if "not" in count_str:
                 target = int(count_str.replace("not", "").strip())
                 return str(not (sum(matching_vals) >= target))
            elif "all" in count_str:
                 return str(all(matching_vals))
            else:
                 target = int(count_str)
                 return str(sum(matching_vals) >= target)

        condition = re.sub(r'((?:not\s+)?\d+|all)\s+of\s+(\w+)\*?', replace_x_of, condition)

        if "all of them" in condition: condition = condition.replace("all of them", str(all(selections.values())))
        if "1 of them" in condition: condition = condition.replace("1 of them", str(any(selections.values())))
        if "any of them" in condition: condition = condition.replace("any of them", str(any(selections.values())))
        
        for key, result in selections.items():
            condition = re.sub(rf"\b{re.escape(key)}\b", str(result), condition)

        try:
            return bool(eval(condition))
        except Exception:
            if not self._condition_warned:
                self._condition_warned = True
                logger.warning("Cannot evaluate condition of rule '%s': %r; falling back to any(selections)",
                               self.title, self.detection.get('condition', condition))
            return any(selections.values())


class SigmaRulesLoader:
    """
    Manages the lifecycle of Sigma rules within a specified directory.

    This class handles searching for, loading, and initializing Sigma rules into 
    executable matchers. It provides a high-level interface for checking log 
    entries against the entire rule set and managing rule-specific metadata.
    """
    def __init__(self, rules_dir: str, flexible_mode: bool = True, exclude_status=(), exclude_rules_file: str = None):
        self.rules_dir = rules_dir
        self.flexible_mode = flexible_mode
        self.exclude_status = set(exclude_status)
        self.exclude_rules_file = exclude_rules_file
        self.matchers = []
        self.skipped = []
        self.skip_counts = dict.fromkeys(("status", "exclude_list", "unsupported_modifier", "invalid"), 0)
        self.skipped_by_status = Counter()
        self._load_rules()

    def _load_rules(self):
        """
        Loads all rules from desired directory.

        This function scans the specified rules directory for YAML files,
        creates a SigmaMatcher for each, and stores them in the matchers list.
        """
        if not self.rules_dir:
            print("No rules directory specified. Skipping rule loading.")
            return

        rules_path = Path(self.rules_dir)
        if not rules_path.exists():
            print(f"Rules directory {rules_path} does not exist")
            return
        
        mode_str = "FLEXIBLE" if self.flexible_mode else "STRICT"
        print(f"- Loading Sigma Rules from: {self.rules_dir} (Mode: {mode_str})")
        
        exclude_ids = read_rule_id_list(self.exclude_rules_file) if self.exclude_rules_file else set()
        loaded_count = 0
        for rule_file in sorted(rules_path.glob('**/*.yml')):
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule_data = yaml.safe_load(f)
                # same order as Hayabusa: an excluded rule counts as excluded whatever its status
                if str(rule_data.get('id', '')) in exclude_ids:
                    self.skip_counts["exclude_list"] += 1
                    continue
                if rule_data.get('status') in self.exclude_status:
                    self.skip_counts["status"] += 1
                    self.skipped_by_status[rule_data['status']] += 1
                    continue
                matcher = SigmaMatcher(str(rule_file), flexible_mode=self.flexible_mode, rule_data=rule_data)
                self.matchers.append({
                    'matcher': matcher,
                    'title': matcher.title,
                    'level': matcher.level,
                })
                loaded_count += 1
            except UnsupportedModifierError as e:
                logger.warning("Skipping %s: %s", rule_file.name, e)
                self.skipped.append(str(e))
                self.skip_counts["unsupported_modifier"] += 1
            except Exception:
                self.skip_counts["invalid"] += 1
        
        print(f"- Total rules loaded: {loaded_count} rules")
        if self.skipped:
            print(f"- Skipped {len(self.skipped)} rules with unsupported modifiers")
        if self.skip_counts["status"] or self.skip_counts["exclude_list"]:
            print(f"- Skipped {self.skip_counts['status']} rules by status and {self.skip_counts['exclude_list']} by exclude list")

    def summary(self) -> Dict[str, Any]:
        """Rules loaded and skipped per reason, and the options that selected them (for the run metadata)."""
        return {
            "loaded": len(self.matchers),
            "skipped": self.skip_counts,
            "skipped_by_status": dict(sorted(self.skipped_by_status.items())),
            "exclude_status": sorted(self.exclude_status),
            "exclude_rules_file": self.exclude_rules_file,
        }

    def check_row(self, parsed_row: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Check if a row matches any of the loaded rules.

        This function iterates through all loaded rules and checks if the given
        parsed log row matches any of them. Returns a list of matching rules.
        """
        matches = []
        for rule_info in self.matchers:
            matcher = rule_info['matcher']
            if matcher.match(parsed_row):
                matches.append({
                    'rule_title': matcher.title,
                    'rule_level': matcher.level,
                    'rule_id': matcher.rule_id,
                })
        return matches

    def extract_sigma_priority(self, sigma_value: str) -> str:
        """
        Select top priority rule based on severity.

        This function parses a string of matched Sigma rules (formatted as 
        'Title[Severity] | Title[Severity]') and determines the highest priority
        match based on severity level. Ties go to the alphabetically first label, so the
        result does not depend on rule load order (rules with the same title and level
        produce the same label anyway).
        """
        if not sigma_value or not sigma_value.strip():
            return ""

        items = [s.strip() for s in sigma_value.split("|")]
        scored = [(SIGMA_LEVELS.get(item[item.rfind("[") + 1:item.rfind("]")].lower().strip(), 0), item)
                  for item in items if "[" in item and "]" in item]
        best = max((score for score, _ in scored), default=0)
        return min(item for score, item in scored if score == best) if best else ""


class SigmaLabel(object):
    """
    Orchestrates the log labeling process using Sigma rules.

    This class is responsible for reading input log files (CSV or TXT), 
    identifying the appropriate log type and source, and applying the loaded 
    Sigma rules to each entry to generate a labeled dataset.
    """
    def __init__(self, input_file, rules_dir=None, flexible_mode=True, keep_all_timestamps=False,
                 exclude_status=(), exclude_rules_file=None):
        self.input_file = input_file
        self.rules_dir = rules_dir
        self.flexible_mode = flexible_mode
        self.keep_all_timestamps = keep_all_timestamps
        self.exclude_status = exclude_status
        self.exclude_rules_file = exclude_rules_file
        self.rules_loader = None

    def count_lines(self):
        """
        Counts the number of lines in the input file.

        This function reads the input file to count the total number of lines,
        which is useful for progress tracking.
        """
        cnt = 0
        try:
            with open(self.input_file, 'r', encoding='utf-8', errors='replace') as f:
                for _ in f: cnt += 1
        except:
             pass
        return cnt

    def detect_log_type(self, desc: str, filename: str) -> Dict[str, Any]:
        """
        Detects the type of log entry based on its description and filename.

        This function analyzes the log description and filename to categorize the log
        (e.g., 'webserver', 'linux', 'windows') and extracts relevant fields like
        HTTP methods or status codes.
        """
        parsed = {}
        log_types = []
        lower_desc = desc.lower()
        
        if 'access.log' in filename:
            log_types.extend(['webserver', 'proxy', 'nginx', 'apache'])
            self._extract_http_fields(desc, parsed)
            
        if 'auth.log' in filename:
            log_types.extend(['linux', 'auth', 'sshd'])
            if 'pam' in lower_desc: log_types.append('pam')
        if 'syslog' in filename:
            log_types.extend(['syslog', 'linux'])
            if 'systemd' in lower_desc: log_types.append('systemd')
            if 'kernel' in lower_desc: log_types.append('kernel')
            if 'audit' in lower_desc: log_types.append('auditd')

        if 'windows' in filename.lower() or '.evtx' in filename.lower():
            log_types.append('windows')
            if 'sysmon' in filename.lower(): log_types.append('sysmon')
            if 'security' in filename.lower(): log_types.append('security')
            if 'system' in filename.lower(): log_types.append('system')

        if self._looks_like_http_log(desc):
             if 'webserver' not in log_types: log_types.extend(['webserver', 'generic_http'])
             if 'cs-method' not in parsed: self._extract_http_fields(desc, parsed)
             
        if not log_types:
            log_types.append('unknown')

        parsed['log_type'] = log_types
        return parsed

    def _looks_like_http_log(self, desc: str)-> bool:
        """
        Detects if a log entry looks like an HTTP log entry.

        This function uses regular expressions to check for common HTTP log patterns,
        such as HTTP methods, status codes, or user-agent strings.
        """
        http_indicators = [
            r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b',
            r'HTTP/\d\.\d',
            r'\b(200|301|302|400|401|403|404|500)\b',
            r'user[_-]?agent',
            r'referer',
        ]
        for pattern in http_indicators:
            if re.search(pattern, desc, re.IGNORECASE):
                return True
        return False

    def _extract_http_fields(self, desc: str, parsed: Dict[str, Any]):
        """
        Extracts HTTP fields from a log entry description.

        This function parses the log description to extract HTTP Method, URI, 
        Status Code, and User Agent, populating the 'parsed' dictionary.
        """
        method_match = re.search(r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b', desc)
        if method_match: parsed['cs-method'] = method_match.group(1)
        
        uri_match = re.search(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP', desc)
        if uri_match:
            parsed['c-uri'] = uri_match.group(2)
        else:
            uri_match = re.search(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s\"]+)', desc)
            if uri_match: parsed['c-uri'] = uri_match.group(2)

        status_match = re.search(r'code:\s*(\d{3})', desc)
        if status_match: parsed['sc-status'] = status_match.group(1)
        
        ua_match = re.search(r'user_agent:\s*(.+?)(?:\s+\w+:|$)', desc)
        if ua_match: parsed['cs-user-agent'] = ua_match.group(1).strip()

    def run(self):
        """
        Processes the input file and returns a labeled DataFrame.

        This function orchestrates the loading of data, detection of log types,
        matching against Sigma rules, and generation of a labeled DataFrame.
        """
        rules_loader = SigmaRulesLoader(self.rules_dir, flexible_mode=self.flexible_mode,
                                        exclude_status=self.exclude_status, exclude_rules_file=self.exclude_rules_file)
        self.rules_loader = rules_loader
        
        if not rules_loader.matchers:
             print("No rules loaded! Continuing without matching...")

        input_format = detect_input_format(self.input_file)
        df = pd.DataFrame()

        if input_format == "plaso_jsonl":
            df = load_plaso_jsonl(self.input_file, keep_all_timestamps=self.keep_all_timestamps)
        elif input_format == "plaso_csv":
            try:
                df = pd.read_csv(self.input_file, dtype=str)
            except:
                df = pd.read_csv(self.input_file, header=None, dtype=str)
                df.columns = [f'col_{i}' for i in range(len(df.columns))]
        else:
            try:
                with open(self.input_file, 'r', encoding='utf-8', errors='replace') as f:
                    lines = f.readlines()
                df = pd.DataFrame({'description': lines})
                df['filename'] = self.input_file
            except Exception as e:
                print(f"Error reading file: {e}")
                return df

        event_fields = [c for c in df.columns if c not in GENERIC_COLUMNS] if input_format == "plaso_jsonl" else []
        processed_rows = []
        total_rows = len(df)
        print(f"- Labeling {total_rows} rows...")
        
        count = 0 
        for _, row in df.iterrows():
            count += 1
            if count % 1000 == 0:
                print(f"- Processed {count}/{total_rows} lines...")

            desc = ""
            if 'message' in row: desc = str(row['message'])
            elif 'desc' in row: desc = str(row['desc'])
            elif 'description' in row: desc = str(row['description']) 
            elif len(row) > 4 and isinstance(row.values[4], str) : desc = row.values[4]
            else: desc = str(row.values[0])

            fname = self.input_file
            if 'filename' in row: fname = str(row['filename'])
            elif 'source_short' in row: fname = str(row['source_short'])
            elif 'display_name' in row: fname = str(row['display_name'])
            elif 'source' in row: fname = str(row['source'])
            elif len(row) > 6 and isinstance(row.values[6], str): fname = row.values[6]

            if input_format == "plaso_jsonl" and isinstance(row.get('log_type'), list):
                features = {"log_type": row['log_type']}
                log_entry = {k: row[k] for k in event_fields if isinstance(row[k], str)}
                log_entry.update(desc=desc, log_type=row['log_type'])
            else:
                features = self.detect_log_type(str(desc), str(fname))

                log_entry = {
                    "desc": desc,
                    "log_type": features["log_type"],
                    "cs-method": features.get("cs-method", ""),
                    "c-uri": features.get("c-uri", ""),
                    "sc-status": features.get("sc-status", ""),
                    "cs-user-agent": features.get("cs-user-agent", ""),
                    "service": features.get("service", ""),
                }

            matches = rules_loader.check_row(log_entry)
            detection_str = " | ".join(sorted({f"{m['rule_title']}[{m['rule_level']}]" for m in matches}))

            new_row = row.to_dict()
            new_row['logsource'] = str(features['log_type'])
            new_row['sigma'] = rules_loader.extract_sigma_priority(detection_str)
            new_row['sigma_all'] = detection_str
            # sorted by rule ID; not aligned with sigma_all, where rules sharing a title and level are one label
            new_row['sigma_ids'] = " | ".join(sorted({m['rule_id'] for m in matches if m['rule_id']}))
            processed_rows.append(new_row)

        return pd.DataFrame(processed_rows)


class EdgeGraph(object):
    """
    Constructs a directed graph from sigma-labeled logs to visualize system behavior.

    This class transforms a sequential list of security events into a 
    MultiDiGraph where nodes represent unique event types and edges represent 
    temporal transitions between them. It captures event frequency and 
    associated log metadata to facilitate forensic analysis.

    Transitions follow timestamp order (``edge_order="time"``, ties keep row order)
    or row order (``edge_order="file"``, the original behavior).

    Nodes are the Sigma labels and only labeled rows are mapped (``node_mode="sigma"``), or the event
    identity of every row with Sigma as node and row attributes (``node_mode="drain"``, see
    ``recongraph.event_identity``). This class defaults to ``"sigma"``; ReconGraph and the CLI to ``"drain"``.
    """
    def __init__(self, df: pd.DataFrame, edge_order: str = "time", node_mode: str = "sigma"):
        if edge_order not in ("time", "file"):
            raise ValueError(f"edge_order must be 'time' or 'file', got {edge_order!r}")
        if node_mode not in NODE_MODES:
            raise ValueError(f"node_mode must be one of {NODE_MODES}, got {node_mode!r}")
        self.edge_order = edge_order
        self.node_mode = node_mode
        self.key_column = "sigma" if node_mode == "sigma" else "event_key"
        self.df = df.copy()
        
        if 'message' not in self.df.columns:
            if 'desc' in self.df.columns:
                self.df.rename(columns={'desc': 'message'}, inplace=True)
            elif 'description' in self.df.columns:
                self.df.rename(columns={'description': 'message'}, inplace=True)
            else:
                 self.df['message'] = ""

        if 'datetime' not in self.df.columns:
            if 'timestamp' in self.df.columns:
                 self.df.rename(columns={'timestamp': 'datetime'}, inplace=True)
            else:
                 self.df['datetime'] = ""

        self.events_dict = {}
        self.node_labels = {}
        self.node_events = []
        self.G = nx.MultiDiGraph()
        
        self.log_event_id = []
        self.node_members = defaultdict(list)
        self.event_logs = defaultdict(list)
        self.event_timestamps = defaultdict(list)
        self.event_rows = defaultdict(list)
        self.event_times_us = defaultdict(list)
        self.sequence = []

        self.edges_list = []
        self.edges_weight = defaultdict(int)
        self.edges_weight_list = []
        self.temporal_edges = []
        self.edge_transitions = defaultdict(list)
        self.T = nx.MultiDiGraph()
        self.drain3 = None
        self.event_sources = None
        if node_mode == "drain":
            self._assign_event_identity()

    def _assign_event_identity(self):
        """Add event_key and the row's Sigma annotation; empty values are "", which GraphML can store."""
        self.df[['message', 'datetime']] = self.df[['message', 'datetime']].fillna("")
        self.df['sigma'] = self.df['sigma'].fillna("") if 'sigma' in self.df.columns else ""
        self.df['sigma_all'] = self.df['sigma_all'].fillna("") if 'sigma_all' in self.df.columns else self.df['sigma']
        # not "level": Plaso attributes and EVTX fields can use that name
        self.df['sigma_level'] = self.df['sigma'].map(self.extract_level)
        self.df['event_key'], self.drain3, self.event_sources = assign_event_keys(self.df)

    @staticmethod
    def _to_epoch_us(values: pd.Series) -> list:
        """Parse timestamps as UTC; epoch microseconds per value, None when empty or invalid."""
        parsed = pd.to_datetime(values, utc=True, errors="coerce", format="ISO8601")
        epoch, one_us = pd.Timestamp(0, tz="UTC"), pd.Timedelta(1, "us")
        return [None if pd.isna(t) else (t - epoch) // one_us for t in parsed]

    @staticmethod
    def _time_attrs(name: str, epoch_us: int) -> dict:
        iso = (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=epoch_us)).isoformat(timespec="microseconds")
        return {name: iso, f"{name}_us": epoch_us}

    def define_events(self):
        """
        Identify unique events from the dataset.

        This function iterates through the identity column ('sigma' or 'event_key', see ``node_mode``)
        to find all unique values. These define the nodes of the graph: each one
        becomes a distinct node in the resulting behavioral map.
        """
        lines = self.df['message'].tolist()

        if self.key_column in self.df.columns:
             identities = self.df[self.key_column]
             events = self.df[identities.notna() & (identities != '')][self.key_column].unique().tolist()
        else:
             events = []

        self.events_dict = {}
        for index, event in enumerate(events):
            self.events_dict[event] = index
        self.node_labels = {}
        for index, event in enumerate(events):
            self.node_labels[index] = event

        self.node_events = []
        for index, event in enumerate(events):
            self.node_events.append((index, {'event': f"{str(index)}. {event}"}))

    def create_graph(self):
        """
        Initialize the graph with nodes.

        This function creates a new networkx MultiDiGraph and adds the identified events
        as nodes.
        """
        self.G = nx.MultiDiGraph()
        self.G.add_nodes_from(self.node_events)
        print(f"Graph nodes added: {self.G.number_of_nodes()}")

    def get_list_event_id(self):
        """
        Map log entries to event IDs.

        This function processes the DataFrame rows, identifying which event ID corresponds
        to each log entry based on its identity column, and stores this mapping.
        """
        self.log_event_id = []
        self.node_members = defaultdict(list)
        self.event_logs = defaultdict(list)
        self.event_timestamps = defaultdict(list)
        self.event_rows = defaultdict(list)
        self.event_times_us = defaultdict(list)
        self.sequence = []
        times_us = self._to_epoch_us(self.df['datetime'])

        for position, (line_id, row) in enumerate(self.df.iterrows()):
            sigma_value = row.get(self.key_column)
            desc_value = row.get('message')
            timestamp_value = row.get('datetime')

            if pd.notna(sigma_value) and sigma_value != '':
                if sigma_value in self.events_dict:
                    event_id = self.events_dict[sigma_value]
                    self.log_event_id.append(event_id)
                    self.node_members[event_id].append(line_id)
                    self.event_logs[event_id].append(desc_value)
                    self.event_timestamps[event_id].append(timestamp_value)
                    self.event_rows[event_id].append(position)
                    self.event_times_us[event_id].append(times_us[position])
                    self.sequence.append((event_id, times_us[position], position))

        missing = sum(t is None for _, t, _ in self.sequence)
        if missing:
            logger.info("%d labeled rows have an empty or invalid timestamp; their time attributes are left empty", missing)

    @staticmethod
    def extract_level(sigma_label: str) -> str:
        """
        Extract the severity level from a sigma label string.

        Sigma labels are formatted as ``"<Rule Title>[<level>]"`` (e.g.
        ``"SSH Brute Force[high]"``). This function pulls the trailing
        ``[<level>]`` token out and returns it lowercased, or an empty string
        when no level token is present.
        """
        if not sigma_label:
            return ""
        open_idx = sigma_label.rfind("[")
        close_idx = sigma_label.rfind("]")
        if open_idx != -1 and close_idx != -1 and close_idx > open_idx:
            return sigma_label[open_idx + 1:close_idx].strip().lower()
        return ""

    def add_node_attributes(self):
        """
        Enrich nodes with attributes.

        This function adds metadata to each node in the graph, such as the first log snippet,
        timestamp, the count of logs, and the severity level associated with that event.
        """
        for event_id in self.event_logs.keys():
            logs = self.event_logs[event_id]
            timestamps = self.event_timestamps[event_id]


            if logs:
                first_log = logs[0]
            else:
                first_log = ""

            if timestamps:
                first_timestamp = timestamps[0]
            else:
                first_timestamp = ""


            if self.G.has_node(event_id):
                self.G.nodes[event_id]['message'] = first_log
                self.G.nodes[event_id]['timestamp'] = first_timestamp
                self.G.nodes[event_id]['log_count'] = len(logs)
                if self.node_mode == "drain":
                    self.G.nodes[event_id].update(self._drain_node_attributes(event_id))
                else:
                    self.G.nodes[event_id]['level'] = self.extract_level(
                        self.node_labels.get(event_id, "")
                    )
                known = [t for t in self.event_times_us[event_id] if t is not None]
                if known:
                    self.G.nodes[event_id].update(self._time_attrs('first_seen', min(known)))
                    self.G.nodes[event_id].update(self._time_attrs('last_seen', max(known)))

    def _drain_node_attributes(self, event_id) -> dict:
        """The node's identity and the Sigma annotation of its rows; a node can mix annotated and other rows."""
        rows = self.df.iloc[self.event_rows[event_id]]
        annotated = rows[rows['sigma_all'] != ""]
        rules = {rule for labels in annotated['sigma_all'] for rule in labels.split(" | ")}
        return {
            'event_key': self.node_labels[event_id],
            'message': xml_safe(str(self.event_logs[event_id][0])),
            'row_count': len(rows),
            'sigma_hits': len(annotated),
            'sigma_rules': " | ".join(sorted(rules)),
            'sigma_max_level': max(rows['sigma_level'], key=lambda level: SIGMA_LEVELS.get(level, 0)),
        }

    def _ordered_sequence(self) -> list:
        """Return the (event_id, epoch_us, row) sequence in the configured edge order."""
        if self.edge_order == "file":
            return self.sequence
        # a row without a timestamp sorts right after the row it follows in the file
        keys, last = [], None
        for _, t, _ in self.sequence:
            last = t if t is not None else last
            keys.append(last)
        first = next((k for k in keys if k is not None), 0)
        keys = [first if k is None else k for k in keys]
        return [item for _, item in sorted(zip(keys, self.sequence), key=lambda pair: pair[0])]

    def create_edges(self):
        """
        Calculate edges based on event transitions.

        This function orders the labeled events (see ``edge_order``), records every
        consecutive transition with its timestamps and source rows, and counts the
        transitions per event pair to determine weights.
        """
        sequence = self._ordered_sequence()
        levels = self.df['sigma_level'].tolist() if self.node_mode == "drain" else None
        self.temporal_edges = []
        self.edge_transitions = defaultdict(list)
        self.edges_weight = defaultdict(int)

        for seq, ((u, t_u, row_u), (v, t_v, row_v)) in enumerate(zip(sequence, sequence[1:])):
            attrs = {'seq': seq, 'src_row': row_u, 'dst_row': row_v}
            if levels:
                attrs.update(src_level=levels[row_u], dst_level=levels[row_v])
            if t_u is not None:
                attrs.update(self._time_attrs('t_src', t_u))
            if t_v is not None:
                attrs.update(self._time_attrs('t_dst', t_v))
            if t_u is not None and t_v is not None:
                attrs['delta_us'] = t_v - t_u
            self.temporal_edges.append((u, v, attrs))
            self.edge_transitions[(u, v)].append(attrs)
            self.edges_weight[(u, v)] += 1
        self.edges_list = [(u, v) for u, v, _ in self.temporal_edges]

    def create_weighted_edges(self):
        """
        Format edges with weights for the graph.

        This function prepares the list of weighted edges to be added to the networkx graph,
        with the first/last transition time and the min/median/max delay of each event pair.
        """
        self.edges_weight_list = []
        for edge, weight in self.edges_weight.items():
            attrs = {'weight': weight}
            transitions = self.edge_transitions[edge]
            starts = [a['t_src_us'] for a in transitions if 't_src_us' in a]
            deltas = sorted(a['delta_us'] for a in transitions if 'delta_us' in a)
            if starts:
                attrs.update(self._time_attrs('first_seen', min(starts)))
                attrs.update(self._time_attrs('last_seen', max(starts)))
            if deltas:
                attrs.update(delta_min_us=deltas[0], delta_median_us=median_low(deltas), delta_max_us=deltas[-1])
            self.edges_weight_list.append((edge[0], edge[1], attrs))

    def create_temporal_graph(self):
        """Build a MultiDiGraph with the aggregate graph's nodes and one edge per transition."""
        self.T = nx.MultiDiGraph()
        self.T.add_nodes_from(self.G.nodes(data=True))
        self.T.add_edges_from((u, v, attrs['seq'], attrs) for u, v, attrs in self.temporal_edges)  # key = seq -> unique GraphML edge id

    def add_edges_to_graph(self):
        """
        Add weighted edges to the graph.

        This function incorporates the calculated weighted edges into the graph structure.
        """
        self.G.add_edges_from(self.edges_weight_list)

    def write_to_graphml(self, output_filename="reconstruction_edge_graph.graphml", graph=None):
        """
        Save the graph to a GraphML file.

        This function exports the constructed graph (the aggregate graph unless
        ``graph`` is given) to a file in GraphML format.
        """
        graph = self.G if graph is None else graph
        filename_graph_output = output_filename
        nx.write_graphml_lxml(graph, filename_graph_output)
        print(f"[!] Graph saved to {filename_graph_output}")
        print(f"[!] Graph contains {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges.")

    def export_event_logs(self, output_filename="reconstruction_event_logs.csv"):
        """
        Exports detailed event logs to a separate CSV file.

        This function creates a detailed CSV report containing every log entry that 
        contributed to the identified events.
        """
        csv_export_data = []
        annotations = (self.df[['sigma', 'sigma_all', 'sigma_level']].rename(columns={'sigma_level': 'level'}).to_dict("records")
                       if self.node_mode == "drain" else None)
        for event_id in self.event_logs.keys():
            logs = self.event_logs[event_id]
            timestamps = self.event_timestamps[event_id]
            rows = self.event_rows[event_id]
            times_us = self.event_times_us[event_id]

            for ts, log, row_index, ts_us in zip(timestamps, logs, rows, times_us):
                csv_export_data.append({
                    'event_id': event_id,
                    'event_name': self.node_labels[event_id],
                    'event_key': self.node_labels[event_id],
                    'timestamp': ts,
                    'log': log,
                    'row_index': row_index,
                    'timestamp_us': ts_us,
                    **(annotations[row_index] if annotations else {})
                })

        if csv_export_data:
            csv_export_df = pd.DataFrame(csv_export_data).astype({'timestamp_us': 'Int64'})
            csv_filename = output_filename
            csv_export_df.to_csv(csv_filename, index=False)
            print(f"[+] Event logs also saved to: {csv_filename}")
        else:
             print("[!] No event logs to export.")

    def run_all(self, graph_output="reconstruction_edge_graph.graphml", csv_output=None, temporal_output=None):
        """
        Execute the full graph construction pipeline.

        This function will run the full graph construction pipeline which consists of 6 phases:
        1. Defining Events
        2. Creating Graph Nodes
        3. Processing Log Events
        4. Adding Node Attributes
        5. Creating Edges
        6. Writing Output (plus the per-transition graph when ``temporal_output`` is set)
        """
        if self.df.empty:
            print("[!] DataFrame is empty. Cannot build graph.")
            return

        print("[+] Defining Events")
        self.define_events()
        
        if not self.events_dict:
            print("[!] No Sigma events found. Graph will be empty.")
            return

        print("[+] Creating Graph Nodes")
        self.create_graph()
        
        print("[+] Processing Log Events")
        self.get_list_event_id()
        
        print("[+] Adding Node Attributes")
        self.add_node_attributes()
        
        print("[+] Creating Edges")
        self.create_edges()
        self.create_weighted_edges()
        self.add_edges_to_graph()
        
        print("[+] Writing Output")
        self.write_to_graphml(graph_output)

        if temporal_output:
            print("[+] Writing Temporal Graph")
            self.create_temporal_graph()
            self.write_to_graphml(temporal_output, self.T)

        if csv_output:
            print("[+] Exporting Event Logs")
            self.export_event_logs(csv_output)

class ReconGraph(object):
    """
    Unified facade for the complete forensic reconstruction pipeline.

    This class serves as the main entry point for the ReconGraph library, 
    coordinating the transition from raw logs to labeled data and finally 
    to a behavioral graph. It simplifies complex operations into a 
    single automated workflow.
    """
    def __init__(self, input_file, rules_dir=None, flexible_mode=True, keep_all_timestamps=False,
                 edge_order="time", node_mode="drain", exclude_status=(), exclude_rules_file=None):
        self.input_file = input_file
        self.rules_dir = rules_dir
        self.flexible_mode = flexible_mode
        self.keep_all_timestamps = keep_all_timestamps
        self.exclude_status = exclude_status
        self.exclude_rules_file = exclude_rules_file
        self.edge_order = edge_order
        self.node_mode = node_mode

    def _write_metadata(self, reconstruction, graph_paths, rules_loader):
        """Write the run's configuration next to each graph, as ``<graph>.meta.json``."""
        try:
            recongraph_version = version("recongraph")
        except PackageNotFoundError:  # running from a source checkout
            recongraph_version = "unknown"
        metadata = {
            "recongraph_version": recongraph_version,
            "node_mode": self.node_mode,
            "edge_order": self.edge_order,
            "input_file": str(self.input_file),
            "sigma_rules_path": self.rules_dir,
            "sigma_matching": "flexible" if self.flexible_mode else "strict",
            "sigma_rules": rules_loader.summary(),
            "keep_all_timestamps": self.keep_all_timestamps,
            "rows_total": len(reconstruction.df),
            "rows_in_graph": len(reconstruction.sequence),
            "event_sources": reconstruction.event_sources,
            "drain3": reconstruction.drain3,
        }
        for path in graph_paths:
            with open(f"{path}.meta.json", "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=1)
            print(f"[!] Run metadata saved to {path}.meta.json")

    def run_all(self, graph_output="reconstruction_edge_graph.graphml",
                csv_output=None, sigma_output=None, temporal_output=None):
        """
        Executes the full pipeline.
        
        This function will run the full execution pipeline which consists of 3 phases:
        1. Sigma Labeling
        2. Edge Graph Construction
        3. Export
        """
        print(f"[+] Starting ReconGraph Pipeline for {self.input_file}")
        
        print("[Phase 1] Sigma Labeling")
        labeler = SigmaLabel(self.input_file, self.rules_dir, flexible_mode=self.flexible_mode,
                             keep_all_timestamps=self.keep_all_timestamps,
                             exclude_status=self.exclude_status, exclude_rules_file=self.exclude_rules_file)
        df_labeled = labeler.run()
        reconstruction = EdgeGraph(df_labeled, edge_order=self.edge_order, node_mode=self.node_mode)

        if sigma_output:
            if sigma_output == 'AUTO':
                base_name = os.path.splitext(os.path.basename(self.input_file))[0]
                final_sigma_output = f"{base_name}_sigma_labeled.csv"
            else:
                final_sigma_output = sigma_output
                
            (df_labeled if self.node_mode == "sigma" else reconstruction.df).to_csv(final_sigma_output, index=False)
            print(f"Sigma-labeled data exported to: {final_sigma_output}")
            
        print("\n[Phase 2] Edge Graph Construction")
        reconstruction.run_all(graph_output=graph_output, csv_output=csv_output, temporal_output=temporal_output)
        if reconstruction.G.number_of_nodes():
            self._write_metadata(reconstruction, [graph_output, *([temporal_output] if temporal_output else [])], labeler.rules_loader)
        print("\n[+] Pipeline Completed Successfully")


def main():
    """
    Main execution entry point.
    Uses the ReconGraph facade to run the full pipeline.
    """
    parser = argparse.ArgumentParser(description='Reconstruct a graph from forensic timeline.')
    parser.add_argument('-f', '--file', required=True, help='Path to the input file (Plaso CSV, Plaso JSON Lines, or TXT)')
    parser.add_argument('-o', '--output', help='Output filename for the GraphML file', default='reconstruction_edge_graph.graphml')
    parser.add_argument('-r', '--rules', help='Path to the rules directory (defaults to the SIGMA_RULES_PATH environment variable if set)', default=os.environ.get('SIGMA_RULES_PATH'))
    parser.add_argument('--export-csv', nargs='?', const='reconstruction_event_logs.csv', default=None, help='Export detailed event logs to a separate CSV file')
    parser.add_argument('--export-sigma', nargs='?', const='AUTO', default=None, help='Export the sigma-labeled DataFrame to a CSV file')
    parser.add_argument('--strict', action='store_true', help='Disable flexible matching mode (strict validation)')
    parser.add_argument('--exclude-status', type=lambda v: [s.strip() for s in v.split(',') if s.strip()], default=[], metavar='STATUS[,STATUS...]',
                        help='Do not load rules with these statuses (ex: deprecated,unsupported)')
    parser.add_argument('--exclude-rules-file', default=None, metavar='FILE',
                        help='Do not load rules whose id is listed in FILE (format of Hayabusa exclude_rules.txt: one UUID per line, # starts a comment)')
    parser.add_argument('--keep-all-timestamps', action='store_true', help='JSON Lines input: keep every timestamp row of an EVTX record instead of only "Creation Time"')
    parser.add_argument('--edge-order', choices=['time', 'file'], default='time', help='Order transitions by timestamp (default) or by input row order')
    parser.add_argument('--temporal-output', default=None, help='Also write a GraphML with one edge per transition (timestamps, delta, source rows)')
    parser.add_argument('--node', choices=NODE_MODES, default='drain',
                        help='Node identity. drain (default): every row is mapped, as Provider:EventID for EVTX, data_type:timestamp_desc for '
                             'structured artefacts, a Drain3 template for free text; Sigma is stored as an annotation. '
                             'sigma: the original behavior, only rows with a Sigma label are mapped and the label is the node')

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
    if args.exclude_rules_file and not os.path.isfile(args.exclude_rules_file):
        parser.error(f"--exclude-rules-file: {args.exclude_rules_file} not found")

    if os.path.exists(args.file):
        pipeline = ReconGraph(
            input_file=args.file,
            rules_dir=getattr(args, 'rules', None),
            flexible_mode=not args.strict,
            keep_all_timestamps=args.keep_all_timestamps,
            edge_order=args.edge_order,
            node_mode=args.node,
            exclude_status=args.exclude_status,
            exclude_rules_file=args.exclude_rules_file
        )

        pipeline.run_all(
            graph_output=args.output,
            csv_output=args.export_csv,
            sigma_output=args.export_sigma,
            temporal_output=args.temporal_output
        )
            
    else:
        print(f"[!] File {args.file} not found. Please ensure the input file is present.")

if __name__ == '__main__':
    main()
