"""Pure-stdlib schema validation for Satsuma Smart Rule v1 data.

This module exists so release validation does not depend on third-party
``jsonschema`` being installed on a production host.  The JSON Schema file
``schemas/rule-v1.schema.json`` documents the strict v1 contract for newly
authored rules.  Legacy bundled rules predate that file, so this module keeps a
compatibility branch for their historical ``{"always": "..."}`` action shape.
Both branches are checked before a release can claim schema-valid rules.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

_ALLOWED_MATCH_KEYS = {
    "source", "action", "kind", "category",
    "cmd_contains", "cmd_arg_contains", "cmd_not_contains", "cmd_regex", "cmd_regex_cs",
    "cmd_not_regex", "exe_contains", "exe_regex", "file_path",
    "file_path_not", "operation", "env_contains", "uid", "uid_not",
    "parent_contains",
}
_ALLOWED_SEVERITY = {"info", "low", "medium", "high", "critical"}
_ALLOWED_CLASSIFICATION = {"indicator", "suspicious", "likely"}
_ALLOWED_CONFIDENCE = {"low", "medium", "high"}
_ALLOWED_PROOF_LEVEL = {
    "IN_THE_WILD_CONFIRMED", "PUBLIC_RESEARCH", "DEFENSE_TAMPERING",
    "KERNEL_EXPLOIT", "HARDENING", "UNKNOWN/UNVERIFIED",
}
_SAFE_ACTIONS = {
    "record", "evidence", "ticket", "bpf_inventory", "bpffs_inventory",
    "process_inventory", "network_inventory", "capability_inventory",
    "kernel_posture_snapshot", "correlation_request",
}
_ALLOWED_TOP_KEYS = {
    "id", "name", "severity", "classification", "confidence",
    "base_match", "actions", "category", "mitre", "dedup_group",
    "scoring", "threshold", "base_score", "context",
    "schema_version", "implementation_status", "requires",
    "proof_level", "false_positives", "references",
}


def _as_list(value):
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _validate_matcher_value(key, value, errors):
    values = value if isinstance(value, list) else [value]
    if not values:
        errors.append(f"base_match.{key} requires non-empty values")
    for item in values:
        if key in {"uid", "uid_not"}:
            if isinstance(item, bool) or not isinstance(item, (str, int)):
                errors.append(f"base_match.{key} has invalid value")
        elif not isinstance(item, str) or not item:
            errors.append(f"base_match.{key} requires non-empty strings")


def validate_rule(rule) -> list[str]:
    """Return a list of schema errors for one rule mapping."""
    errors: list[str] = []
    if not isinstance(rule, Mapping):
        return ["rule must be a mapping"]
    unknown = sorted(set(rule) - _ALLOWED_TOP_KEYS)
    if unknown:
        errors.append("unknown rule key(s): " + ", ".join(unknown))
    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        errors.append("id must be a non-empty string")
        rule_id = rule_id or "?"
    if not isinstance(rule.get("name"), str) or not rule.get("name", "").strip():
        errors.append(f"{rule_id}: name must be a non-empty string")
    severity = rule.get("severity")
    if not isinstance(severity, str) or severity not in _ALLOWED_SEVERITY:
        errors.append(f"{rule_id}: invalid severity {severity!r}")
    classification = rule.get("classification")
    if not isinstance(classification, str) or classification not in _ALLOWED_CLASSIFICATION:
        errors.append(f"{rule_id}: invalid classification {classification!r}")
    if "confidence" in rule and (not isinstance(rule["confidence"], str) or rule["confidence"] not in _ALLOWED_CONFIDENCE):
        errors.append(f"{rule_id}: invalid confidence")
    if "proof_level" in rule and (not isinstance(rule["proof_level"], str) or rule["proof_level"] not in _ALLOWED_PROOF_LEVEL):
        errors.append(f"{rule_id}: invalid proof_level")

    new_format = "schema_version" in rule
    if new_format and (type(rule.get("schema_version")) is not int or rule.get("schema_version") != 1):
        errors.append(f"{rule_id}: unsupported schema_version")
    if "implementation_status" in rule and rule.get("implementation_status") != "CURRENT_TELEMETRY":
        errors.append(f"{rule_id}: non-current telemetry cannot be active")

    base_match = rule.get("base_match")
    if not isinstance(base_match, Mapping) or not base_match:
        errors.append(f"{rule_id}: base_match must be a non-empty mapping")
    else:
        unknown_match = sorted(set(base_match) - _ALLOWED_MATCH_KEYS)
        if unknown_match:
            errors.append(f"{rule_id}: unknown matcher(s): " + ", ".join(unknown_match))
        for key, value in base_match.items():
            if key not in _ALLOWED_MATCH_KEYS:
                continue
            _validate_matcher_value(key, value, errors)
            if key in {"cmd_regex", "cmd_regex_cs", "cmd_not_regex", "exe_regex"}:
                for pattern in _as_list(value):
                    try:
                        flags = 0 if key == "cmd_regex_cs" else re.IGNORECASE
                        re.compile(str(pattern), flags=flags)
                    except re.error as exc:
                        errors.append(f"{rule_id}: invalid {key}: {exc}")

    actions = rule.get("actions")
    if not isinstance(actions, list) or not actions:
        errors.append(f"{rule_id}: actions must be a non-empty list")
    elif new_format:
        if any(not isinstance(a, str) or a not in _SAFE_ACTIONS for a in actions):
            errors.append(f"{rule_id}: actions must use explicit safe action names")
        if all(isinstance(a, str) for a in actions) and len(actions) != len(set(actions)):
            errors.append(f"{rule_id}: duplicate action")
    else:
        for item in actions:
            if isinstance(item, str):
                if not item.strip():
                    errors.append(f"{rule_id}: empty legacy action")
            elif isinstance(item, Mapping):
                if set(item) != {"always"} or not isinstance(item.get("always"), str) or not item["always"].strip():
                    errors.append(f"{rule_id}: invalid legacy action shape")
            else:
                errors.append(f"{rule_id}: invalid action entry")

    scoring = rule.get("scoring", [])
    if not isinstance(scoring, list):
        errors.append(f"{rule_id}: scoring must be a list")
    else:
        for item in scoring:
            if not isinstance(item, Mapping) or set(item) != {"if", "add"}:
                errors.append(f"{rule_id}: invalid scoring entry")
            elif not isinstance(item["if"], str) or type(item["add"]) not in (int, float):
                errors.append(f"{rule_id}: invalid scoring value")
    for key in ("threshold", "base_score"):
        if key in rule and type(rule[key]) not in (int, float):
            errors.append(f"{rule_id}: {key} must be numeric")
    return errors


def validate_rules(rules) -> list[str]:
    """Return schema errors for an iterable of rules."""
    errors: list[str] = []
    for rule in rules or []:
        errors.extend(validate_rule(rule))
    return errors
