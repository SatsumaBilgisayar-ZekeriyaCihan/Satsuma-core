#!/usr/bin/env python3
"""Bundled Smart Rules icin paketleme oncesi strict validation.

Validates active rules with SmartRuleEngine plus a pure-stdlib schema audit.
Future telemetry specs live under ``future_specs/`` and must remain disabled;
they are intentionally not loaded by the rule engine.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from satsuma.rule_schema import validate_rules as schema_validate_rules
from satsuma.smart_rules import SmartRuleEngine, NON_RULE_YAML


def _load_yaml(path: Path):
    with path.open(encoding="utf-8") as stream:
        data = yaml.safe_load(stream)
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError(f"{path}: YAML root must be a list")
    return data


def _future_spec_errors() -> tuple[int, list[str]]:
    errors: list[str] = []
    count = 0
    root = ROOT / "future_specs"
    if not root.exists():
        return 0, errors
    for path in sorted(root.rglob("*.yaml")):
        try:
            specs = _load_yaml(path)
        except Exception as exc:  # noqa: BLE001 - report exact validation failure
            errors.append(f"{path.relative_to(ROOT)}: {type(exc).__name__}: {exc}")
            continue
        for index, spec in enumerate(specs, 1):
            count += 1
            if not isinstance(spec, dict):
                errors.append(f"{path.relative_to(ROOT)}#{index}: must be a mapping")
                continue
            if spec.get("enabled") is not False:
                errors.append(f"{path.relative_to(ROOT)}#{index}: future spec must set enabled=false")
            status = str(spec.get("implementation_status") or "")
            if not status.startswith("NEEDS_"):
                errors.append(f"{path.relative_to(ROOT)}#{index}: missing NEEDS_* telemetry marker")
    return count, errors


def _active_schema_errors(engine: SmartRuleEngine) -> list[str]:
    raw_rules = []
    for path in sorted(engine.rules_dir.rglob("*.yaml")):
        if path.name in NON_RULE_YAML:
            continue
        try:
            raw_rules.extend(_load_yaml(path))
        except Exception as exc:  # noqa: BLE001 - report exact validation failure
            raw_rules.append({"_yaml_error": f"{path}: {type(exc).__name__}: {exc}"})
    return schema_validate_rules(raw_rules)


def main() -> int:
    engine = SmartRuleEngine(ROOT / "rules")
    stats = engine.stats()
    stats["schema_invalid"] = _active_schema_errors(engine)
    stats["future_telemetry_count"], future_errors = _future_spec_errors()
    stats["future_spec_errors"] = future_errors
    print(json.dumps(stats, ensure_ascii=False, indent=2, sort_keys=True))
    if stats["invalid_files"] or stats["schema_invalid"] or future_errors:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
