"""Fail-safe config upgrade compatibility for Satsuma Core.

The live ``/etc/satsuma-core/config.json`` file is operator data.  Release
maintainer scripts and runtime loaders must never overwrite it blindly.  This
module migrates *in memory*: recognised old values are preserved, missing
release defaults are added, and unknown or structurally invalid data fails
closed before the caller can apply anything.

The migration is intentionally idempotent.  A second application to the
effective result must not change the result and must not reject the already
migrated object.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import config as _config
from . import policy as _policy

CONFIG_SCHEMA_VERSION = 2

# Keys that are produced by the policy/effective view but are not part of the
# flat legacy config schema.  Their presence identifies an already-migrated
# effective configuration.
_EFFECTIVE_KEYS = {
    "suricata_collector_enabled",
    "dns_monitor_enabled",
    "audit_enabled",
    "audit_log_path",
    "finding_enabled",
    "correlation_window_seconds",
    "audit_candidate_limit",
    "evidence_enabled",
    "archive_budget_bytes",
    "scheduled_scans",
}


class ConfigMigrationError(ValueError):
    """Raised when a config cannot be migrated safely."""


def _is_policy_shape(data: dict) -> bool:
    """Return True only for the strict policy document shape.

    ``scheduled_scans`` alone is not enough because it also exists in the flat
    effective view produced by :func:`_policy.effective`.
    """

    return "workers" in data and "correlation" in data


def _is_effective_shape(data: dict) -> bool:
    # ``scheduled_scans`` is present in both the strict policy document and
    # the flat effective view, so it cannot be the sole marker.
    return bool((_EFFECTIVE_KEYS - {"scheduled_scans"}).intersection(data))


def _validate_effective(data: dict) -> dict:
    """Validate the flat subset of an already-migrated effective config."""
    unknown = sorted(set(data) - set(_config.DEFAULT) - _EFFECTIVE_KEYS - {"schema_version"})
    if unknown:
        raise ConfigMigrationError("unknown effective configuration keys: " + ",".join(unknown))
    flat = {key: data.get(key, default) for key, default in _config.DEFAULT.items()}
    if "schema_version" in data:
        flat["schema_version"] = data["schema_version"]
    try:
        validated = _config.validate(flat)
    except Exception as exc:  # noqa: BLE001 - normalise for fail-safe callers
        raise ConfigMigrationError(f"{type(exc).__name__}: {exc}") from exc
    out = dict(data)
    out.update({key: validated[key] for key in _config.DEFAULT})
    return out


def migrate_config_data(data: Any) -> dict:
    """Return an effective, validated config without mutating the input.

    Flat legacy configs are merged with safe defaults and returned in the flat
    schema.  Policy-shaped configs are passed through the strict policy
    validator and converted to the flat runtime view.  Already-migrated
    effective configs are returned unchanged after validation.  Any unknown key
    or failed validation raises :class:`ConfigMigrationError` so callers can
    fail closed.
    """
    if not isinstance(data, dict):
        raise ConfigMigrationError("config root must be a JSON object")
    try:
        if _is_effective_shape(data):
            return _validate_effective(data)
        if _is_policy_shape(data):
            policy = _policy.validate(dict(data))
            return dict(_policy.effective(policy))
        unknown = sorted(set(data) - set(_config.DEFAULT) - {"schema_version"})
        if unknown:
            raise ConfigMigrationError("unknown configuration keys: " + ",".join(unknown))
        if "schema_version" in data:
            version = data.get("schema_version")
            if type(version) is not int or version > CONFIG_SCHEMA_VERSION:
                raise ConfigMigrationError("unsupported config schema_version")
        merged = dict(_config.DEFAULT)
        for key, value in data.items():
            if key in _config.DEFAULT:
                merged[key] = value
        return _config.validate(merged)
    except ConfigMigrationError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalise all failures for fail-safe callers
        raise ConfigMigrationError(f"{type(exc).__name__}: {exc}") from exc


def migrate_config_document(data: Any) -> tuple[dict, dict]:
    """Migrate one raw document and return ``(effective_config, policy)``.

    This is the single production bridge between the raw JSON document and the
    runtime/policy views.  It applies :func:`migrate_config_data` exactly once
    for flat legacy documents and once through the strict policy validator for
    policy documents.
    """
    if not isinstance(data, dict):
        raise ConfigMigrationError("config root must be a JSON object")
    try:
        if _is_effective_shape(data):
            effective = _validate_effective(data)
            flat = {key: effective.get(key, default) for key, default in _config.DEFAULT.items()}
            return effective, _policy.from_legacy(flat)
        if _is_policy_shape(data):
            policy = _policy.validate(dict(data))
            return dict(_policy.effective(policy)), policy
        flat = migrate_config_data(data)
        policy = _policy.from_legacy(flat)
        return dict(_policy.effective(policy)), policy
    except ConfigMigrationError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ConfigMigrationError(f"{type(exc).__name__}: {exc}") from exc


def migrate_config_file(path: str | Path) -> dict:
    """Read a config JSON file and migrate it in memory.

    The file is opened read-only.  This function never writes, renames or
    deletes the source file.
    """
    source = Path(path)
    try:
        with source.open(encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception as exc:  # noqa: BLE001
        raise ConfigMigrationError(f"{type(exc).__name__}: {exc}") from exc
    return migrate_config_data(data)


def migration_report(data: Any) -> dict:
    """Return an auditable report without exposing secret values."""
    before = data if isinstance(data, dict) else {}
    try:
        effective = migrate_config_data(before)
    except ConfigMigrationError as exc:
        return {"status": "failed", "error": str(exc)[:300]}
    defaults_added = sorted(set(_config.DEFAULT) - set(before))
    return {
        "status": "ok",
        "schema_version": CONFIG_SCHEMA_VERSION,
        "defaults_added": defaults_added,
        "preserved_keys": sorted(set(before) & set(_config.DEFAULT)),
        "effective": {key: effective.get(key) for key in _config.DEFAULT},
    }
