"""Destructive response policy gate.

Rule YAML, collectors and single-event detectors are not allowed to execute a
destructive response directly.  The gate below is intentionally fail-closed:
the caller supplies a finding/context, and every required independent check
must pass before the low-level :class:`satsuma.response.ResponseWorker`
primitive may be invoked.

Required checks (full protection, 2.2.9)
----------------------------------------
1. ``response_enabled`` is true (on by default, see satsuma.full_protection).
2. The action is a known destructive action.
3. An operator/response policy allows the specific destructive action.
4. The fail-safe target checks pass.

Per-rule operator evidence requirements are additive and cannot be waived by
the general enforcement policy. Without an explicit per-rule override,
a single detection is enough: the earlier "confirmed only" classification
and the two-source/two-sensor corroboration conditions were removed at the
user's decision (2026-10-26).

Gerekli denetimler (tam koruma, 2.2.9): yanıt açık, eylem bilinen bir yıkıcı
eylem, ilke eylemi kapsıyor ve hedef güvenlik denetimi geçiyor. Tek tespit
yeterlidir; önceki "yalnızca kesin" sınıf ve iki kaynak/iki sensör koşulları
kullanıcının kararıyla (2026-10-26) kaldırıldı.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field

from .action_contract import canonical_action, DESTRUCTIVE_ACTIONS


# Sources that describe the rule/engine itself rather than independent
# evidence.  They do not count toward multi-source corroboration.
_SYNTHETIC_SOURCES = {
    "smart-rule-v2",
    "rule_engine",
    "correlation_engine",
    "self",
    "unknown",
    "tls_verified",
    "tls",
    "transport_tls",
    "",
}

# Critical operating system paths must never be quarantined.
_PROTECTED_QUARANTINE_ROOTS = (
    "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/lib64",
    "/usr/lib", "/etc", "/boot", "/dev", "/proc", "/sys",
)


@dataclass(frozen=True)
class DestructiveAuthorization:
    allowed: bool
    action: str
    canonical_action: str
    reasons: tuple[str, ...] = field(default_factory=tuple)
    sources: tuple[str, ...] = field(default_factory=tuple)
    policy: str = ""


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _source_name(item) -> str:
    if isinstance(item, str):
        return item.strip()
    if isinstance(item, dict):
        for key in ("source", "source_type", "collector", "collector_id", "type"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def independent_sources(finding: dict | None) -> set[str]:
    """Extract distinct independent source identities from a finding/context."""
    if not isinstance(finding, dict):
        return set()
    candidates: list = []
    for key in (
        "corroborating_sources",
        "independent_sources",
        "sources",
        "source_signals",
        "evidence_sources",
    ):
        candidates.extend(_as_list(finding.get(key)))
    for key in ("events", "corroborating_findings", "related_findings"):
        for item in _as_list(finding.get(key)):
            if isinstance(item, dict):
                candidates.append(item)
                candidates.extend(_as_list(item.get("sources")))
    event = finding.get("event")
    if isinstance(event, dict):
        candidates.append(event.get("source"))
        candidates.extend(_as_list(event.get("sources")))
    candidates.append(finding.get("source"))

    sources: set[str] = set()
    for item in candidates:
        name = _source_name(item).lower()
        if not name or name in _SYNTHETIC_SOURCES:
            continue
        # Correlation module names are not independent evidence.
        if name.endswith("_team") or name.endswith("-team"):
            continue
        sources.add(name)
    return sources


def multi_source_correlation(finding: dict | None) -> tuple[bool, tuple[str, ...]]:
    if isinstance(finding, dict):
        for key in ("multi_source_verified", "corroborated", "corroboration_verified"):
            if finding.get(key) is True:
                sources = tuple(sorted(independent_sources(finding) or {"explicit_corroboration"}))
                return True, sources
    sources = tuple(sorted(independent_sources(finding)))
    return len(sources) >= 2, sources


def _policy_settings(config: dict | None):
    config = config or {}
    response_policy = config.get("response_policy")
    if not isinstance(response_policy, dict):
        response_policy = {}
    destructive = response_policy.get("destructive")
    if not isinstance(destructive, dict):
        destructive = {}
    enabled = bool(
        destructive.get("enabled")
        or response_policy.get("destructive_enabled")
        or config.get("destructive_response_enabled")
        or config.get("allow_destructive_response")
    )
    allowed = (
        destructive.get("allowed_actions")
        or response_policy.get("destructive_allowed_actions")
        or config.get("destructive_allowed_actions")
        or []
    )
    if isinstance(allowed, str):
        allowed = [allowed]
    allowed_set = {str(x) for x in allowed if str(x).strip()}
    label = str(
        destructive.get("policy_id")
        or response_policy.get("policy_id")
        or config.get("destructive_policy_id")
        or "operator-policy"
    )
    return enabled, allowed_set, label


def policy_allows(
    action: str,
    config: dict | None,
    finding: dict | None,
    context: dict | None = None,
) -> tuple[bool, str]:
    enabled, allowed, label = _policy_settings(config)
    context = context or {}
    finding = finding or {}
    canonical = canonical_action(action)

    # Manual operator paths may carry an explicit policy acknowledgement, but
    # rule/auto paths must have an operator-controlled config policy.  A rule
    # finding cannot grant itself destructive authority with a bare boolean.
    if not enabled and context.get("manual") is True and finding.get("policy_allowed") is True:
        enabled = True
        label = "operator-manual-policy"

    if not enabled:
        return False, "destructive_response_policy_disabled"
    if allowed and canonical not in allowed:
        return False, "destructive_action_not_in_policy"
    if finding.get("policy_allowed") is False:
        return False, "finding_policy_denied"
    return True, label


def _target_from_context(finding: dict | None, context: dict | None) -> str:
    context = context or {}
    finding = finding or {}
    for source in (context, finding):
        for key in ("target_ip", "dest_ip", "dst_ip", "src_ip", "ip", "target"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    event = finding.get("event")
    if isinstance(event, dict):
        for key in ("target_ip", "dest_ip", "dst_ip", "src_ip", "ip"):
            value = event.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def fail_safe_ok(action: str, finding: dict | None, context: dict | None = None) -> tuple[bool, str]:
    """Target/process safety checks independent of the policy decision."""
    context = context or {}
    finding = finding or {}
    canonical = canonical_action(action)

    if finding.get("fail_safe_ok") is False or context.get("fail_safe_ok") is False:
        return False, "finding_fail_safe_false"

    if canonical == "network_isolate":
        target = _target_from_context(finding, context)
        if not target:
            return False, "missing_network_target"
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            return False, "invalid_network_target"
        if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
            return False, "protected_network_target"
        from .full_protection import protected_reason
        reason = protected_reason(addr)
        if reason and not context.get("manual", False):
            return False, reason
        return True, "ok"

    if canonical == "process_kill":
        raw_pid = context.get("pid") or finding.get("pid")
        if raw_pid is None:
            event = finding.get("event")
            if isinstance(event, dict):
                raw_pid = event.get("pid")
        try:
            pid = int(raw_pid)
        except (TypeError, ValueError):
            return False, "missing_or_invalid_pid"
        if pid <= 1 or pid == os.getpid():
            return False, "protected_pid"
        return True, "ok"

    if canonical == "file_quarantine":
        raw_path = context.get("path") or context.get("file_path") or finding.get("path")
        event = finding.get("event")
        if not raw_path and isinstance(event, dict):
            raw_path = event.get("file_path") or event.get("path")
        if not isinstance(raw_path, str) or not raw_path or not raw_path.startswith("/"):
            return False, "missing_or_invalid_quarantine_path"
        if any(raw_path == root or raw_path.startswith(root + "/") for root in _PROTECTED_QUARANTINE_ROOTS):
            return False, "protected_quarantine_path"
        return True, "ok"

    if canonical == "user_disable":
        target_user = context.get("target_user") or context.get("username") or finding.get("target_user")
        if not isinstance(target_user, str) or not target_user.strip():
            return False, "missing_target_user"
        if target_user.strip() in {"root", "0"}:
            return False, "protected_user"
        return True, "ok"

    # Unknown-but-destructive actions are still checked for explicit target
    # safety false signals, but policy/multi-source gates remain mandatory.
    return True, "ok"


def authorize_destructive(
    action: str,
    finding: dict | None,
    config: dict | None,
    context: dict | None = None,
    *, evidence_store=None,
) -> DestructiveAuthorization:
    """Return an auditable authorization decision for a destructive action."""
    canonical = canonical_action(action)
    reasons: list[str] = []

    if canonical not in DESTRUCTIVE_ACTIONS:
        return DestructiveAuthorization(
            False, action, canonical, ("not_a_destructive_action",), (), ""
        )

    config = config or {}
    finding = finding or {}
    context = context or {}

    from .ai_rule_package import is_ai_finding
    if is_ai_finding(finding):
        # 2.2.25: an operator-activated AI rule may stop a process after the
        # Satsuma-database and live /proc confirmations (never audit).
        from .ai_enforcement import confirm
        confirmed = confirm(finding, evidence_store, context) if canonical == 'process_kill' else {'passed': False, 'missing': ['ai_proposal_requires_separate_operator_action']}
        if not confirmed['passed']:
            return DestructiveAuthorization(False, action, canonical, tuple(confirmed['missing']) or ('ai_confirmation_failed',), (), '')

    from .rule_response import requirement_for, evidence_report
    try:
        requirement = requirement_for(finding, config, evidence_store)
        if requirement and requirement['minimum_sources'] > 1:
            evidence = evidence_report(evidence_store, finding, canonical, requirement, context)
            if not evidence['passed']:
                reasons.extend(evidence['missing'])
    except (ValueError, TypeError, KeyError):
        reasons.append('invalid_rule_evidence_policy')

    # Remote OPNsense telemetry only proposes actions on its own firewall.
    # Never turn it into an automatic local nftables rule or other host action.
    if context.get('manual') is not True:
        from .opnsense_advisory import is_opnsense_advisory
        if is_opnsense_advisory(finding):
            reasons.append('remote_advisory_only')

    if not bool(config.get("response_enabled", False)) and not bool(context.get("response_enabled")):
        reasons.append("response_disabled")

    # Unified hard rule: no destructive action is authorized merely because a
    # detector, correlation rule or root-running worker asks for it. A valid
    # admin session must have been verified by the privileged broker for this
    # specific request, except explicitly enabled automatic network/process
    # policies, which still require independent evidence and target checks.
    auto_network = (context.get('automated') is True
                    and canonical == 'network_isolate'
                    and config.get('auto_action_network_enabled') is True
                    and canonical in config.get('destructive_allowed_actions', []))
    auto_process = (context.get('automated') is True
                    and canonical == 'process_kill'
                    and config.get('auto_action_process_enabled') is True
                    and canonical in config.get('destructive_allowed_actions', []))
    if context.get("admin_session_valid") is not True and not (auto_network or auto_process):
        reasons.append("admin_session_required")
    user_enforced = (auto_process and context.get('user_enforcement') is True
                     and config.get('user_enforcement') is True)
    # Full protection: one detection is enough; no corroboration condition is
    # added on top of policy and target checks. Plain activity indicators
    # (clipboard, ps, git…) stay reports for every automatic path.
    if (auto_network or auto_process) and context.get('manual') is not True:
        from .enforcement import automatic_allowed
        if not automatic_allowed(finding, config.get('sudo_autoblock_enabled') is True):
            reasons.append('activity_indicator_reports_only')
    _, sources = multi_source_correlation(finding)
    if user_enforced and not sources:
        sources = ("user_enforcement_policy",)
    if not sources:
        sources = ("single_detection",)
    if context.get("multi_source_verified") is True and not sources:
        sources = ("explicit_corroboration",)

    policy_ok, policy_label = policy_allows(action, config, finding, context)
    if not policy_ok:
        reasons.append(policy_label)

    safe_ok, safe_reason = fail_safe_ok(action, finding, context)
    if not safe_ok:
        reasons.append(safe_reason)

    return DestructiveAuthorization(
        allowed=not reasons,
        action=action,
        canonical_action=canonical,
        reasons=tuple(reasons),
        sources=tuple(sources),
        policy=policy_label,
    )


def denied_action_record(auth: DestructiveAuthorization, finding: dict | None = None) -> dict:
    finding = finding or {}
    return {
        "status": "destructive_hard_brake",
        "action": auth.action,
        "canonical_action": auth.canonical_action,
        "reasons": list(auth.reasons),
        "classification": finding.get("classification"),
        "rule_id": finding.get("rule_id") or finding.get("type"),
        "sources": list(auth.sources),
        "policy": auth.policy,
        "executed": False,
    }
