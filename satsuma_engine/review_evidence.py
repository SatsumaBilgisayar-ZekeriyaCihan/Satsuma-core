"""Bounded, redacted evidence summaries for operator review of lab-only rules.

Never serialize a full raw event or executable action. Preserve enough context
for false-positive analysis while removing common credential material.
"""
from __future__ import annotations

import hashlib
import re

_MAX_TEXT = 512
_SECRET_PATTERNS = (
    re.compile(r'(?i)(\b(?:password|passwd|token|secret|api[_-]?key|access[_-]?key)\s*[=:]\s*)([^\s,;]+)'),
    re.compile(r'(?i)(--(?:password|token|secret|api-key|access-key)(?:=|\s+))([^\s]+)'),
    re.compile(r'(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+'),
    re.compile(r'(?i)(https?://)[^/@\s:]+:[^/@\s]+@'),
)


def _text(value, *, command=False):
    if value is None:
        return None
    if not isinstance(value, (str, int, float, bool)):
        return None
    result = str(value).replace('\x00', '')[:_MAX_TEXT]
    if command:
        for pattern in _SECRET_PATTERNS:
            if pattern is _SECRET_PATTERNS[-1]:
                result = pattern.sub(r'\1[REDACTED]@', result)
            elif pattern is _SECRET_PATTERNS[2]:
                result = pattern.sub(r'\1[REDACTED]', result)
            else:
                result = pattern.sub(r'\1[REDACTED]', result)
    return result


def _pick(source, names, *, command_fields=()):
    result = {}
    for name in names:
        if name in source:
            raw = source[name]
            value = raw if type(raw) in (int, float, bool) else _text(raw, command=name in command_fields)
            if value is not None:
                result[name] = value
    return result


def build_review_evidence(finding, *, window_events):
    """Return a compact review record; never include raw_event or actions."""
    finding = finding if isinstance(finding, dict) else {}
    source = finding.get('source') if isinstance(finding.get('source'), dict) else {}
    raw = source.get('raw_event') if isinstance(source.get('raw_event'), dict) else {}
    event = raw.get('event') if isinstance(raw.get('event'), dict) else raw
    if not isinstance(event, dict):
        event = {}

    process = _pick(event, ('pid', 'starttime', 'boot_id', 'uid', 'ppid', 'exe', 'parent_exe', 'comm', 'cmd', 'parent_cmd'),
                    command_fields=('cmd', 'parent_cmd'))
    file_context = _pick(event, ('operation', 'file_path', 'path', 'file_sha256'))
    network = _pick(event, ('src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto'))

    matched = []
    for item in finding.get('evidence', []) if isinstance(finding.get('evidence'), list) else []:
        if not isinstance(item, dict) or item.get('type') != 'field':
            continue
        field = _text(item.get('field'))
        value = item.get('value')
        if isinstance(value, (str, int, float, bool)) or value is None:
            matched.append({'field': field, 'value': _text(value, command=field in ('event.cmd', 'cmd', 'event.parent_cmd'))})
        if len(matched) >= 24:
            break

    event_id = event.get('id')
    event_fingerprint = hashlib.sha256(str(event_id).encode()).hexdigest()[:16] if event_id is not None else _text(finding.get('event_fingerprint'))
    result = {
        'finding_id': _text(finding.get('finding_id')),
        'rule_id': _text(finding.get('rule_id')),
        'rule_title': _text(finding.get('rule_title')),
        'severity': _text(finding.get('severity')),
        'classification': _text(finding.get('classification')),
        'confidence': _text(finding.get('confidence')),
        'score': _text(finding.get('score')),
        'category': _text(finding.get('category')),
        'timestamp': _text(finding.get('timestamp') or event.get('timestamp')),
        'event_source': _text(event.get('source') or event.get('event_source')),
        'event_kind': _text(event.get('kind')),
        'event_action': _text(event.get('action')),
        'event_fingerprint': event_fingerprint,
        'process': process,
        'file': file_context,
        'network': network,
        'matched_conditions': matched,
        'mitre': [
            {'technique': _text(item.get('technique')), 'tactic': _text(item.get('tactic'))}
            for item in (finding.get('mitre') or [])[:12] if isinstance(item, dict)
        ] if isinstance(finding.get('mitre'), list) else [],
        'window_events': max(0, min(int(window_events), 100000)),
        'evidence_type': 'deep_engine_observation',
        'authorization': 'none',
        'test_rule': True,
        'review_required': True,
    }
    return result
