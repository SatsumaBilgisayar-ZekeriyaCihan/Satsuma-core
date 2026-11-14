"""Read-only evidence correlation for Fedora advisory cache and prior Python audits.

No network, RPM transaction, code execution, quarantining or policy mutation.
Advisories identify available fixes, not proven local exploitability.
"""
from __future__ import annotations

import json
import re
import subprocess
from .host_provenance import _run

ADVISORY_COMMAND = ['/usr/bin/dnf5', '--cacheonly', 'advisory', 'list', '--security', '--json']
ADVISORY_ID = re.compile(r'^FEDORA-\d{4}-[A-Za-z0-9]+$')
NEVRA_RE = re.compile(r'^(.+)-\d[^\s]*\.[a-zA-Z0-9_]+$')
MAX_ADVISORIES = 400
MAX_SCRIPTS = 100


def parse_advisories(payload, installed_names):
    """Untrusted locally cached metadata; no CVE or signature verification claim."""
    raw = json.loads(payload)
    if not isinstance(raw, list):
        raise ValueError('expected a JSON list')
    if len(raw) > 4000:
        raise ValueError('advisory count exceeds safety limit')
    names = set(installed_names)
    results = []
    for row in raw:
        if not isinstance(row, dict):
            continue
        advisory_id, nevra = row.get('name'), row.get('nevra')
        if not isinstance(advisory_id, str) or not ADVISORY_ID.fullmatch(advisory_id):
            continue
        if row.get('type') != 'security' or not isinstance(nevra, str) or len(nevra) > 260:
            continue
        match = NEVRA_RE.fullmatch(nevra)
        if not match:
            continue
        # Match installed packages by the longest name prefix before version.
        candidates = [name for name in names if nevra.startswith(name + '-')]
        if not candidates:
            continue
        name = max(candidates, key=len)
        results.append({'advisory': advisory_id, 'package': name,
                        'severity': str(row.get('severity') or 'Unknown')[:32],
                        'fixed_nevra': nevra, 'interpretation': 'cached_security_update_candidate'})
        if len(results) >= MAX_ADVISORIES:
            break
    return results


def python_findings(state):
    """Summarize stored scan results without reopening scripts or leaking code lines."""
    if not isinstance(state, dict) or not state.get('updated_at'):
        return {'status': 'NOT_SCANNED', 'items': [], 'updated_at': None}
    items = []
    for item in (state.get('items') or [])[:MAX_SCRIPTS]:
        if not isinstance(item, dict) or not isinstance(item.get('path'), str):
            continue
        points = item.get('points')
        if type(points) is not int or points < 2:
            continue
        hits = item.get('hits') or []
        items.append({'path': item['path'][:512], 'points': points,
                      'rules': [str(hit.get('rule'))[:50] for hit in hits[:12] if isinstance(hit, dict)],
                      'classification': 'heuristic_review_not_malware_proof'})
    return {'status': 'CACHED', 'updated_at': state['updated_at'], 'items': items,
            'modified': [str(p)[:512] for p in (state.get('modified') or [])[:MAX_SCRIPTS]]}


def collect_risk(installed_names, *, state=None, runner=subprocess.run):
    text, error = _run(ADVISORY_COMMAND, runner=runner)
    if text is None:
        advisory = {'status': 'UNAVAILABLE', 'error': error, 'items': []}
    else:
        try:
            items = parse_advisories(text, installed_names)
            advisory = {'status': 'CACHE_OBSERVED', 'items': items,
                        'truncated': len(items) >= MAX_ADVISORIES}
        except (ValueError, TypeError, AttributeError):
            advisory = {'status': 'INVALID_CACHE_DATA', 'items': [], 'error': 'invalid_advisory_schema'}
    return {'advisories': advisory, 'python_audit': python_findings(state),
            'assurances': {'cached_metadata_is_signed_attestation': False,
                           'advisory_means_exploitable': False,
                           'python_heuristic_means_malware': False,
                           'network_used_by_satsuma': False,
                           'mutations': False}}
