"""Read-only OPNsense observations and firewall recommendations.

An OPNsense event is untrusted external telemetry. It must never authorize a
local nftables response or a change on the OPNsense firewall.
"""
from __future__ import annotations

import ipaddress
import time


def is_opnsense_advisory(finding):
    """True for findings derived from a remote OPNsense source."""
    if not isinstance(finding, dict):
        return False
    if str(finding.get('target_scope', '')).lower() == 'opnsense':
        return True
    candidates = [finding.get('source'), finding.get('sources')]
    event = finding.get('event')
    if isinstance(event, dict):
        candidates.extend((event.get('source'), event.get('sources')))
    for candidate in candidates:
        if isinstance(candidate, dict):
            candidate = candidate.get('collector_id') or candidate.get('type')
        if isinstance(candidate, (list, tuple, set)):
            if any(is_opnsense_advisory({'source': item}) for item in candidate):
                return True
        elif isinstance(candidate, str) and candidate.lower() in ('opnsense', 'opnsense_firewall'):
            return True
    return False


def candidate(event):
    """Return a single public IPv4/IPv6 host for *review*, never execution.

    One remote packet drop is not evidence of a compromised host. The worker
    requires repeated inbound drops before creating an operator recommendation.
    """
    if not isinstance(event, dict) or not is_opnsense_advisory(event):
        return None
    if event.get('category') != 'firewall':
        return None
    if event.get('action') not in ('block', 'reject'):
        return None
    network = event.get('network')
    if not isinstance(network, dict) or network.get('direction') != 'in':
        return None
    try:
        address = ipaddress.ip_address(network.get('src_ip', ''))
    except (ValueError, TypeError):
        return None
    if (not address.is_global or address.is_multicast or address.is_reserved
            or address.is_unspecified or address.is_loopback or address.is_link_local):
        return None
    return str(address)


def finding_for(event, ip, count, now=None):
    """Create an operator-only finding; no nftables or OPNsense API calls."""
    now = time.time() if now is None else now
    source = event.get('source') or {}
    host = source.get('host', 'opnsense') if isinstance(source, dict) else 'opnsense'
    return {
        'timestamp': now, 'source': 'OPNSENSE', 'source_host': str(host)[:128],
        'category': 'firewall', 'severity': 'medium',
        'classification': 'suspicious', 'confidence': 'low',
        'rule_id': 'SATSUMA-OPNSENSE-REVIEW-001',
        'title': f'OPNsense: {ip} adresinin engellenmesi değerlendirilmeli',
        'target_ip': ip, 'target_scope': 'opnsense', 'event_count': count,
        'status': 'review_required', 'operator_review_required': True,
        'recommendation': 'OPNsense üzerinde bu IP için kalıcı engel gerekip gerekmediğini inceleyin.',
        'action': {'type': 'recommendation', 'executed': False, 'target_scope': 'opnsense'},
        'evidence': {'observed_inbound_blocks': count, 'local_nft_modified': False,
                     'opnsense_firewall_modified': False},
    }
