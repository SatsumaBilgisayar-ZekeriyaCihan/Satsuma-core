"""OTX never cuts the user's remote-support relays (TeamViewer, AnyDesk).

OTX, kullanıcının uzaktan destek aktarıcılarını (TeamViewer, AnyDesk) asla kesmez.
"""
from types import SimpleNamespace as NS

import pytest

from satsuma import otx
from satsuma.store import Store

TLS = {'verified': True, 'version': 'fixture', 'cipher': 'fixture', 'host': otx.HOST}


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / 'data', test=True)
    yield s
    s.close()


@pytest.mark.parametrize('name,expected', [
    ('teamviewer.com', True), ('router7.teamviewer.com.', True), ('relay-1.net.anydesk.com', True),
    ('ANYDESK.COM', True), ('evilteamviewer.com', False), ('anydesk.com.evil.example', False), ('', False),
])
def test_remote_support_domain(name, expected):
    assert otx.remote_support_domain(name) is expected


def strong_otx(monkeypatch):
    monkeypatch.setattr(otx, 'load_config', lambda: {'api_key': 'fixture', 'cache_ttl_seconds': 3600, 'max_queries_per_cycle': 12})
    monkeypatch.setattr(otx, 'load_with_policy', lambda: ({'otx_enabled': True, 'otx_blocker_mode': True}, None, None))
    monkeypatch.setattr(otx, 'run_domains', lambda *a: None)
    monkeypatch.setattr(otx, 'request_ipv4', lambda *a: ({}, TLS))
    monkeypatch.setattr(otx, 'summarize', lambda ip, data, tls: {'ip': ip, 'tls': tls, 'pulse_count': 50,
        'latest_pulse_age_days': 0, 'satsuma_otx_risk_score': 50, 'reason': 'fixture'})


def test_address_resolved_from_teamviewer_is_recorded_not_blocked(store, monkeypatch):
    strong_otx(monkeypatch)
    store.add('dns', {'query': 'router7.teamviewer.com', 'type': 'response', 'ips': ['37.252.230.10']})
    response = NS(block_ip=lambda *a, **k: pytest.fail('remote-support relay must not be blocked'))
    rows = otx._run_once(store=store, response=response, candidates=['37.252.230.10'])
    assert rows[0]['decision'] == 'review' and rows[0]['block_reason'] == 'remote_support_peer'


def test_other_strong_indicator_is_still_blocked(store, monkeypatch):
    strong_otx(monkeypatch)
    from satsuma import early_guard
    monkeypatch.setattr(early_guard, 'read_verdict', lambda: {'response_unlocked': True})
    store.add('dns', {'query': 'router7.teamviewer.com', 'type': 'response', 'ips': ['37.252.230.10']})
    calls = []
    response = NS(block_ip=lambda ip, *a, **k: calls.append(ip) or {'status': 'set_membership_confirmed'})
    rows = otx._run_once(store=store, response=response, candidates=['45.33.32.10'])
    assert calls == ['45.33.32.10'] and rows[0]['decision'] == 'block'


def test_remote_support_domains_are_never_queried_or_kept_blocked(store, monkeypatch):
    import satsuma.dnsmasq_control as dnsmasq
    monkeypatch.setattr(dnsmasq, 'refresh', lambda s: None)
    store.add('dns', {'query': 'master1.teamviewer.com'})
    store.add('dns', {'query': 'relay-1.net.anydesk.com'})
    store.set('dns_blocked_domains', {'master1.teamviewer.com': {'expires_at': 9e12}})
    monkeypatch.setattr(otx, 'request_indicator', lambda name, *a: pytest.fail('queried ' + name))
    otx.run_domains(store, {'api_key': 'fixture', 'cache_ttl_seconds': 3600, 'max_queries_per_cycle': 12}, {})
    assert store.get('dns_blocked_domains') == {}
