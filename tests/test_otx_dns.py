"""OTX domains reach the DNS filter and the panel shows OTX's share (2.2.32).

OTX alan adları DNS filtresine ulaşır, panel OTX'in payını gösterir.
"""
from pathlib import Path

from satsuma.store import Store

ROOT = Path(__file__).parents[1]


def test_otx_worker_may_write_the_dns_filter():
    unit = (ROOT / 'systemd' / 'satsuma-core-otx.service').read_text()
    caps = [l for l in unit.splitlines() if l.startswith(('CapabilityBoundingSet=', 'AmbientCapabilities='))]
    assert len(caps) == 2 and all('CAP_CHOWN' in l for l in caps)


def test_otx_dns_status_counts_only_live_otx_domains(tmp_path):
    from satsuma.otx import dns_status
    from satsuma.dashboard_qt.panels.protection import otx_dns_text
    store = Store(tmp_path, test=True)
    store.set('dns_blocked_domains', {'bad.example': {'source': 'otx', 'expires_at': 200},
                                      'old.example': {'source': 'otx', 'expires_at': 50},
                                      'user.example': {'source': 'custom', 'expires_at': 200}})
    store.set('otx_domain_cache', {'bad.example': {}, 'ok.example': {}})
    store.set('otx_health', {'status': 'error', 'error': 'Operation not permitted'})
    info = dns_status(store, now=100)
    assert info['blocked'] == 1 and info['checked'] == 2
    assert otx_dns_text(info) == ' · OTX: 1 alan adı engelli (2 denetlendi), hata: Operation not permitted'



def test_dnsmasq_restarts_for_otx_only_when_needed(tmp_path):
    # 2.2.32 field: each changed OTX cycle restarted dnsmasq; readiness timed out.
    from satsuma.otx import refresh_due
    store = Store(tmp_path, test=True)
    assert refresh_due(store, {'a'}, {'a', 'new'}, 1000)       # new block: at once
    assert not refresh_due(store, {'a'}, {'a'}, 1000)           # nothing changed
    store.set('otx_dns_refreshed_at', 900)
    assert not refresh_due(store, {'a', 'old'}, {'a'}, 1000)    # expiry waits
    assert refresh_due(store, {'a', 'old'}, {'a'}, 900 + 1800)  # at most every 30 min


def test_dns_filter_keeps_running_when_only_names_expire(tmp_path):
    # Field 2026-11-04: dnsmasq restarted every minute as list entries expired.
    from satsuma.dnsmasq_control import removals_wait
    store = Store(tmp_path, test=True)
    old = 'address=/a/#\naddress=/b/#\n'
    assert not removals_wait(store, old, 'address=/a/#\naddress=/b/#\naddress=/c/#\n', True, 1000)  # new block: now
    store.set('dns_filter_restarted_at', 900)
    assert removals_wait(store, old, 'address=/a/#\n', True, 1000)          # removal waits
    assert not removals_wait(store, old, 'address=/a/#\n', True, 900 + 1800)  # at most 30 minutes
    assert not removals_wait(store, old, 'address=/a/#\n', False, 1000)     # upstream change: at once
    assert not removals_wait(store, None, 'address=/a/#\n', True, 1000)     # first setup
