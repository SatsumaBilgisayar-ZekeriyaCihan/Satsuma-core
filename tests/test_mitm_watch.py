"""The man-in-the-middle watch: findings, events, kernel write-back, packaging."""
import json
from pathlib import Path

from satsuma import mitm_watch, route_watch
from satsuma.host_store import HostStore

ROOT = Path(__file__).resolve().parents[1]


class Kernel:
    def __init__(self, drift):
        self.current = list(drift)
        self.writes = 0

    def drift(self):
        return list(self.current)

    def restore(self):
        self.writes += 1
        done, self.current = self.current, []
        return {'restored': done, 'failed': []}


def route(**fields):
    return {key: fields.get(key) for key in route_watch._KEEP}


CLEAN = [route(dst='default', gateway='192.168.1.1', dev='wlp2s0'),
         route(type='local', dst='192.168.1.10', dev='wlp2s0', table='local')]
RULES = [{'table': 'local'}, {'table': 'main'}, {'table': 'default'}]
OWN = frozenset({__import__('ipaddress').ip_address('192.168.1.10')})


def fakes(routes=CLEAN, kernel=None, profiles=(), own=OWN, dns=()):
    return {'snapshot': lambda runner: {'routes': list(routes), 'rules': RULES, 'unavailable': []},
            'own': lambda runner: own, 'profiles': lambda runner: list(profiles),
            'kernel': kernel or Kernel([]), 'listeners': lambda: [], 'anydesk': lambda: [],
            'dns': lambda **k: list(dns), 'as_root': True, 'runner': object()}


class Core:
    def __init__(self, upstream='192.168.1.1'):
        self.upstream = upstream

    def get(self, key, default=None):
        return {'upstream': self.upstream, 'enabled': True} if key == 'dns_policy' else default


def bodies(host):
    return {json.loads(b)['rule_id']: json.loads(b) for (b,) in host.db.execute('SELECT body FROM findings')}


def test_first_run_applies_kernel_settings_quietly_then_reports_changes(tmp_path):
    host = HostStore(tmp_path / 'host', test=True)
    try:
        drift = [{'key': 'net/ipv4/conf/all/rp_filter', 'expected': '1', 'actual': '2'}]
        kernel = Kernel(drift)
        state = mitm_watch.run(host, Core(), **fakes(kernel=kernel))
        assert kernel.writes == 1 and state['kernel']['first_apply'] and bodies(host) == {}
        kernel.current = [{'key': 'net/ipv4/conf/wlp2s0/route_localnet', 'expected': '0', 'actual': '1'}]
        mitm_watch.run(host, Core(), **fakes(kernel=kernel))
        found = bodies(host)['SATSUMA-MITM-KERNEL_SETTING_CHANGED']
        assert found['severity'] == 'high' and found['item']['restored'] is True and kernel.current == []
        mitm_watch.run(host, Core(), **fakes(kernel=kernel))
        # An event stays on record after the value is back.
        assert bodies(host)['SATSUMA-MITM-KERNEL_SETTING_CHANGED']['status'] == 'REVIEW'
    finally:
        host.close()


def test_a_hostile_route_is_reported_cleared_and_reopened(tmp_path):
    host = HostStore(tmp_path / 'host', test=True)
    hostile = CLEAN + [route(type='local', dst='8.8.8.8', dev='lo', table='local')]
    try:
        mitm_watch.run(host, Core(), **fakes())
        mitm_watch.run(host, Core(), **fakes(routes=hostile))
        found = bodies(host)['SATSUMA-MITM-LOCAL_ROUTE_FOR_FOREIGN_ADDRESS']
        assert found['severity'] == 'critical' and found['source'] == 'mitm_watch' and '8.8.8.8' in found['summary']
        mitm_watch.run(host, Core(), **fakes())
        assert bodies(host)['SATSUMA-MITM-LOCAL_ROUTE_FOR_FOREIGN_ADDRESS']['status'] == 'CLEARED'
        mitm_watch.run(host, Core(), **fakes(routes=hostile))
        again = bodies(host)['SATSUMA-MITM-LOCAL_ROUTE_FOR_FOREIGN_ADDRESS']
        assert again['status'] == 'REVIEW' and again['reopened'] is True
    finally:
        host.close()


def test_routes_are_not_judged_without_the_own_addresses(tmp_path):
    host = HostStore(tmp_path / 'host', test=True)
    try:
        state = mitm_watch.run(host, Core(), **fakes(routes=CLEAN + [route(type='local', dst='8.8.8.8', dev='lo')],
                                                     own=None))
        assert bodies(host) == {} and 'ip address show' in state['unavailable']
    finally:
        host.close()


def test_default_route_and_new_profile_are_events(tmp_path):
    host = HostStore(tmp_path / 'host', test=True)
    home = {'connection.id': 'Ev', 'connection.uuid': 'u1', 'connection.type': '802-3-ethernet'}
    vpn = {'connection.id': 'Tünel', 'connection.uuid': 'u2', 'connection.type': 'wireguard'}
    try:
        mitm_watch.run(host, Core(), **fakes(profiles=[home]))
        assert bodies(host) == {}
        moved = [route(dst='default', gateway='192.168.1.66', dev='wlp2s0')] + CLEAN[1:]
        mitm_watch.run(host, Core(), **fakes(routes=moved, profiles=[home, vpn]))
        found = bodies(host)
        assert found['SATSUMA-MITM-DEFAULT_ROUTE_CHANGED']['severity'] == 'medium'
        assert found['SATSUMA-MITM-NETWORK_PROFILE_ADDED']['item']['profile'] == 'Tünel'
        assert found['SATSUMA-MITM-NETWORK_PROFILE_TUNNEL']['severity'] == 'high'
    finally:
        host.close()


def test_a_changed_dns_upstream_is_reported_once(tmp_path):
    host = HostStore(tmp_path / 'host', test=True)
    try:
        real = mitm_watch.dns_watch.findings
        dns = lambda **k: [f for f in real(**k, known=lambda: None, pinned=frozenset, is_immutable=lambda p: False)
                           if f['code'] == 'dns_upstream_changed']
        mitm_watch.run(host, Core('192.168.1.1'), **{**fakes(), 'dns': dns})
        mitm_watch.run(host, Core('192.168.1.66'), **{**fakes(), 'dns': dns})
        mitm_watch.run(host, Core('192.168.1.66'), **{**fakes(), 'dns': dns})
        changed = [b for b in bodies(host).values() if b['rule_id'] == 'SATSUMA-MITM-DNS_UPSTREAM_CHANGED']
        assert len(changed) == 1 and changed[0]['item']['after'] == '192.168.1.66'
        assert host.get('mitm_watch')['upstream'] == '192.168.1.66'
    finally:
        host.close()


def test_info_results_stay_in_the_state_only(tmp_path):
    host = HostStore(tmp_path / 'host', test=True)
    try:
        mitm_watch.record(host, [{'code': 'exposed_listener', 'severity': 'info', 'port': 5353}])
        assert bodies(host) == {}
    finally:
        host.close()


def test_shipped_sysctl_file_matches_the_required_table():
    from satsuma.kernel_net import sysctl_conf
    assert (ROOT / 'packaging/root/usr/lib/sysctl.d/92-satsuma-network.conf').read_text() == sysctl_conf()


def test_the_watch_is_installed_enabled_and_may_write_kernel_settings():
    spec = (ROOT / 'packaging/satsuma-core.spec').read_text()
    assert '/usr/lib/sysctl.d/92-satsuma-network.conf' in spec
    assert 'satsuma-mitm-watch.timer || exit 1' in spec and 'systemctl start satsuma-mitm-watch.timer' in spec
    from installer.service_setup import UNITS
    assert {'satsuma-mitm-watch.service', 'satsuma-mitm-watch.timer'} <= set(UNITS)
    unit = (ROOT / 'systemd/satsuma-mitm-watch.service').read_text()
    assert 'ProtectKernelTunables=yes' not in unit and 'CAP_NET_ADMIN' in unit and '-m satsuma.mitm_watch' in unit
    assert 'OnUnitActiveSec=1min' in (ROOT / 'systemd/satsuma-mitm-watch.timer').read_text()


def test_full_check_row_reports_findings_and_a_stale_watch(monkeypatch, tmp_path):
    import time
    from satsuma import full_check, host_store
    state = {}
    class FakeHost:
        def __init__(self, *a, **k): pass
        def get(self, key, default=None): return state if key == 'mitm_watch' else default
        def close(self): pass
    monkeypatch.setattr(host_store, 'HostStore', FakeHost)
    assert not full_check.mitm_row()['ok']
    state.update(updated_at=time.time(), counts={'critical': 1, 'high': 0, 'medium': 0}, upstream='192.168.1.1')
    row = full_check.mitm_row()
    assert not row['ok'] and 'kritik 1' in row['detail']
    state.update(counts={})
    assert full_check.mitm_row()['ok']
    state.update(updated_at=time.time() - 3600)
    assert '10 dakikadan eski' in full_check.mitm_row()['detail']
