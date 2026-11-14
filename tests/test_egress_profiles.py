"""Outbound profiles: only destination ports change, incoming stays closed.

Çıkış profilleri: yalnızca hedef portlar değişir, gelen trafik kapalı kalır.
"""
import json
import re
from types import SimpleNamespace as NS

import pytest

from satsuma import egress_profiles as profiles
from satsuma import network_control as nft
from satsuma.operator_service import OperatorController, weakens
from satsuma.store import Store
from test_k7_lowering_protection import Auth, PASSWORD, changes


def table(ports):
    out = [{'table': {'family': 'inet', 'name': nft.TABLE, 'comment': nft.OWNER}},
           {'set': {'name': 'blocked_ips', 'type': 'ipv4_addr'}}, {'set': {'name': 'blocked_ips_v6', 'type': 'ipv6_addr'}}]
    for chain in ('input', 'output', 'forward'):
        out.append({'chain': {'name': chain, 'type': 'filter', 'hook': chain, 'prio': 0, 'policy': 'drop'}})
        out += [{'rule': {'chain': chain, 'expr': expr}} for expr in nft.expected_rules(chain, ports=ports)]
    return json.dumps({'nftables': out})


class FakeNft:
    """Live table whose ports follow the last applied script."""
    def __init__(self, ports, fail_readback=False):
        self.ports, self.fail_readback, self.scripts = ports, fail_readback, []

    def __call__(self, args, **kw):
        if args[1:3] == ['-j', 'list']:
            body = table(self.ports)
            if self.fail_readback and self.scripts:
                body = body.replace('"policy": "drop"', '"policy": "accept"', 1)
            return NS(returncode=0, stdout=body, stderr='')
        if args[1:] == ['-f', '-']:
            script = kw['input']
            self.scripts.append(script)
            found = {}
            for proto in ('tcp', 'udp'):
                m = re.search(r'^  %s dport (\{ [\d, ]+ \}|\d+) counter queue' % proto, script, re.M)
                found[proto] = tuple(int(x) for x in re.findall(r'\d+', m.group(1))) if m else ()
            self.ports = found
        return NS(returncode=0, stdout='', stderr='')


@pytest.fixture
def files(tmp_path, monkeypatch):
    monkeypatch.setattr(profiles, 'PROFILE_FILE', tmp_path / 'egress-profile.json')
    monkeypatch.setattr(nft, 'RULESET', tmp_path / 'nftables.nft')
    nft.RULESET.write_text(nft.render_ruleset())
    return tmp_path


def test_without_a_stored_profile_the_policy_is_the_packaged_one(files):
    assert profiles.current_ports() == {'tcp': (53, 443), 'udp': (53,)}
    assert nft.render_ruleset() == nft.RULESET.read_text()


def test_remote_support_opens_only_vendor_ports_outbound():
    ports = profiles.ports_for({'addons': ['remote_support']})
    assert ports == {'tcp': (53, 443, 5938, 6568), 'udp': (53, 5938)}
    text = nft.render_ruleset(ports=ports)
    assert '  tcp dport { 53, 443, 5938, 6568 } counter queue num 100' in text
    assert ' 80,' not in text and ' 80 ' not in text  # plain HTTP stays closed
    # Incoming: only established replies; no new inbound accept anywhere.
    inbound = text.split('chain input', 1)[1].split('chain output', 1)[0]
    assert all('ct state established ct direction reply' in l for l in inbound.splitlines() if 'sport' in l)
    # Loopback lines only ever match lo (this machine talking to itself).
    outside = '\n'.join(l for l in inbound.splitlines() if not l.strip().startswith('iifname "lo"'))
    assert 'dport' not in outside
    # The only inbound accepts are replies on the direct ports (2.2.16).
    assert all(l.strip().startswith('ct state established ct direction reply')
               for l in outside.splitlines() if 'accept' in l)


@pytest.mark.parametrize('bad', [{'addons': ['everything']}, {'custom': {'tcp': [0]}}, {'custom': {'tcp': [70000]}},
                                 {'custom': {'tcp': ['22']}}, {'custom': {'sctp': [1]}}, {'custom': {'tcp': list(range(1, 40))}},
                                 {'addons': ['ssh'], 'inbound': [22]}])
def test_bad_selections_are_refused(bad):
    with pytest.raises(ValueError):
        profiles.normalize(bad)


def test_validator_follows_the_profile_and_rejects_others():
    wide = profiles.ports_for({'addons': ['ssh']})
    data = json.loads(table(wide))
    assert nft.validate_layout(data, ports=wide)
    assert not nft.validate_layout(data, ports=profiles.ports_for({}))
    # Element order in the kernel readback does not matter.
    for entry in data['nftables']:
        for expr in entry.get('rule', {}).get('expr', []):
            right = expr.get('match', {}).get('right')
            if isinstance(right, dict) and 'set' in right:
                right['set'].reverse()
    assert nft.validate_layout(data, ports=wide)


def test_apply_switches_live_table_then_files(files):
    runner = FakeNft(profiles.current_ports())
    result = nft.apply_profile({'addons': ['email']}, runner=runner)
    assert result['ports']['tcp'] == [53, 443, 465, 587, 993, 995]
    assert profiles.load()['addons'] == ['email']
    assert nft.RULESET.read_text() == nft.render_ruleset()  # boot setup will accept it
    assert 'flush chain inet satsuma_core output' in runner.scripts[0]
    assert 'set blocked_ips' not in runner.scripts[0]  # live block sets are kept


def test_failed_readback_restores_previous_chains_and_files(files):
    before = nft.RULESET.read_text()
    runner = FakeNft(profiles.current_ports(), fail_readback=True)
    with pytest.raises(RuntimeError, match='readback'):
        nft.apply_profile({'addons': ['ssh']}, runner=runner)
    assert runner.ports == {'tcp': (53, 443), 'udp': (53,)}
    assert profiles.load() == profiles.normalize({}) and nft.RULESET.read_text() == before


def test_live_table_that_does_not_match_is_left_alone(files):
    runner = FakeNft({'tcp': (22, 53, 443), 'udp': (53,)})
    with pytest.raises(RuntimeError, match='does not match'):
        nft.apply_profile({'addons': ['ssh']}, runner=runner)
    assert runner.scripts == []


@pytest.fixture
def controller(files):
    store = Store(files / 'data', test=True)
    c = OperatorController(store, auth=Auth(), runner=FakeNft(profiles.current_ports()),
                           boot_provider=lambda: {'response_unlocked': True})
    token = c.dispatch(1000, 'login', {'password': PASSWORD})['token']
    yield c, store, token
    store.close()


def test_opening_ports_needs_the_password_and_is_recorded(controller, monkeypatch):
    c, store, token = controller
    monkeypatch.setattr(nft, 'apply_profile', lambda sel, runner: {'ports': {p: list(v) for p, v in profiles.ports_for(sel).items()}})
    request = {'action': 'set', 'selection': {'addons': ['remote_support']}, 'token': token}
    assert weakens('egress_profile', request)
    with pytest.raises(PermissionError, match='K7'):
        c.dispatch(1000, 'egress_profile', request)
    result = c.dispatch(1000, 'egress_profile', {**request, 'password': PASSWORD})
    assert result['profile']['ports']['tcp'] == [53, 443, 5938, 6568]
    assert [x['status'] for x in changes(store) if x['method'] == 'egress_profile'] == ['refused_password', 'applied']


def test_narrowing_does_not_ask_for_the_password(files):
    profiles.save({'addons': ['ssh', 'email']})
    assert not weakens('egress_profile', {'action': 'set', 'selection': {'addons': ['ssh']}})
    assert not weakens('egress_profile', {'action': 'status'})


def test_dashboard_page_sends_the_selection_and_shows_open_ports(files, monkeypatch):
    import time
    from PyQt6.QtWidgets import QApplication
    from satsuma.dashboard_qt.panels.admin import AdminPanel
    from satsuma.dashboard_qt.panels import admin as admin_module
    app = QApplication.instance() or QApplication([])
    sent = []

    class Client:
        def __init__(self, *a, **k):
            pass

        def call(self, method, **params):
            sent.append((method, params))
            return {'ok': True, 'profile': profiles.describe(params.get('selection') or {})}
    monkeypatch.setattr(admin_module, 'ReaderClient', Client)
    panel = AdminPanel(NS(call=lambda *a, **k: {}))
    try:
        titles = [panel.sections.item(i).text() for i in range(panel.sections.count())]
        assert 'İnternet trafiği' in titles
        assert titles[titles.index('Ağ koruması') + 1] == 'İnternet trafiği'
        panel.token = 'session'
        panel.egress_addons['remote_support'].setChecked(True)
        panel.egress_tcp.setText('8443, 9000')
        panel.ask_password = lambda method: PASSWORD
        panel._send('egress_profile', {'action': 'set'})
        for _ in range(50):
            app.processEvents(); time.sleep(0.02)
            if sent and 'TCP' in panel.egress_state.text():
                break
        method, params = sent[0]
        assert method == 'egress_profile' and params['password'] == PASSWORD
        assert params['selection'] == {'addons': ['remote_support'], 'custom': {'tcp': [8443, 9000], 'udp': []}}
        assert '5938' in panel.egress_state.text() and 'kapalıdır' in panel.egress_state.text()
        panel.egress_tcp.setText('22a')
        sent.clear()
        panel._send('egress_profile', {'action': 'set'})
        assert sent == [] and 'sayılar' in panel.status.text()
    finally:
        panel.close()


def test_dhcp_ntp_and_remote_support_bypass_the_queue_outbound_only():
    """2.2.16: address, clock and remote support survive a stopped IPS queue.

    2.2.16: adres, saat ve uzaktan destek, IPS kuyruğu dursa da çalışır.
    """
    text = nft.render_ruleset()
    output = text.split('chain output')[1].split('chain forward')[0]
    incoming = text.split('chain input')[1].split('chain output')[0]
    assert 'tcp dport { 5938, 6568 } counter accept' in output
    assert 'udp dport { 67, 123, 5938 } counter accept' in output
    # Blocked addresses are dropped before anything is accepted.
    assert output.index('@blocked_ips counter drop') < output.index('tcp dport { 5938, 6568 } counter accept')
    # Inbound: only replies to those connections, never a new connection.
    for line in incoming.splitlines():
        if '5938' in line or '123' in line or ' 67' in line:
            assert line.strip().startswith('ct state established ct direction reply')
    rules = nft.expected_rules('output')
    assert [nft.match({'payload': {'protocol': 'udp', 'field': 'dport'}}, {'set': [67, 123, 5938]}),
            {'counter': {}}, {'accept': None}] in rules


def test_network_service_waits_for_nftables_service():
    """Both load the managed table at boot; without an order the rules were doubled.

    İkisi de açılışta aynı tabloyu yükler; sıra olmadan kurallar iki kez yazılıyordu.
    """
    from pathlib import Path
    unit = (Path(__file__).parents[1] / 'systemd/satsuma-network.service').read_text()
    assert 'After=nftables.service' in unit.splitlines()


def test_lockdown_keeps_dhcp_ntp_and_remote_support():
    calls = []

    def runner(args, **kw):
        calls.append((args, kw.get('input', '')))
        return NS(returncode=0, stdout='{"nftables": []}', stderr='')
    nft.lockdown(runner=runner)
    script = calls[-1][1]
    output = script.split('chain output')[1].split('chain forward')[0]
    incoming = script.split('chain input')[1].split('chain output')[0]
    assert 'policy drop' in output and 'tcp dport { 5938, 6568 } accept' in output
    assert 'udp dport { 67, 123, 5938 } accept' in output
    assert 'tcp dport { 53, 443 }' not in output  # DNS/HTTPS stay closed in lockdown
    assert all(l.strip().startswith(('ct state established ct direction reply', 'iifname "lo"', 'chain', 'type', '}'))
               or not l.strip() for l in incoming.splitlines() if 'accept' in l)
