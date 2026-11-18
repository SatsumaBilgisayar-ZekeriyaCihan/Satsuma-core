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
    # 2.2.41: the always-open ports are part of every queued set.
    assert runner.ports == {'tcp': (53, 443, 5938, 6568), 'udp': (53, 67, 123, 5938)}
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


def test_dashboard_page_sends_the_selection_with_custom_ports(files, monkeypatch):
    """2.2.47: the egress choice lives on Koruma → Ayarlar; custom ports are checked before sending."""
    import sys
    from pathlib import Path
    from PyQt6.QtWidgets import QApplication
    sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
    from dashboard_fixture import FakeBackend
    from satsuma.dashboard_qt.panels.protection import FirewallSettingsPanel as ProtectionPanel
    QApplication.instance() or QApplication([])
    panel = ProtectionPanel(FakeBackend())
    acted = []
    panel.act = lambda action, refresh=True: acted.append(action)
    try:
        panel.reload()
        assert set(panel.egress_boxes) >= {'http', 'mail', 'quic'}
        panel.egress_boxes['mail'].setChecked(True)
        panel.egress_tcp.setText('8443, 9000')
        panel.egress_udp.setText('')
        panel._apply_egress()
        assert acted[-1] == {'method': 'egress_profile', 'params': {'action': 'set', 'selection': {
            'addons': ['http', 'mail'], 'custom': {'tcp': [8443, 9000], 'udp': []}}}}
        acted.clear()
        panel.egress_tcp.setText('22a')
        panel._apply_egress()
        assert acted == [] and 'sayılar' in panel.egress_error.text()
        panel.egress_tcp.setText('70000')
        panel._apply_egress()
        assert acted == []
    finally:
        panel.close()


def test_no_channel_bypasses_suricata_in_any_profile():
    """2.2.41 (owner, 2026-11-18): every open port goes through the Suricata queue.

    DHCP, NTP, TeamViewer and AnyDesk were accepted outside the queue from
    2.2.16 to 2.2.40. Outside loopback, no rule may accept a packet.
    Loopback dışında hiçbir kural paketi Suricata'ya uğratmadan kabul edemez.
    """
    selections = [{}] + [{'addons': [name]} for name in profiles.ADDONS] + [{'addons': sorted(profiles.ADDONS)}]
    for selection in selections:
        ports = profiles.ports_for(profiles.normalize(selection)) if hasattr(profiles, 'ports_for') else None
        text = nft.render_ruleset(ports=ports)
        for line in text.splitlines():
            if line.strip().endswith('accept'):
                assert '"lo"' in line, (selection, line)
            assert 'bypass' not in line
        output = text.split('chain output')[1].split('chain forward')[0]
        incoming = text.split('chain input')[1].split('chain output')[0]
        assert 'tcp dport { 53, 443, 5938, 6568' in output or '5938, 6568 } counter queue num 100' in output
        queued = [l for l in output.splitlines() if 'queue num 100' in l]
        assert any('5938' in l and '6568' in l and l.strip().startswith('tcp') for l in queued)
        assert any(' 67,' in l and '123' in l and '5938' in l and l.strip().startswith('udp') for l in queued)
        # Inbound: only replies, and those are queued too.
        for line in incoming.splitlines():
            if '5938' in line or '123' in line:
                assert line.strip().startswith('ct state established ct direction reply') and line.endswith('queue num 100')
    for chain in ('input', 'output', 'forward'):
        for rule in nft.expected_rules(chain, ports={'tcp': (53, 443), 'udp': (53,)}):
            if {'accept': None} in rule:
                assert any(e.get('match', {}).get('right') == 'lo' for e in rule), (chain, rule)


def test_network_service_waits_for_nftables_service():
    """Both load the managed table at boot; without an order the rules were doubled.

    İkisi de açılışta aynı tabloyu yükler; sıra olmadan kurallar iki kez yazılıyordu.
    """
    from pathlib import Path
    unit = (Path(__file__).parents[1] / 'systemd/satsuma-network.service').read_text()
    assert 'After=nftables.service' in unit.splitlines()


def test_lockdown_keeps_dhcp_ntp_and_remote_support_only_through_suricata():
    calls = []

    def runner(args, **kw):
        calls.append((args, kw.get('input', '')))
        return NS(returncode=0, stdout='{"nftables": []}', stderr='')
    nft.lockdown(runner=runner)
    script = calls[-1][1]
    output = script.split('chain output')[1].split('chain forward')[0]
    incoming = script.split('chain input')[1].split('chain output')[0]
    assert 'policy drop' in output
    assert 'tcp dport { 5938, 6568 } queue num 100' in output
    assert 'udp dport { 67, 123, 5938 } queue num 100' in output
    assert 'tcp dport { 53, 443 }' not in output  # DNS/HTTPS stay closed in lockdown
    for line in script.splitlines():
        if line.strip().endswith('accept'):
            assert '"lo"' in line, line   # 2.2.41: nothing but loopback is accepted
        assert 'bypass' not in line
    assert all(l.strip().startswith(('ct state established ct direction reply', 'iifname "lo"', 'chain', 'type', '}'))
               or not l.strip() for l in incoming.splitlines() if 'queue' in l or 'accept' in l)
