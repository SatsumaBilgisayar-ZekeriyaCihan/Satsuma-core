"""A gateway answering from another MAC is reported as possible ARP spoofing.

Aynı ağ geçidinin başka bir MAC'ten yanıt vermesi olası ARP sahteciliği
olarak bildirilir.
"""
import hashlib

from satsuma import modem_identity, network_identity
from satsuma.network_identity import classify_change


def candidate(gateway='192.168.1.1', mac='02:00:00:00:00:02', interface='enp3s0'):
    c = {'table': 254, 'interface': interface, 'interface_mac': '02:00:00:00:00:01', 'gateway': gateway, 'gateway_mac': mac}
    c['id'] = hashlib.sha256(modem_identity.encoded(c)).hexdigest()
    return c


APPROVED = {'modem': candidate(), 'route_fingerprint': 'f1'}


def observe(candidates, fingerprint='f1'):
    return modem_identity.compare(APPROVED, {'candidates': candidates, 'route_fingerprint': fingerprint})


def test_matching_modem_is_quiet():
    assert observe([candidate()])['status'] == 'MATCHED_USER_APPROVAL'


def test_same_gateway_from_another_mac_is_critical():
    kind, severity, title, advice = classify_change(observe([candidate(mac='02:00:00:00:00:66')], 'f2'))
    assert (kind, severity) == ('GATEWAY_MAC_CHANGED', 'critical')
    assert '02:00:00:00:00:02 → 02:00:00:00:00:66' in title and 'ARP' in title
    assert 'onaylayın' in advice  # a replaced modem is re-approved, not silently adopted


def test_two_answers_for_the_gateway_are_still_critical():
    kind, severity, *_ = classify_change(observe([candidate(), candidate(mac='02:00:00:00:00:66')], 'f2'))
    assert (kind, severity) == ('GATEWAY_MAC_CHANGED', 'critical')


def test_extra_gateway_is_high_and_route_change_is_a_warning():
    assert classify_change(observe([candidate(), candidate(gateway='192.168.42.129', interface='usb0')], 'f2'))[:2] == ('ADDITIONAL_GATEWAY', 'high')
    assert classify_change(observe([candidate()], 'f2'))[:2] == ('ROUTES_CHANGED', 'warning')
    assert classify_change(observe([], 'f1'))[:2] == ('GATEWAY_CHANGED', 'high')
    assert classify_change({'status': 'MODEM_APPROVAL_REQUIRED'})[:2] == ('MODEM_APPROVAL_REQUIRED', 'warning')


def test_sync_records_one_finding_per_change_and_blocks_nothing(monkeypatch):
    class Store:
        state, findings = {}, []
        def get(self, key, default=None): return self.state.get(key, default)
        def set(self, key, value): self.state[key] = value
        def add(self, kind, body): self.findings.append((kind, body))
        def close(self): pass
    store = Store()
    monkeypatch.setattr('satsuma.store.Store', lambda: store)
    monkeypatch.setattr(network_identity, 'check_loopback', lambda *a: {'status': 'checked'})
    monkeypatch.setattr(network_identity, 'ip', lambda *a: [])
    monkeypatch.setattr(modem_identity, 'load', lambda: APPROVED)
    spoofed = {'candidates': [candidate(mac='02:00:00:00:00:66')], 'route_fingerprint': 'f2', 'tables': []}
    monkeypatch.setattr(modem_identity, 'inventory', lambda: spoofed)
    for _ in range(3):
        network_identity._sync()
    findings = [b for k, b in store.findings if k == 'findings']
    assert len(findings) == 1
    assert findings[0]['severity'] == 'critical' and findings[0]['automatic_action'] == 'none'
    assert store.state['network_identity']['change_kind'] == 'GATEWAY_MAC_CHANGED'


def test_gateway_baseline_survives_a_restart(tmp_path):
    from satsuma.gateway_guard import Guard, Profile, load_profiles, save_profiles
    path = tmp_path / 'gateway-profiles.json'
    save_profiles(path, {'enp3s0': Profile('enp3s0', '192.168.1.1', '02:00:00:00:00:02')})
    # After a restart the attacker's MAC is compared with the saved one, not adopted.
    events = Guard(load_profiles(path)).check({'enp3s0': Profile('enp3s0', '192.168.1.1', '02:00:00:00:00:66')})
    assert events[0]['changes']['gateway_mac'] == {'previous': '02:00:00:00:00:02', 'current': '02:00:00:00:00:66'}
    assert events[0]['severity'] == 'high'
    path.write_text('{broken')
    assert load_profiles(path) is None


def test_gateway_mac_disappearing_is_not_a_mac_change():
    from satsuma.gateway_guard import Guard, Profile
    guard = Guard({'enp3s0': Profile('enp3s0', '192.168.1.1', '02:00:00:00:00:02')})
    event, = guard.check({'enp3s0': Profile('enp3s0', '192.168.1.1', '')})
    assert 'gateway_mac' not in event['changes']
    assert event['changes']['gateway_mac_unobserved'] == {'previous': '02:00:00:00:00:02', 'current': ''}
    assert event['change_kinds'] == ['gateway_mac_unobserved'] and event['severity'] == 'review'


def test_gateway_mac_first_seen_and_metric_change_are_named():
    from satsuma.gateway_guard import Guard, Profile
    guard = Guard({'enp3s0': Profile('enp3s0', '192.168.1.1', '', route_metric=100)})
    event, = guard.check({'enp3s0': Profile('enp3s0', '192.168.1.1', '02:00:00:00:00:02', route_metric=600)})
    assert event['change_kinds'] == ['gateway_mac_first_observed', 'route_metric_changed']
    assert event['severity'] == 'review'


def test_a_real_mac_change_stays_a_mac_change():
    from satsuma.gateway_guard import Guard, Profile
    guard = Guard({'enp3s0': Profile('enp3s0', '192.168.1.1', '02:00:00:00:00:02')})
    event, = guard.check({'enp3s0': Profile('enp3s0', '192.168.1.1', '02:00:00:00:00:66')})
    assert event['change_kinds'] == ['gateway_mac_changed'] and event['severity'] == 'high'


def test_approved_modem_without_visible_mac_is_its_own_warning():
    unobserved = {'dev': 'enp3s0', 'gateway': '192.168.1.1', 'table': 254, 'code': 'mac_unobserved', 'reason': '...'}
    result = modem_identity.compare(APPROVED, {'candidates': [], 'route_fingerprint': 'f1', 'rejected': [unobserved]})
    assert result['reference_mac_unobserved'] is True
    assert classify_change(result)[:2] == ('GATEWAY_MAC_UNOBSERVED', 'warning')
    # Another route missing its MAC does not explain the approved modem's absence.
    other = {**unobserved, 'dev': 'wlp2s0'}
    result = modem_identity.compare(APPROVED, {'candidates': [], 'route_fingerprint': 'f1', 'rejected': [other]})
    assert classify_change(result)[:2] == ('GATEWAY_CHANGED', 'high')


def test_inventory_marks_a_route_whose_modem_mac_is_missing(monkeypatch):
    def reader(*args):
        if args == ('link', 'show'):
            return [{'ifname': 'enp3s0', 'address': '02:00:00:00:00:01', 'link_type': 'ether'}]
        if args == ('-4', 'route', 'show', 'table', 'all'):
            return [{'dst': 'default', 'gateway': '192.168.1.1', 'dev': 'enp3s0', 'table': 'main'}]
        return []
    monkeypatch.setattr(modem_identity, 'arp_mac', lambda *a: None)
    data = modem_identity.inventory(reader=reader)
    assert data['candidates'] == []
    assert data['rejected'][0]['code'] == 'mac_unobserved' and data['rejected'][0]['gateway'] == '192.168.1.1'
