"""WireGuard VPN profiles imported from a .conf file, with the firewall port opened only while active.

User request 2026-11-04: Satsuma has a WireGuard section; a profile is
imported from a file, and while it is active Satsuma opens its port itself.

- Import: the file is parsed strictly. PreUp/PostUp/PreDown/PostDown and
  SaveConfig/Table/FwMark are refused, because wg-quick runs those as
  commands or they change routing outside Satsuma. DNS lines are dropped:
  Satsuma's DNS filter stays pinned (MITM protection) and every port-53
  query keeps going to it. IPv6 endpoints are refused (IPv6 is off).
  The clean file is kept root-only under /etc/satsuma-core/wireguard and
  imported into NetworkManager with autoconnect off, IPv6 off and a fixed
  fwmark/routing table (FWMARK), so the MITM watch can tell this
  profile's policy rule from a foreign one. If NetworkManager brings the
  profile up on import, it is taken down again: connecting is a separate
  step that opens the port first.
- Port: the endpoint UDP ports of active Satsuma profiles are written to
  the egress profile's "wireguard" field. They leave through the Suricata
  queue like every other port; nothing is opened inbound. sync() also runs
  every 20 seconds in the operator service, so a profile switched on or
  off from the desktop network menu gets its port opened or closed too.
- The private key never enters the database, actions or logs.

.conf dosyasından içe aktarılan WireGuard VPN profilleri; güvenlik duvarı
portu yalnızca profil etkinken açılır.

Kullanıcı isteği 2026-11-04: Satsuma'da WireGuard bölümü olsun; profil
dosyadan içe aktarılsın, etkinken portunu Satsuma kendisi açsın.

- İçe aktarma: dosya sıkı denetlenir. PreUp/PostUp/PreDown/PostDown ile
  SaveConfig/Table/FwMark reddedilir; wg-quick bunları komut olarak çalıştırır
  ya da Satsuma dışında yönlendirmeyi değiştirir. DNS satırları atılır:
  Satsuma'nın DNS filtresi sabit kalır (MITM koruması), 53. porta giden her
  sorgu yine ona gider. IPv6 uç noktaları reddedilir (IPv6 kapalı). Temiz
  dosya yalnızca root'un okuyabileceği /etc/satsuma-core/wireguard altında
  saklanır ve NetworkManager'a otomatik bağlanma kapalı, IPv6 kapalı, sabit
  fwmark/yönlendirme tablosuyla (FWMARK) aktarılır; böylece MITM izleyicisi
  bu profilin politika kuralını yabancı bir kuraldan ayırt eder.
  NetworkManager profili içe aktarırken hemen bağlarsa bağlantı kesilir;
  bağlanmak, önce portu açan ayrı bir adımdır.
- Port: etkin Satsuma profillerinin uç nokta UDP portları çıkış profilinin
  "wireguard" alanına yazılır. Diğer portlar gibi Suricata kuyruğundan
  çıkar; içeriye hiçbir şey açılmaz. sync() yönetim servisinde 20 saniyede
  bir de çalışır; profil masaüstü ağ menüsünden açılıp kapatılsa bile portu
  açılır ya da kapanır.
- Özel anahtar veritabanına, eylem kayıtlarına ve günlüklere girmez.
"""
import base64
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import time

DIRECTORY = Path('/etc/satsuma-core/wireguard')
STATE_KEY = 'wireguard_profiles'
FWMARK = 51847
NMCLI = '/usr/bin/nmcli'
MAX_BYTES = 16 * 1024
MAX_PEERS = 8
NAME = re.compile(r'[a-z][a-z0-9-]{0,14}')
HOST = re.compile(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*')
REFUSED = {
    'preup': 'PreUp komut çalıştırır', 'postup': 'PostUp komut çalıştırır',
    'predown': 'PreDown komut çalıştırır', 'postdown': 'PostDown komut çalıştırır',
    'saveconfig': 'SaveConfig dosyayı Satsuma dışında yeniden yazar',
    'table': 'Table yönlendirmeyi Satsuma dışında değiştirir',
    'fwmark': 'FwMark yönlendirmeyi Satsuma dışında değiştirir',
}
INTERFACE_KEYS = {'privatekey': 'PrivateKey', 'address': 'Address', 'dns': 'DNS', 'mtu': 'MTU', 'listenport': 'ListenPort'}
PEER_KEYS = {'publickey': 'PublicKey', 'presharedkey': 'PresharedKey', 'endpoint': 'Endpoint',
             'allowedips': 'AllowedIPs', 'persistentkeepalive': 'PersistentKeepalive'}


class ConfigError(ValueError):
    pass


def _key(value, field):
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raw = b''
    if len(value) != 44 or len(raw) != 32:
        raise ConfigError(field + ': geçerli bir WireGuard anahtarı değil')
    return value


def _addresses(value, field, allow_v6=True):
    out = []
    for part in [p.strip() for p in value.split(',') if p.strip()]:
        try:
            network = ipaddress.ip_interface(part)
        except ValueError:
            raise ConfigError(field + ': geçersiz adres ' + part[:60])
        if network.version == 6 and not allow_v6:
            raise ConfigError(field + ': IPv6 desteklenmiyor')
        out.append(str(network))
    if not out:
        raise ConfigError(field + ' boş')
    return out


def _endpoint(value):
    value = value.strip()
    if value.startswith('['):
        raise ConfigError('Endpoint: IPv6 uç nokta desteklenmiyor (bu bilgisayarda IPv6 kapalı)')
    host, sep, port = value.rpartition(':')
    if not sep or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ConfigError('Endpoint: "adres:port" biçiminde olmalı')
    try:
        address = ipaddress.ip_address(host)
        if address.version == 6:
            raise ConfigError('Endpoint: IPv6 uç nokta desteklenmiyor')
        host = str(address)
    except ValueError:
        if not HOST.fullmatch(host):
            raise ConfigError('Endpoint: geçersiz sunucu adı')
    return host, int(port)


def _int(value, field, low, high):
    if not value.strip().isdigit() or not low <= int(value) <= high:
        raise ConfigError(f'{field}: {low}-{high} arasında sayı olmalı')
    return int(value)


def parse(text):
    """Validated profile: {'interface', 'peers', 'dropped', 'notes'}; raises ConfigError."""
    if not isinstance(text, str):
        raise ConfigError('Dosya metin olmalı')
    if len(text.encode('utf-8', 'replace')) > MAX_BYTES:
        raise ConfigError('Dosya çok büyük (en fazla 16 KB)')
    interface, peers, section, dropped = None, [], None, []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.split('#', 1)[0].strip()
        if not line or line.startswith(';'):
            continue
        header = re.fullmatch(r'\[\s*(\w+)\s*\]', line)
        if header:
            name = header.group(1).lower()
            if name == 'interface':
                if interface is not None:
                    raise ConfigError('Birden çok [Interface] bölümü var')
                interface, section = {}, 'interface'
            elif name == 'peer':
                if len(peers) >= MAX_PEERS:
                    raise ConfigError(f'En fazla {MAX_PEERS} [Peer] bölümü olabilir')
                peers.append({})
                section = 'peer'
            else:
                raise ConfigError(f'Satır {number}: bilinmeyen bölüm [{header.group(1)}]')
            continue
        key, sep, value = line.partition('=')
        if not sep:
            raise ConfigError(f'Satır {number}: "Anahtar = Değer" biçiminde değil')
        key, value = key.strip().lower(), value.strip()
        if key in REFUSED:
            raise ConfigError(f'Satır {number}: {REFUSED[key]}; bu satırı içeren dosya içe aktarılmaz')
        if section is None:
            raise ConfigError(f'Satır {number}: bölüm başlığından önce ayar var')
        target, allowed = (interface, INTERFACE_KEYS) if section == 'interface' else (peers[-1], PEER_KEYS)
        if key not in allowed:
            raise ConfigError(f'Satır {number}: desteklenmeyen ayar {key[:40]}')
        if allowed[key] in target:
            raise ConfigError(f'Satır {number}: {allowed[key]} iki kez yazılmış')
        target[allowed[key]] = value
    if interface is None:
        raise ConfigError('[Interface] bölümü yok')
    if not peers:
        raise ConfigError('[Peer] bölümü yok')
    clean = {'PrivateKey': _key(interface.get('PrivateKey', ''), 'PrivateKey'),
             'Address': _addresses(interface.get('Address', ''), 'Address')}
    if 'MTU' in interface:
        clean['MTU'] = _int(interface['MTU'], 'MTU', 1280, 9000)
    notes = []
    if 'DNS' in interface:
        dropped.append('DNS')
        notes.append('DNS satırı uygulanmadı: Satsuma DNS filtresi sabit kalır.')
    if 'ListenPort' in interface:
        dropped.append('ListenPort')
        notes.append('ListenPort uygulanmadı: dışarıdan gelen bağlantı açılmaz.')
    clean_peers = []
    for index, peer in enumerate(peers, 1):
        item = {'PublicKey': _key(peer.get('PublicKey', ''), f'Peer {index} PublicKey'),
                'AllowedIPs': _addresses(peer.get('AllowedIPs', ''), f'Peer {index} AllowedIPs')}
        if 'PresharedKey' in peer:
            item['PresharedKey'] = _key(peer['PresharedKey'], f'Peer {index} PresharedKey')
        if 'Endpoint' in peer:
            item['Endpoint'] = _endpoint(peer['Endpoint'])
        if 'PersistentKeepalive' in peer:
            item['PersistentKeepalive'] = _int(peer['PersistentKeepalive'], 'PersistentKeepalive', 0, 65535)
        clean_peers.append(item)
    if not any('Endpoint' in p for p in clean_peers):
        raise ConfigError('Hiçbir [Peer] bölümünde Endpoint yok; bağlanılacak sunucu bilinmiyor')
    if any(ipaddress.ip_network(a, strict=False).version == 6 for p in clean_peers for a in p['AllowedIPs']):
        notes.append('IPv6 adresleri tünelden geçmez; bu bilgisayarda IPv6 kapalı.')
    return {'interface': clean, 'peers': clean_peers, 'dropped': dropped, 'notes': notes}


def render(profile):
    """The clean .conf text NetworkManager imports (no DNS, no commands)."""
    iface = profile['interface']
    lines = ['[Interface]', 'PrivateKey = ' + iface['PrivateKey'], 'Address = ' + ', '.join(iface['Address'])]
    if 'MTU' in iface:
        lines.append(f"MTU = {iface['MTU']}")
    for peer in profile['peers']:
        lines += ['', '[Peer]', 'PublicKey = ' + peer['PublicKey']]
        if 'PresharedKey' in peer:
            lines.append('PresharedKey = ' + peer['PresharedKey'])
        lines.append('AllowedIPs = ' + ', '.join(peer['AllowedIPs']))
        if 'Endpoint' in peer:
            lines.append(f"Endpoint = {peer['Endpoint'][0]}:{peer['Endpoint'][1]}")
        if 'PersistentKeepalive' in peer:
            lines.append(f"PersistentKeepalive = {peer['PersistentKeepalive']}")
    return '\n'.join(lines) + '\n'


def summary(profile):
    """What may be shown and stored: no keys."""
    return {'addresses': profile['interface']['Address'],
            'endpoints': [f'{p["Endpoint"][0]}:{p["Endpoint"][1]}' for p in profile['peers'] if 'Endpoint' in p],
            'ports': sorted({p['Endpoint'][1] for p in profile['peers'] if 'Endpoint' in p}),
            'full_tunnel': any(a in ('0.0.0.0/0', '::/0') for p in profile['peers'] for a in p['AllowedIPs']),
            'peers': len(profile['peers']), 'notes': profile['notes']}


def _nm(runner, *args):
    result = runner([NMCLI, *args], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('NetworkManager: ' + (result.stderr or result.stdout or 'hata').strip()[:300])
    return result.stdout


def _profiles(store):
    value = store.get(STATE_KEY, {}) or {}
    return value if isinstance(value, dict) else {}


def import_profile(store, name, text, runner=subprocess.run, directory=None):
    """Validate, keep a root-only clean copy and import it into NetworkManager."""
    directory = Path(DIRECTORY if directory is None else directory)
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ConfigError('Ad küçük harfle başlamalı; yalnızca a-z, 0-9 ve - (en fazla 15 karakter)')
    profiles = _profiles(store)
    if name in profiles:
        raise ConfigError('Bu adla bir profil zaten var; önce silin')
    profile = parse(text)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    path = directory / (name + '.conf')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(render(profile))
    try:
        _nm(runner, 'connection', 'import', 'type', 'wireguard', 'file', str(path))
        _nm(runner, 'connection', 'modify', name, 'connection.autoconnect', 'no', 'ipv6.method', 'disabled',
            'ipv4.ignore-auto-dns', 'yes', 'wireguard.fwmark', str(FWMARK), 'wireguard.ip4-auto-default-route', 'yes')
        # NetworkManager may bring an imported profile up at once; connecting is
        # an explicit step that opens the port first (field 2026-11-04).
        if name in active(runner):
            _nm(runner, 'connection', 'down', name)
    except Exception:
        try:
            runner([NMCLI, 'connection', 'delete', name], capture_output=True, text=True, timeout=30)
        finally:
            path.unlink(missing_ok=True)
        raise
    profiles[name] = {**summary(profile), 'imported_at': time.time()}
    store.set(STATE_KEY, profiles)
    return {'ok': True, 'name': name, **profiles[name]}


def active(runner=subprocess.run):
    """Names of NetworkManager connections that are active now."""
    out = _nm(runner, '-t', '-f', 'NAME,TYPE', 'connection', 'show', '--active')
    names = set()
    for line in out.splitlines():
        name, _, kind = line.rpartition(':')
        if kind == 'wireguard' and name:
            names.add(name.replace('\\:', ':'))
    return names


def active_managed(store, runner=subprocess.run):
    return sorted(set(_profiles(store)) & active(runner))


def wanted_ports(store, names):
    profiles = _profiles(store)
    return sorted({port for name in names for port in profiles.get(name, {}).get('ports', [])})


def sync(store, runner=subprocess.run, apply=None):
    """Open the endpoint ports of active Satsuma profiles; close the others."""
    from . import egress_profiles
    if apply is None:
        from .network_control import apply_profile as apply
    names = active_managed(store, runner) if _profiles(store) else []
    wanted = wanted_ports(store, names)
    selection = egress_profiles.load()
    if selection.get('wireguard', {}).get('udp', []) == wanted:
        return {'ok': True, 'changed': False, 'active': names, 'ports': wanted}
    apply({**selection, 'wireguard': {'udp': wanted}}, runner=runner)
    store.add('actions', {'timestamp': time.time(), 'action': 'wireguard.port_sync', 'status': 'completed',
                          'active': names, 'ports': wanted})
    return {'ok': True, 'changed': True, 'active': names, 'ports': wanted}


def up(store, name, runner=subprocess.run, apply=None):
    """Open the port first, then connect; close it again if connecting fails."""
    if name not in _profiles(store):
        raise ConfigError('Satsuma’da böyle bir WireGuard profili yok')
    from . import egress_profiles
    if apply is None:
        from .network_control import apply_profile as apply
    selection = egress_profiles.load()
    current = selection.get('wireguard', {}).get('udp', [])
    opened = sorted(set(current) | set(wanted_ports(store, [name])))
    if opened != current:
        apply({**selection, 'wireguard': {'udp': opened}}, runner=runner)
    try:
        _nm(runner, 'connection', 'up', name)
    except Exception:
        sync(store, runner, apply)
        raise
    return sync(store, runner, apply)


def down(store, name, runner=subprocess.run, apply=None):
    if name not in _profiles(store):
        raise ConfigError('Satsuma’da böyle bir WireGuard profili yok')
    if name in active(runner):
        _nm(runner, 'connection', 'down', name)
    return sync(store, runner, apply)


def remove(store, name, runner=subprocess.run, apply=None, directory=None):
    directory = Path(DIRECTORY if directory is None else directory)
    profiles = _profiles(store)
    if name not in profiles:
        raise ConfigError('Satsuma’da böyle bir WireGuard profili yok')
    if name in active(runner):
        _nm(runner, 'connection', 'down', name)
    runner([NMCLI, 'connection', 'delete', name], capture_output=True, text=True, timeout=30)
    (directory / (name + '.conf')).unlink(missing_ok=True)
    del profiles[name]
    store.set(STATE_KEY, profiles)
    return sync(store, runner, apply)


def status(store, runner=subprocess.run):
    profiles = _profiles(store)
    try:
        live = active(runner)
        error = None
    except Exception as exc:
        live, error = set(), str(exc)[:200]
    return {'ok': True, 'profiles': [{'name': name, 'active': name in live, **info} for name, info in sorted(profiles.items())],
            'error': error}
