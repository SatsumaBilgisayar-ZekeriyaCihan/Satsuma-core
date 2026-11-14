"""Outbound traffic profiles for the managed firewall.

The managed table drops everything by default. A profile only chooses which
destination ports may leave the machine, always through the Suricata queue;
incoming traffic is accepted only as replies to those outbound connections,
in every profile. The base profile (DNS and HTTPS) is always present; the
add-ons extend it and "custom" adds the operator's own ports. The DNS server
is never chosen here. The "wireguard" field carries the endpoint UDP ports
of active Satsuma WireGuard profiles (2.2.29); only satsuma.wireguard sets
it, and it is kept when the operator changes the rest of the profile.

Vendor ports, from the vendors' documentation as of 2026-10-25 (read through
search results restricted to the vendors' own domains; the pages could not be
opened directly from the build environment):
- TeamViewer, "Ports and URLs used by TeamViewer"
  (teamviewer.com knowledge base): outbound TCP/UDP 5938 first, then TCP
  443, then TCP 80; no inbound port is needed.
- AnyDesk, "Configure firewalls for AnyDesk" (support.anydesk.com/docs/
  firewall): TCP 80, 443 and 6568; at least one must be open.
TCP 80 is left out on purpose: both programs work over 443 or their own
port, and plain HTTP is the easiest place for a man in the middle.
E-mail ports follow RFC 8314 (implicit TLS) and RFC 6409 (submission).

Yönetilen güvenlik duvarı için çıkış trafiği profilleri.

Yönetilen tablo varsayılan olarak her şeyi düşürür. Profil yalnızca hangi
hedef portlara bilgisayardan çıkılabileceğini seçer; trafik her zaman
Suricata kuyruğundan geçer. Gelen trafik her profilde yalnızca bu çıkış
bağlantılarının yanıtı olarak kabul edilir. Temel profil (DNS ve HTTPS) her
zaman vardır; eklentiler onu genişletir, "özel" ise yöneticinin kendi
portlarını ekler. DNS sunucusu burada seçilmez. "wireguard" alanı etkin Satsuma
WireGuard profillerinin uç nokta UDP portlarını taşır (2.2.29); onu yalnızca
satsuma.wireguard yazar, yönetici profilin geri kalanını değiştirince korunur.

Üretici portları, 2026-10-25 itibarıyla üreticilerin belgelerine göre (yalnızca
üreticilerin kendi alan adlarıyla sınırlı arama sonuçlarından okundu; sayfalar
derleme ortamından doğrudan açılamadı):
- TeamViewer, "Ports and URLs used by TeamViewer" (teamviewer.com bilgi
  bankası): önce dışarıya TCP/UDP 5938, sonra TCP 443, sonra TCP 80; gelen
  port gerekmez.
- AnyDesk, "Configure firewalls for AnyDesk" (support.anydesk.com/docs/
  firewall): TCP 80, 443 ve 6568; en az biri açık olmalı.
TCP 80 bilerek dışarıda bırakıldı: iki program da 443 ya da kendi portuyla
çalışır; şifresiz HTTP ise ortadaki adam için en kolay yerdir.
E-posta portları RFC 8314 (doğrudan TLS) ve RFC 6409'a (gönderim) uyar.
"""
import json
import os
from pathlib import Path

PROFILE_FILE = Path('/etc/satsuma-core/egress-profile.json')
BASE = {'tcp': (53, 443), 'udp': (53,)}
ADDONS = {
    'remote_support': {
        'title': 'Uzak destek (TeamViewer, AnyDesk) — yalnızca dışarıya',
        'ports': {'tcp': (5938, 6568), 'udp': (5938,)},
        'explain': 'TeamViewer TCP/UDP 5938, AnyDesk TCP 6568. Dışarıdan gelen bağlantı açılmaz.',
    },
    'ssh': {
        'title': 'SSH ile başka bilgisayara bağlanma',
        'ports': {'tcp': (22,), 'udp': ()},
        'explain': 'TCP 22, yalnızca dışarıya. Bu bilgisayara SSH ile girilemez.',
    },
    'email': {
        'title': 'E-posta programı (şifreli SMTP/IMAP/POP3)',
        'ports': {'tcp': (465, 587, 993, 995), 'udp': ()},
        'explain': 'TCP 465 ve 587 gönderim, 993 IMAP, 995 POP3; hepsi TLS.',
    },
}
CUSTOM_LIMIT = 32


def _ports(values, name):
    if not isinstance(values, (list, tuple)) or len(values) > CUSTOM_LIMIT:
        raise ValueError(f'{name}: en fazla {CUSTOM_LIMIT} port listesi gerekli')
    out = set()
    for value in values:
        if type(value) is not int or not 1 <= value <= 65535:
            raise ValueError(f'{name}: geçersiz port {value!r}')
        out.add(value)
    return out


WIREGUARD_LIMIT = 8


def normalize(selection):
    """Validated {'addons': [...], 'custom': {'tcp': [...], 'udp': [...]}, 'wireguard': {'udp': [...]}}.

    'wireguard' holds the endpoint UDP ports of active Satsuma WireGuard
    profiles; only satsuma.wireguard writes it.
    """
    if not isinstance(selection, dict) or set(selection) - {'addons', 'custom', 'wireguard'}:
        raise ValueError('Profil seçimi addons, custom ve wireguard alanlarından oluşur')
    addons = selection.get('addons', [])
    if not isinstance(addons, list) or any(a not in ADDONS for a in addons):
        raise ValueError('Bilinmeyen profil eklentisi')
    custom = selection.get('custom', {}) or {}
    if not isinstance(custom, dict) or set(custom) - {'tcp', 'udp'}:
        raise ValueError('Özel portlar tcp ve udp listeleridir')
    wireguard = selection.get('wireguard', {}) or {}
    if not isinstance(wireguard, dict) or set(wireguard) - {'udp'}:
        raise ValueError('WireGuard portları yalnızca udp listesidir')
    wg_ports = sorted(_ports(wireguard.get('udp', []), 'wireguard'))
    if len(wg_ports) > WIREGUARD_LIMIT:
        raise ValueError(f'En fazla {WIREGUARD_LIMIT} WireGuard portu')
    return {'addons': sorted(set(addons)),
            'custom': {p: sorted(_ports(custom.get(p, []), p)) for p in ('tcp', 'udp')},
            'wireguard': {'udp': wg_ports}}


def ports_for(selection):
    """Destination ports per protocol, as sorted tuples."""
    selection = normalize(selection)
    ports = {p: set(BASE[p]) for p in ('tcp', 'udp')}
    for name in selection['addons']:
        for p in ('tcp', 'udp'):
            ports[p].update(ADDONS[name]['ports'][p])
    for p in ('tcp', 'udp'):
        ports[p].update(selection['custom'][p])
    ports['udp'].update(selection['wireguard']['udp'])
    return {p: tuple(sorted(v)) for p, v in ports.items()}


def load(path=None):
    """The stored selection; the base (narrowest) profile when none is readable.

    A damaged file falls back to the narrowest profile: the boot setup then
    sees a mismatch with the ruleset file and keeps the emergency drop, and
    any wider selection asks for the password again.
    """
    try:
        return normalize(json.loads(Path(PROFILE_FILE if path is None else path).read_text()))
    except (OSError, ValueError):
        return normalize({})


def current_ports(path=None):
    return ports_for(load(path))


def opens_more(selection, path=None):
    """True when the new selection allows a port the current one does not."""
    new, old = ports_for(selection), current_ports(path)
    return any(set(new[p]) - set(old[p]) for p in ('tcp', 'udp'))


def save(selection, path=None):
    path = Path(PROFILE_FILE if path is None else path)
    tmp = path.with_name('.' + path.name + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'w') as fh:
        json.dump(normalize(selection), fh, sort_keys=True)
        fh.write('\n')
    os.replace(tmp, path)


def describe(selection):
    """Plain-Turkish summary for the dashboard."""
    selection = normalize(selection)
    ports = ports_for(selection)
    return {
        'selection': selection,
        'ports': {p: list(v) for p, v in ports.items()},
        'addons': [{'id': k, 'title': v['title'], 'explain': v['explain'], 'enabled': k in selection['addons']}
                   for k, v in ADDONS.items()],
        'base': 'Her zaman açık: DNS (TCP/UDP 53) ve HTTPS (TCP 443).',
        'wireguard': ('Etkin WireGuard için açık UDP: ' + ', '.join(map(str, selection['wireguard']['udp'])))
                     if selection['wireguard']['udp'] else 'Etkin WireGuard yok.',
        'incoming': 'Dışarıdan başlatılan bağlantılar her profilde kapalıdır.',
    }
