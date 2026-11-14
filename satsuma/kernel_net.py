"""Kernel network settings against interception, checked and written back.

Taken from the yeni-yazim branch (common/kernel_settings.py and
privd/kernel.py). The values are shipped in
/usr/lib/sysctl.d/92-satsuma-network.conf, so systemd-sysctl applies them
at boot and for every new interface; mitm_watch checks them every minute
and writes a changed value back towards the hardened one (only this fixed
table, never a value chosen by a caller):

* route_localnet = 0 on every interface: with it on, a remote host can
  reach services that believe they only listen on localhost.
* rp_filter = 1 (strict) on all, default and every interface: packets
  whose source could not have arrived on that interface (forged 127.x,
  forged LAN addresses from the internet) are dropped. The kernel uses
  the larger of the "all" and the interface value, and Fedora's
  50-default.conf sets every interface to 2 (loose), so the interfaces
  are set too.
* Source routing and ICMP redirects are refused: a remote host cannot
  change how this machine routes.

Ortadaki adam saldırılarına karşı çekirdek ağ ayarları; denetlenir ve
geri yazılır. yeni-yazim dalından alındı. Değerler
/usr/lib/sysctl.d/92-satsuma-network.conf ile gelir; systemd-sysctl
açılışta ve her yeni arayüzde uygular. mitm_watch her dakika denetler ve
değişen değeri sertleştirilmiş değere geri yazar (yalnızca bu sabit
tablo). route_localnet her arayüzde 0; rp_filter her yerde 1 (sıkı;
sahte kaynak adresli paketler düşer); kaynak yönlendirme ve ICMP
yönlendirmeleri reddedilir.
"""
import os
import re

PROC_SYS = '/proc/sys'
SYSCTL_FILE = '/usr/lib/sysctl.d/92-satsuma-network.conf'

# key relative to /proc/sys -> required value
REQUIRED = {
    'net/ipv4/conf/all/rp_filter': '1',
    'net/ipv4/conf/default/rp_filter': '1',
    'net/ipv4/conf/all/log_martians': '1',
    'net/ipv4/conf/all/accept_source_route': '0',
    'net/ipv4/conf/default/accept_source_route': '0',
    'net/ipv6/conf/all/accept_source_route': '0',
    'net/ipv6/conf/default/accept_source_route': '0',
    'net/ipv4/conf/all/accept_redirects': '0',
    'net/ipv4/conf/default/accept_redirects': '0',
    'net/ipv4/conf/all/secure_redirects': '0',
    'net/ipv4/conf/all/send_redirects': '0',
    'net/ipv4/conf/default/send_redirects': '0',
    'net/ipv6/conf/all/accept_redirects': '0',
    'net/ipv6/conf/default/accept_redirects': '0',
    'net/ipv4/icmp_echo_ignore_broadcasts': '1',
    'net/ipv4/tcp_syncookies': '1',
}
# Settings that must hold on every interface directory, not just all/default.
PER_INTERFACE = {
    'route_localnet': '0',
    'accept_source_route': '0',
    'rp_filter': '1',
}
_KEY = re.compile(r'net/ipv[46]/(?:conf/[A-Za-z0-9_.@-]{1,15}/[a-z_]+|[a-z_]+)')


def _read(path):
    try:
        with open(path) as stream:
            return stream.read().strip()
    except OSError:
        return None


def expected(root=PROC_SYS, listdir=os.listdir):
    """Every key required on this machine right now, with its value."""
    wanted = dict(REQUIRED)
    try:
        interfaces = listdir(os.path.join(root, 'net/ipv4/conf'))
    except OSError:
        interfaces = []
    for interface in interfaces:
        for name, value in PER_INTERFACE.items():
            wanted[f'net/ipv4/conf/{interface}/{name}'] = value
    return wanted


def drift(root=PROC_SYS, read=_read, listdir=os.listdir):
    """Keys whose live value differs from the required one."""
    found = []
    for key, value in sorted(expected(root, listdir).items()):
        actual = read(os.path.join(root, key))
        if actual is not None and actual != value:
            found.append({'key': key, 'expected': value, 'actual': actual})
    return found


def restore(root=PROC_SYS, listdir=os.listdir, read=_read):
    """Write drifted keys back to the hardened value (root only)."""
    restored, failed = [], []
    for item in drift(root, read=read, listdir=listdir):
        key = item['key']
        if not _KEY.fullmatch(key) or '..' in key:
            failed.append({**item, 'error': 'unexpected key'})
            continue
        try:
            fd = os.open(os.path.join(root, key), os.O_WRONLY | os.O_NOFOLLOW)
            try:
                os.write(fd, item['expected'].encode())
            finally:
                os.close(fd)
            restored.append(item)
        except OSError as exc:
            failed.append({**item, 'error': exc.strerror or str(exc)})
    return {'restored': restored, 'failed': failed}


def sysctl_conf():
    """The text of the sysctl.d file shipped with the package."""
    lines = ['# Satsuma: kernel network settings against interception (kernel_net.py).',
             '# Satsuma: araya girme saldırılarına karşı çekirdek ağ ayarları.',
             '# mitm_watch checks these every minute and writes a changed value back.']
    for key, value in REQUIRED.items():
        lines.append(f"{key.replace('/', '.')} = {value}")
    for name, value in PER_INTERFACE.items():
        lines.append(f'net.ipv4.conf.*.{name} = {value}')
    return '\n'.join(lines) + '\n'
