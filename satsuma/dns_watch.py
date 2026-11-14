"""Watch which DNS servers this machine uses, and who could change them.

Taken from the yeni-yazim branch (netd/dns.py) and fitted to 2.x, where
every plain DNS query on port 53 is redirected to Satsuma's own dnsmasq
(127.0.0.1:53053), which asks one upstream server (dns_policy.upstream).
Changing a DNS server sends name lookups to the attacker, so the setting
is watched instead of frozen (chattr +i on /etc/resolv.conf would stop
NetworkManager from applying the servers of the next network):

* /etc/resolv.conf must be root-owned and writable by root only; a
  symbolic link may only point to the files NetworkManager or
  systemd-resolved manage under /run.
* Pinned servers (/etc/satsuma-core/dns-pinned.json, {"pinned":
  [addresses]}, root-owned; shipped with OpenDNS, user decision
  2026-10-26): the upstream of Satsuma's DNS filter, where every query
  ends up, must be one of them. A rogue DHCP server or a taken-over modem
  handing out its own DNS server is the most common way into the middle;
  since port 53 is redirected to the filter, the server DHCP hands out is
  not where queries go, and is not judged against the pinned set.
* Every server in /etc/resolv.conf must be one NetworkManager knows (from
  DHCP or a profile the user made): a server written into the file by
  hand or by malware is reported. Behind the systemd-resolved stub
  (127.0.0.53) its real upstreams are checked. A change of the filter's
  upstream is reported once (high when servers are pinned).
* An immutable flag is reported at info level, with what it breaks.

Bu makinenin kullandığı DNS sunucularını ve onları kimin değiştirebileceğini
izler (yeni-yazim dalından, 2.x'e uyarlandı: 53. porttaki her DNS sorgusu
Satsuma'nın dnsmasq'ına yönlendirilir, o da tek bir üst sunucuya sorar).
/etc/resolv.conf yalnızca root'a ait ve yalnızca root yazabilir olmalı.
Sabitlenmiş sunucular (/etc/satsuma-core/dns-pinned.json; OpenDNS ile
gelir) varsa her sorgunun gittiği filtre üst sunucusu onlardan biri
olmalıdır. resolv.conf'taki her sunucu NetworkManager'ın bildiği bir
sunucu olmalıdır; dosyaya elle ya da zararlı yazılımla eklenen sunucu
bildirilir. Üst sunucunun değişmesi bir
kez bildirilir.
"""
import array
import fcntl
import ipaddress
import json
import os
import stat
import subprocess

RESOLV_CONF = '/etc/resolv.conf'
PINNED_PATH = '/etc/satsuma-core/dns-pinned.json'
RESOLVED_UPSTREAMS = '/run/systemd/resolve/resolv.conf'
RESOLVED_STUB = ipaddress.ip_address('127.0.0.53')
ALLOWED_TARGETS = ('/run/NetworkManager/resolv.conf', '/run/NetworkManager/no-stub-resolv.conf',
                   '/run/systemd/resolve/stub-resolv.conf', '/run/systemd/resolve/resolv.conf')
NMCLI = '/usr/bin/nmcli'
_ENV = {'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'}
_FS_IOC_GETFLAGS = 0x80086601
_FS_IMMUTABLE_FL = 0x10


def nameservers(path):
    found = set()
    try:
        with open(path, encoding='ascii', errors='replace') as stream:
            text = stream.read(256 * 1024)
    except OSError:
        return found
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == 'nameserver':
            try:
                found.add(ipaddress.ip_address(fields[1].split('%', 1)[0]))
            except ValueError:
                pass
    return found


def pinned_servers(path=PINNED_PATH):
    """Servers the administrator pinned; an empty set when nothing is pinned.

    The file must be root-owned and not writable by others, or a local
    attacker could pin their own server. A bad file raises instead of
    silently falling back to trusting DHCP.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return frozenset()
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('dns-pinned.json must be a root-owned file not writable by others')
        data = json.load(stream)
    if not isinstance(data, dict) or set(data) != {'pinned'} or not isinstance(data['pinned'], list):
        raise ValueError('dns-pinned.json must be {"pinned": [addresses]}')
    return frozenset(ipaddress.ip_address(value) for value in data['pinned'])


def networkmanager_servers(runner=subprocess.run):
    """DNS servers NetworkManager has configured on any device; None when it cannot be asked."""
    try:
        result = runner([NMCLI, '-t', '-f', 'IP4.DNS,IP6.DNS', 'device', 'show'],
                        capture_output=True, text=True, timeout=5, env=_ENV)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    found = set()
    for line in result.stdout.splitlines():
        _, sep, value = line.partition(':')
        if sep and value:
            try:
                found.add(ipaddress.ip_address(value.replace('\\:', ':').split('%', 1)[0]))
            except ValueError:
                pass
    return found


def immutable(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        flags = array.array('i', [0])
        fcntl.ioctl(fd, _FS_IOC_GETFLAGS, flags, True)
        return bool(flags[0] & _FS_IMMUTABLE_FL)
    except OSError:
        return False  # filesystem without attribute support
    finally:
        os.close(fd)


def servers(path=RESOLV_CONF, upstreams=RESOLVED_UPSTREAMS):
    """The servers lookups go to: resolv.conf, or resolved's upstreams behind its stub."""
    found = nameservers(path)
    if found == {RESOLVED_STUB}:
        return nameservers(upstreams)
    return found


def findings(upstream=None, previous_upstream=None, path=RESOLV_CONF, upstreams=RESOLVED_UPSTREAMS,
             pinned=pinned_servers, known=networkmanager_servers, is_immutable=immutable,
             allowed_targets=ALLOWED_TARGETS, stat_file=os.stat):
    """upstream: dns_policy.upstream now; previous_upstream: at the last check."""
    found = []
    if os.path.islink(path):
        target = os.path.realpath(path)
        if target not in allowed_targets:
            found.append({'code': 'resolv_conf_unexpected_link', 'severity': 'high', 'target': target})
    try:
        info = stat_file(path)
    except OSError as exc:
        return found + [{'code': 'resolv_conf_missing', 'severity': 'high', 'error': exc.strerror or str(exc)}]
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        found.append({'code': 'resolv_conf_writable', 'severity': 'critical', 'uid': info.st_uid,
                      'mode': oct(stat.S_IMODE(info.st_mode))})
    if is_immutable(path):
        found.append({'code': 'resolv_conf_immutable', 'severity': 'info',
                      'note': 'NetworkManager cannot apply the DNS servers of a new network'})
    try:
        allowed = pinned()
    except (OSError, ValueError) as exc:
        return found + [{'code': 'dns_config_invalid', 'severity': 'high', 'error': str(exc)[:200]}]
    in_use = servers(path, upstreams)
    try:
        filter_upstream = ipaddress.ip_address(upstream) if upstream else None
    except ValueError:
        filter_upstream = None
        found.append({'code': 'dns_upstream_invalid', 'severity': 'high', 'server': str(upstream)[:100]})
    if allowed and filter_upstream is not None and filter_upstream not in allowed:
        found.append({'code': 'dns_upstream_not_pinned', 'severity': 'high', 'server': str(filter_upstream)})
    nm = known()
    if nm is not None:
        for server in sorted(in_use - nm - {RESOLVED_STUB}, key=str):
            found.append({'code': 'dns_server_not_from_networkmanager', 'severity': 'high', 'server': str(server)})
    if previous_upstream and upstream and str(previous_upstream) != str(upstream):
        found.append({'code': 'dns_upstream_changed', 'severity': 'high' if allowed else 'medium',
                      'before': str(previous_upstream), 'after': str(upstream)})
    return found
