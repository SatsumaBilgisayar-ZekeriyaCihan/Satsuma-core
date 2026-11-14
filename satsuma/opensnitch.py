"""OpenSnitch as the per-application firewall, with Satsuma keeping the rest.

User decision 2026-11-04: Satsuma's own App Control attributed connections
by scanning the socket table; a short-lived program could slip between
scans, and every script run by one interpreter shared one identity.
OpenSnitch takes the process identity from the kernel (eBPF) and decides
per program, command line, user, host and port. Satsuma keeps the default
drop firewall, DNS pinning, Suricata and the MITM watch.

- running(): a root-owned process whose executable is /usr/bin/opensnitchd.
  A process that only calls itself "opensnitchd" does not count.
- While it runs, Satsuma App Control steps aside (its queue would ask a
  second time); when it stops, App Control comes back on its own, so a
  per-program gate is never missing.
- Satsuma writes its own allow rules under /etc/opensnitchd/rules, all
  named satsuma-*.json and removed when no longer needed: the UDP port of
  an active Satsuma WireGuard profile (its encrypted packets come from the
  kernel, not from a program) and Satsuma's DNS filter (dnsmasq as the
  satsuma-dns user). Rules written by the user are never touched.

Satsuma uygulama güvenlik duvarı olarak OpenSnitch'i kullanır, gerisini
kendisi yapar. Kullanıcı kararı 2026-11-04: Satsuma'nın App Control'ü
bağlantıları soket tablosunu tarayıp eşliyordu; kısa ömürlü bir program
taramalar arasından kaçabiliyor, bir yorumlayıcının çalıştırdığı bütün
betikler tek kimlik sayılıyordu. OpenSnitch süreç kimliğini çekirdekten
(eBPF) alır; programa, komut satırına, kullanıcıya, adrese ve porta göre
karar verir. Varsayılan-düşür güvenlik duvarı, DNS sabitleme, Suricata ve
MITM izleyicisi Satsuma'da kalır. OpenSnitch çalışırken App Control kenara
çekilir, durunca kendiliğinden geri gelir; programa göre kapı hiç eksik
kalmaz. Satsuma kendi izin kurallarını /etc/opensnitchd/rules altında
satsuma-*.json adıyla yazar (etkin WireGuard portu, DNS filtresi) ve
gerekmeyince siler; kullanıcının kurallarına dokunmaz.
"""
import json
import os
from pathlib import Path
import time

DAEMON = '/usr/bin/opensnitchd'
RULES = Path('/etc/opensnitchd/rules')
PREFIX = 'satsuma-'


def running(proc='/proc'):
    """True when a root-owned process runs the real opensnitchd executable."""
    try:
        names = [n for n in os.listdir(proc) if n.isdigit()]
    except OSError:
        return False
    for name in names:
        try:
            if os.readlink(os.path.join(proc, name, 'exe')) != DAEMON:
                continue
            with open(os.path.join(proc, name, 'status')) as handle:
                for line in handle:
                    if line.startswith('Uid:'):
                        if line.split()[1] == '0':
                            return True
                        break
        except OSError:
            continue
    return False


def installed(daemon=DAEMON):
    return Path(daemon).is_file()


def _operand(operand, data, kind='simple'):
    return {'type': kind, 'operand': operand, 'sensitive': False, 'data': str(data), 'list': None}


# Fedora 42 merged /usr/sbin into /usr/bin: the kernel reports
# /usr/bin/dnsmasq, so a rule naming /usr/sbin/dnsmasq never matched and
# OpenSnitch blocked the DNS filter's upstream queries (field 2026-11-04).
# Fedora 42 /usr/sbin'i /usr/bin ile birleştirdi; çekirdek /usr/bin/dnsmasq
# bildirir, /usr/sbin/dnsmasq yazan kural hiç eşleşmiyordu.
DNSMASQ_PATH = r'^/usr/s?bin/dnsmasq$'


def rule(name, description, conditions):
    """An OpenSnitch rule that allows when every condition matches.

    A condition is (operand, value) or (operand, value, type), type 'simple'
    or 'regexp'.
    """
    stamp = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    return {'created': stamp, 'updated': stamp, 'name': PREFIX + name, 'description': description,
            'enabled': True, 'precedence': True, 'nolog': False, 'action': 'allow', 'duration': 'always',
            'operator': {'type': 'list', 'operand': 'list', 'sensitive': False, 'data': '',
                         'list': [_operand(*condition[:2], *(condition[2:] or ('simple',))) for condition in conditions]}}


def wanted_rules(wireguard_ports=(), dns_uid=None):
    rules = {}
    for port in sorted(set(wireguard_ports)):
        rules[f'wireguard-{port}'] = rule(f'wireguard-{port}', 'Satsuma WireGuard: şifreli tünel paketleri (çekirdek)',
                                         [('protocol', 'udp'), ('dest.port', port)])
    if dns_uid is not None:
        rules['dns-filter'] = rule('dns-filter', 'Satsuma DNS filtresi (dnsmasq, satsuma-dns)',
                                   [('process.path', DNSMASQ_PATH, 'regexp'), ('user.id', dns_uid), ('dest.port', 53)])
    return rules


def sync_rules(rules, directory=None, prune=True):
    """Write wanted satsuma-* rules, remove stale ones; returns the names written.

    prune=False writes only the given rules and removes nothing.
    prune=False yalnızca verilen kuralları yazar, hiçbir şeyi silmez.
    """
    directory = Path(RULES if directory is None else directory)
    if not directory.is_dir():
        return []
    written = []
    for name, body in rules.items():
        path = directory / (PREFIX + name + '.json')
        old = None
        try:
            old = json.loads(path.read_text())
        except (OSError, ValueError):
            pass
        comparable = lambda r: {k: v for k, v in (r or {}).items() if k not in ('created', 'updated')}
        if comparable(old) != comparable(body):
            tmp = path.with_name('.' + path.name + '.tmp')
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, 'w') as handle:
                json.dump(body, handle, ensure_ascii=False, indent=1)
            os.replace(tmp, path)
        written.append(path.name)
    for path in (directory.glob(PREFIX + '*.json') if prune else ()):
        if path.name not in written:
            path.unlink(missing_ok=True)
    return written


def ensure_dns_rule(directory=None, uid=...):
    """Write only the DNS filter's allow rule; nothing else is touched or removed.

    The installer calls this before it probes dnsmasq. Field 2026-11-04: on an
    upgrade the rule was written later, by the operator service, so the probe
    ran against the old rule and OpenSnitch blocked dnsmasq's upstream queries.
    Yalnızca DNS filtresinin izin kuralını yazar; başka hiçbir şeye dokunmaz,
    hiçbir şeyi silmez. Kurulum dnsmasq'ı sınamadan önce bunu çağırır. Saha
    2026-11-04: yükseltmede kural sonradan operatör servisi tarafından yazılıyor,
    sınama eski kuralla çalışıyor ve OpenSnitch dnsmasq'ın dış sorgularını
    engelliyordu.
    """
    uid = dns_uid() if uid is ... else uid
    if uid is None:
        return []
    return sync_rules({'dns-filter': wanted_rules((), uid)['dns-filter']}, directory, prune=False)


def dns_uid():
    try:
        import pwd
        return pwd.getpwnam('satsuma-dns').pw_uid
    except (KeyError, ImportError):
        return None


def status(proc='/proc', directory=None):
    directory = Path(RULES if directory is None else directory)
    rules = sorted(p.name for p in directory.glob(PREFIX + '*.json')) if directory.is_dir() else []
    is_running = running(proc)
    return {'installed': installed(), 'running': is_running, 'satsuma_rules': rules,
            'app_control': 'opensnitch' if is_running else 'satsuma'}
