"""Manage the dedicated DNS instance; report local and system readiness separately.

Stability (2026-11-03): an intentional start or restart that systemd refuses
because of its start-rate limit is retried once after ``reset-failed``; the
readiness wait grows with the size of the block list (dnsmasq parses it before
it listens); and a configuration is not rolled back when the upstream servers
did not change and dnsmasq answers but the upstream gives nothing, because the
change is then not the cause. With an unchanged configuration the minute
refresh starts the service only when it is not active (2026-11-04).

Ayrılmış DNS hizmetini yönet; yerel ve sistem hazırlığını ayrı raporla.

Kararlılık (2026-11-03): systemd'nin başlatma hızı sınırı yüzünden reddettiği
bilinçli bir start/restart, ``reset-failed`` sonrası bir kez yeniden denenir;
hazır olma beklemesi engel listesinin boyutuyla artar (dnsmasq dinlemeden önce
listeyi ayrıştırır); üst sunucular değişmediyse ve dnsmasq yanıt verip üst
sunucu hiçbir şey vermiyorsa yapılandırma geri alınmaz, çünkü değişiklik sebep
değildir. Yapılandırma değişmediyse dakikalık yenileme servisi yalnızca
çalışmıyorsa başlatır (2026-11-04).
"""
import grp
import ipaddress
import os
from pathlib import Path
import subprocess
import tempfile

DIRECTORY = Path('/etc/satsuma-core/dns')


class UpstreamNotUsable(RuntimeError):
    """dnsmasq is up and answering, but the upstream gives no usable reply.

    dnsmasq çalışıyor ve yanıt veriyor, ama üst sunucu kullanılabilir yanıt vermiyor.
    """

SERVICE = 'satsuma-core-dns.service'
# 2.2.15: the default upstream (user decision 2026-10-26). When the upstream
# is one of them, dnsmasq is given both, so one being down does not stop DNS.
OPENDNS = ('208.67.222.222', '208.67.220.220')


def upstream_servers(upstream):
    first = str(ipaddress.ip_address(upstream))
    return [first] + [server for server in OPENDNS if first in OPENDNS and server != first]


def render(policy, blocked, allowed):
    resolver = ipaddress.ip_address(policy['upstream'])
    if resolver.is_loopback or resolver.is_multicast or resolver.is_unspecified:
        raise ValueError('A real non-loopback upstream DNS server is required')
    from .domain_lists import domain
    from .dns_readiness import NAME as PROBE_NAME
    # The readiness probe asks for this reserved documentation name (RFC 2606).
    # A list that blocks it made every probe fail, so the filter never became
    # active and OTX/DeepSeek lost name resolution (field log 2026-11-04).
    # Hazırlık testi bu ayrılmış adı sorar; onu engelleyen bir liste her testi
    # düşürüyor, filtre hiç devreye girmiyordu (saha kaydı 2026-11-04).
    allowed = {domain(name) for name in allowed} | {PROBE_NAME}
    domains = {domain(name) for name in blocked}
    domains = {name for name in domains if not any(name == item or name.endswith('.' + item) for item in allowed)}
    rules = ''.join('address=/' + name + '/#\nlocal=/' + name + '/\n' for name in sorted(domains))
    # dnsmasq uses the most-specific suffix; exceptions under blocked parents
    # explicitly use the configured upstream instead of the null address.
    rules += ''.join('server=/' + name + '/' + str(resolver) + '\n' for name in sorted(allowed))
    return rules


def verify_config(directory=DIRECTORY):
    import hmac
    from .package_trust import secure_read
    from installer.integrity import read_key, file_hmac
    names = ['dnsmasq.conf', 'blocked.conf']
    if (directory/ADDED).exists():
        names.append(ADDED)
    for name in names:
        path=directory/name
        secure_read(path, limit=128*1024*1024)
        signature=secure_read(Path(str(path)+'.sig'), limit=128)
        if not hmac.compare_digest(file_hmac(read_key(),path),signature):
            raise PermissionError('DNS configuration signature mismatch: '+str(path))
    return True


def atomic(path, content, gid):
    fd, temporary = tempfile.mkstemp(prefix='.dns-', dir=path.parent)
    try:
        os.fchmod(fd, 0o640)
        os.fchown(fd, 0, gid)
        with os.fdopen(fd, 'w') as stream:
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        from installer.integrity import read_key, sign
        sign(path, read_key())
    finally:
        Path(temporary).unlink(missing_ok=True)


def _systemctl(runner, verb):
    """start/restart the service; if systemd refuses (start-rate limit), reset and retry once."""
    result = runner(['/usr/bin/systemctl', verb, SERVICE], capture_output=True, text=True, timeout=30)
    if result.returncode:
        runner(['/usr/bin/systemctl', 'reset-failed', SERVICE], capture_output=True, text=True, timeout=30)
        result = runner(['/usr/bin/systemctl', verb, SERVICE], capture_output=True, text=True, timeout=30)
    return result


def _ensure_running(runner):
    """Start the service only when it is not active.

    The refresh timer runs every minute; an unconditional ``systemctl start``
    raised a persistence finding each time (field 2026-11-04, 222 a day).
    Zamanlayıcı her dakika çalışır; koşulsuz ``systemctl start`` her seferinde
    kalıcılık bulgusu üretiyordu. Servis zaten çalışıyorsa başlatılmaz.
    """
    active = runner(['/usr/bin/systemctl', 'is-active', '--quiet', SERVICE], capture_output=True, text=True, timeout=30)
    if active.returncode == 0:
        return active
    return _systemctl(runner, 'start')


ADDED = 'added.hosts'


def added_hosts(old_rules, new_rules):
    """hosts lines for names blocked since the running list was loaded (2.2.51).

    A hosts line blocks the name itself; subdomains follow at the next full
    reload. Yeni engellenen adlar için hosts satırları; alt alan adları bir
    sonraki tam yüklemede gelir.
    """
    def names(rules):
        return {line[len('address=/'):-len('/#')] for line in (rules or '').splitlines()
                if line.startswith('address=/') and line.endswith('/#')}
    fresh = sorted(names(new_rules) - names(old_rules))
    return ''.join(f'0.0.0.0 {name}\n:: {name}\n' for name in fresh), len(fresh)


def _main_pid(runner):
    shown = runner(['/usr/bin/systemctl', 'show', '-p', 'MainPID', '--value', SERVICE],
                   capture_output=True, text=True, timeout=30)
    try:
        pid = int((shown.stdout or '').strip())
    except ValueError:
        return None
    return pid if pid > 1 else None


def reload_hosts(runner, kill=None, readlink=None):
    """SIGHUP to the running dnsmasq: it re-reads added.hosts without a restart (no DNS gap).

    The signal goes straight to the verified dnsmasq PID; ``systemctl kill``
    would itself look like a process-stop command to Satsuma's rules.
    Sinyal doğrulanmış dnsmasq PID'ine doğrudan gider.
    """
    import signal
    kill = kill or os.kill
    readlink = readlink or os.readlink
    pid = _main_pid(runner)
    if pid is None:
        return False
    try:
        if readlink(f'/proc/{pid}/exe') != '/usr/sbin/dnsmasq':
            return False
        kill(pid, signal.SIGHUP)
    except OSError:
        return False
    return True


def _servers(config):
    return sorted(line for line in (config or '').splitlines() if line.startswith('server='))


def scaled_timeout(size_bytes, base=15.0, per_mib=2.0, cap=120.0):
    """dnsmasq reads the block list before it listens: wait longer for a bigger list."""
    return min(cap, base + per_mib * max(0, size_bytes) / (1024 * 1024))


def _refresh(store, runner=subprocess.run, directory=DIRECTORY):
    policy = store.get('dns_policy', {}) or {}
    if not policy.get('upstream'):
        state={'ok': False, 'status': 'NOT_CONFIGURED', 'updated_at': __import__('time').time()}
        store.set('dns_filter_health',state)
        if policy.get('enabled'):raise RuntimeError('DNS filter enabled without an upstream resolver')
        return state
    import time
    records = store.get('dns_blocked_domains', {}) or {}
    blocked = {name for name, info in records.items() if info.get('expires_at', 0) > time.time()}
    # 2.2.44 (owner's decision 2026-11-13): no list downloaded from the internet
    # (the HaGeZi lists of 2.2.37) is used; a changed list is a way to steer this
    # machine's DNS. Blocked names come from Satsuma's own findings (OTX and
    # the like) and from lists the user added.
    # İnternetten indirilen liste kullanılmaz; engeller Satsuma bulguları ve
    # kullanıcının eklediği listelerden gelir.
    from .custom_dns_lists import blocked_domains
    blocked.update(blocked_domains(store))
    rules = render(policy, blocked, store.get('dns_allowed_domains', []) or [])
    directory.mkdir(parents=True, exist_ok=True, mode=0o750)
    if directory.is_symlink():
        raise PermissionError('Unsafe DNS configuration directory')
    gid = grp.getgrnam('satsuma-dns').gr_gid
    os.chown(directory, 0, gid); os.chmod(directory, 0o750)
    # 2.2.44: own network namespace (satsuma.dns_netns), never loopback.
    from .dns_netns import DNS_ADDR
    config = ('port=53\nlisten-address=' + DNS_ADDR + '\nbind-interfaces\nno-resolv\nno-hosts\n'
              'cache-size=1000\n' + ''.join('server=' + server + '\n' for server in upstream_servers(policy['upstream'])) + 'conf-file=' + str(directory / 'blocked.conf') + '\n'
              + 'addn-hosts=' + str(directory / ADDED) + '\n')
    block_path, config_path = directory / 'blocked.conf', directory / 'dnsmasq.conf'
    if block_path.exists() or config_path.exists():verify_config(directory)
    old_rules = block_path.read_text() if block_path.exists() else None
    old_config = config_path.read_text() if config_path.exists() else None
    added_path = directory / ADDED
    old_added = added_path.read_text() if added_path.exists() else None
    hot = False
    if removals_wait(store, old_rules, rules, old_config == config, time.time()):
        # Only removals: the running filter keeps blocking a little longer
        # instead of a restart (and a DNS gap) every minute.
        rules = old_rules
    elif hot_add_allowed(store, old_rules, rules, old_config == config, old_added is not None, time.time()):
        # 2.2.51: new names go to added.hosts and dnsmasq re-reads it on SIGHUP;
        # the full list (with subdomains) is reloaded at most every 30 minutes.
        hosts, count = added_hosts(old_rules, rules)
        if hosts != old_added:
            atomic(added_path, hosts, gid)
            hot = True
        rules = old_rules
    if old_rules == rules and old_config == config:
        if hot and policy.get('enabled'):
            if not reload_hosts(runner):
                raise RuntimeError('dnsmasq could not re-read the added names')
            probe()
            store.set('dns_filter_hot_added_at', time.time())
        verify_config(directory)
        if policy.get('enabled'):
            started = _ensure_running(runner)
            if started.returncode:
                raise RuntimeError('dnsmasq service could not be started')
            probe()
        health = record_readiness(store) if policy.get('enabled') else {'status': 'DISABLED'}
        store.set('dns_filter_health', {**health, 'blocked_count':len(blocked), 'updated_at':time.time()})
        return {'ok': True, 'status': 'hot_added' if hot else 'unchanged', 'count': len(blocked)}
    store.set('dns_filter_restarted_at', time.time())
    old_added_text = old_added
    atomic(block_path, rules, gid); atomic(config_path, config, gid); atomic(added_path, '', gid)
    checked = runner(['/usr/sbin/dnsmasq', '--test', '--conf-file=' + str(config_path)], capture_output=True, text=True, timeout=20)
    if checked.returncode:
        if old_rules is not None:
            atomic(block_path, old_rules, gid)
        else:
            block_path.unlink(missing_ok=True)
        if old_config is not None:
            atomic(config_path, old_config, gid)
        else:
            config_path.unlink(missing_ok=True)
        raise RuntimeError('dnsmasq rejected generated configuration: ' + checked.stderr[:300])
    if policy.get('enabled'):
        try:
            restarted=_systemctl(runner,'restart')
            if restarted.returncode:raise RuntimeError('dnsmasq restart failed: '+restarted.stderr[:300])
            probe()
        except Exception as failure:
            if (isinstance(failure,UpstreamNotUsable) and old_config is not None
                    and _servers(old_config)==_servers(config)):
                # The upstream servers are unchanged, so this change is not why
                # the upstream gives nothing; keep the valid new configuration.
                raise
            # Restore both configuration files on *readiness* failure as well as start failure.
            if old_rules is not None and old_config is not None:
                atomic(block_path,old_rules,gid);atomic(config_path,old_config,gid)
                atomic(added_path,old_added_text or '',gid)
                recovered=_systemctl(runner,'restart')
                if recovered.returncode:raise RuntimeError('DNS activation and rollback both failed')
                probe()
            else:
                # First activation has no known-good daemon configuration to restore.
                runner(['/usr/bin/systemctl','stop',SERVICE],capture_output=True,text=True,timeout=30)
                for candidate in (block_path,config_path):
                    candidate.unlink(missing_ok=True)
                    Path(str(candidate)+'.sig').unlink(missing_ok=True)
            raise
    health = record_readiness(store) if policy.get('enabled') else {'status': 'DISABLED'}
    store.set('dns_filter_health', {**health, 'blocked_count': len(blocked), 'updated_at': time.time()})
    return {'ok': True, 'status': 'configured', 'count': len(blocked)}


REMOVAL_RESTART_SECONDS = 1800


def removals_wait(store, old_rules, new_rules, same_config, now):
    """True when the new block list only drops names and a restart was recent.

    Field 2026-11-04: dnsmasq restarted every minute (satsuma-core-dns in the
    audit log at each refresh), because list entries expire continually; each
    restart reloads 830 000 names and DNS answers nothing meanwhile. A newly
    blocked name still applies at once; dropped names wait up to 30 minutes.
    dnsmasq her dakika yeniden başlıyordu; yeni engellenen ad yine hemen
    uygulanır, listeden çıkan adlar en fazla 30 dakika bekler.
    """
    if old_rules is None or old_rules == new_rules or not same_config:
        return False
    old_lines, new_lines = set(old_rules.splitlines()), set(new_rules.splitlines())
    if not new_lines <= old_lines:
        return False
    return now - float(store.get('dns_filter_restarted_at', 0) or 0) < REMOVAL_RESTART_SECONDS


def hot_add_allowed(store, old_rules, new_rules, same_config, added_file_ready, now):
    """True when only names were added, the running config already reads added.hosts, and a restart was recent."""
    if old_rules is None or old_rules == new_rules or not same_config or not added_file_ready:
        return False
    if not set(new_rules.splitlines()) - set(old_rules.splitlines()):
        return False
    return now - float(store.get('dns_filter_restarted_at', 0) or 0) < REMOVAL_RESTART_SECONDS


def pin_upstream(store):
    """dnsmasq may only ask OpenDNS: the host forwards nothing else from its namespace.

    An upstream outside OPENDNS (an old setting) would make every query fail,
    so it is replaced and the earlier value is kept in ``previous_upstream``.
    dnsmasq yalnızca OpenDNS'e sorabilir; başka bir üst sunucu ayarı OpenDNS ile
    değiştirilir, eski değer ``previous_upstream`` alanında saklanır.
    """
    policy = store.get('dns_policy', {}) or {}
    upstream = policy.get('upstream')
    if not upstream or upstream in OPENDNS:
        return policy
    policy = {**policy, 'upstream': OPENDNS[0], 'upstream_source': 'pinned_opendns_namespace',
              'previous_upstream': upstream}
    store.set('dns_policy', policy)
    return policy


def refresh(store, runner=subprocess.run, directory=DIRECTORY):
    """Write, sign and (re)start the DNS filter under a lock.

    2.2.44 (owner's decision 2026-11-13): dnsmasq is back, in its own network
    namespace (satsuma.dns_netns). From 2.2.38 to 2.2.43 this stopped dnsmasq
    and removed its configuration.
    dnsmasq kendi ağ ad alanında geri döndü; 2.2.38-2.2.43 arası durduruluyordu.
    """
    import fcntl
    import stat
    directory.mkdir(parents=True,exist_ok=True,mode=0o750)
    info=directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
        raise PermissionError('Unsafe DNS configuration directory')
    fd=os.open(directory/'.refresh.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        lock=os.fstat(fd)
        if not stat.S_ISREG(lock.st_mode) or lock.st_uid!=0 or lock.st_mode&0o077 or lock.st_nlink!=1:
            raise PermissionError('Unsafe DNS lock')
        fcntl.flock(fd,fcntl.LOCK_EX)
        pin_upstream(store)
        try:return _refresh(store,runner,directory)
        except Exception as exc:
            import time
            store.set('dns_filter_health',{'ok':False,'status':'UPSTREAM_UNUSABLE' if isinstance(exc,UpstreamNotUsable) else 'FAILED',
                                           'error':str(exc)[:1000],'updated_at':time.time()})
            raise
    finally:os.close(fd)


def _probe_once():
    """Check useful A replies on both local transports; this is not system readiness."""
    from .dns_readiness import query
    from .dns_netns import DNS_ADDR
    for transport in ('udp', 'tcp'):
        query(DNS_ADDR, 53, transport=transport)


def record_readiness(store):
    """A successful local probe must never imply that redirected system DNS works."""
    import time
    from .dns_readiness import probe_system
    result = {'local_ready': True, 'system_ready': False, 'status': 'LOCAL_READY',
              'ok': False, 'updated_at': time.time(), 'query': 'example.com A',
              'upstream_cache_bypassed': False}
    if (store.get('satsuma_dns_state', {}) or {}).get('enabled'):
        try:
            result.update(probe_system())
            result.update(status='ACTIVE', ok=True)
        except (OSError, RuntimeError) as exc:
            result.update(status='FAILED', error=str(exc)[:1000])
            store.set('dns_filter_health', result)
            raise
    store.set('dns_filter_health', result)
    return result


def probe(timeout=None):
    """Wait for actual DNS readiness while dnsmasq parses the Ultimate list."""
    import time
    from .dns_readiness import DaemonAnswered
    if timeout is None:
        try:
            timeout = scaled_timeout((DIRECTORY / 'blocked.conf').stat().st_size)
        except OSError:
            timeout = scaled_timeout(0)
    deadline = time.monotonic() + timeout
    while True:
        try:
            _probe_once()
            return
        except (OSError, RuntimeError) as exc:
            if time.monotonic() >= deadline:
                kind = UpstreamNotUsable if isinstance(exc, DaemonAnswered) else RuntimeError
                raise kind('dnsmasq DNS readiness failed; no new redirect applied: ' + str(exc)) from exc
            time.sleep(.2)


if __name__ == '__main__':
    from .store import Store
    store = Store()
    try:
        refresh(store)
    finally:
        store.close()
