"""Hidden process and port detection with unhide, each finding verified again.

User report 2026-11-04: unhide was never a dependency and never ran (the
earlier integration on the rootkit-deneme branch was deleted). unhide
compares several kernel views (getpriority, kill, /proc, ss); a rootkit
that hides a process or a port shows up as a difference. Every reported
object is checked again before it becomes a finding, because a process
that starts or ends during the scan also looks like a difference:

- hidden PID: alive (kill 0), absent from /proc, and still alive;
- fake PID: listed in /proc but not alive;
- hidden port: in use (bind fails) and absent from /proc/net.

The commands run with a clean PATH and locale; unhide's own output is
never executed or trusted beyond parsing numbers and quoted paths.

2.2.36: the Fedora package unhide-20240510 installs /usr/bin/unhide, unhide-tcp and
unhide_rb; unhide-linux no longer exists. The scan looks for /usr/sbin/unhide first
and the older unhide-linux second, so it runs with either package.

unhide ile gizli süreç ve port tespiti; her bulgu yeniden doğrulanır.
Kullanıcı bildirimi 2026-11-04: unhide hiç bağımlılık değildi ve hiç
çalışmıyordu (rootkit-deneme dalındaki eski entegrasyon silinmişti).
unhide çekirdeğin birkaç görünümünü karşılaştırır; süreci ya da portu
gizleyen rootkit fark olarak görünür. Tarama sırasında başlayan ya da
biten süreç de fark gibi göründüğü için bildirilen her nesne bulgu olmadan
önce yeniden denetlenir. Komutlar temiz PATH ve yerel ayarla çalışır.
2.2.36: Fedora'daki unhide-20240510 paketi /usr/bin/unhide, unhide-tcp ve unhide_rb
kurar; unhide-linux artık yoktur. Tarama önce /usr/sbin/unhide'a, sonra eski
unhide-linux'a bakar; iki paketle de çalışır.
"""
import errno
import os
import re
import select
import signal
import socket
import subprocess
import time

# Newer packages ship the program as "unhide"; older ones as "unhide-linux".
# Yeni paketler programı "unhide", eskiler "unhide-linux" adıyla verir.
UNHIDE_LINUX_NAMES = ('/usr/sbin/unhide', '/usr/sbin/unhide-linux')
UNHIDE_TCP = '/usr/sbin/unhide-tcp'
ENV = {'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'}
_QUOTED = re.compile(r'"(.*)"')


def linux_binary(exists=os.path.exists):
    """The installed unhide program: the new name first, the old one second."""
    return next((path for path in UNHIDE_LINUX_NAMES if exists(path)), UNHIDE_LINUX_NAMES[0])


def installed(which):
    """True when either name of the program is on the PATH (``which`` is shutil.which-like)."""
    return bool(which('unhide') or which('unhide-linux'))


def parse_linux(text):
    found, current = [], None
    for line in text.splitlines():
        hidden = re.search(r'Found HIDDEN PID:\s*(\d+)', line)
        fake = re.search(r'Found FAKE PID:\s*(\d+)\s+Command\s*=\s*(\S+)', line)
        if hidden:
            current = {'kind': 'hidden_pid', 'pid': int(hidden.group(1)), 'cmdline': '', 'executable': ''}
            found.append(current)
        elif fake:
            current = None
            found.append({'kind': 'fake_pid', 'pid': int(fake.group(1)), 'command': fake.group(2)})
        elif current is not None and line.strip().startswith(('Cmdline:', 'Executable:')):
            key = 'cmdline' if line.strip().startswith('Cmdline:') else 'executable'
            match = _QUOTED.search(line)
            current[key] = match.group(1)[:500] if match else line.split(':', 1)[1].strip()[:500]
    return found


def parse_tcp(text):
    found, proto = [], 'tcp'
    for line in text.splitlines():
        if 'Starting UDP' in line:
            proto = 'udp'
        elif 'Starting TCP' in line:
            proto = 'tcp'
        match = re.search(r'Found Hidden port that not appears in (\w+):\s*(\d+)', line)
        if match and 1 <= int(match.group(2)) <= 65535:
            found.append({'kind': 'hidden_port', 'proto': proto, 'port': int(match.group(2)), 'missing_from': match.group(1)})
    return found


def _proc_pids():
    return {int(n) for n in os.listdir('/proc') if n.isdigit()}


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _status(pid):
    """Tgid, PPid, Uid and Name from /proc/PID/status; None when it cannot be read.

    A thread is not listed in /proc but /proc/TID/status is readable and names
    its thread group (Tgid).
    """
    try:
        with open(f'/proc/{int(pid)}/status') as handle:
            fields = dict(line.split(':', 1) for line in handle if ':' in line)
    except (OSError, ValueError):
        return None
    try:
        return {'name': fields.get('Name', '').strip()[:64], 'tgid': int(fields['Tgid']), 'ppid': int(fields['PPid']),
                'uid': int(fields.get('Uid', '-1').split()[0])}
    except (KeyError, ValueError, IndexError):
        return None


def confirm_pid(pid, listed=_proc_pids, alive=_alive, status=_status):
    """hidden, visible, thread, transient or invalid.

    2.2.48 field report: "unhide finds many hidden processes". A thread answers
    kill(TID, 0) but is not listed in /proc, so every thread of every program
    looked hidden. A TID whose thread group is listed is a thread, not hidden.
    2.2.48: iş parçacıkları gizli süreç sanılıyordu; Tgid'i görünen TID gizli değildir.
    """
    if pid <= 1:
        return 'invalid'
    if not alive(pid):
        return 'transient'
    names = listed()
    if pid in names:
        return 'visible'
    info = status(pid)
    if info and info.get('tgid') not in (None, pid) and info['tgid'] in names:
        return 'thread'
    if not alive(pid):
        return 'transient'
    return 'hidden'


def confirm_fake(pid, listed=_proc_pids, alive=_alive):
    if pid not in listed():
        return 'transient'
    return 'real' if alive(pid) else 'fake'


def _in_use(proto, port):
    kind = socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as probe:
        try:
            probe.bind(('0.0.0.0', port))
            return False
        except OSError as exc:
            return exc.errno in (errno.EADDRINUSE, errno.EACCES)


def _listed(proto):
    ports = set()
    for name in (f'/proc/net/{proto}', f'/proc/net/{proto}6'):
        try:
            with open(name) as handle:
                next(handle, None)
                for line in handle:
                    fields = line.split()
                    if len(fields) > 3 and (proto == 'udp' or fields[3] == '0A'):
                        ports.add(int(fields[1].rsplit(':', 1)[1], 16))
        except OSError:
            continue
    return ports


def confirm_port(proto, port, in_use=_in_use, listed=_listed):
    if not in_use(proto, port):
        return 'transient'
    return 'visible' if port in listed(proto) else 'hidden'


def run(runner=subprocess.run, confirm_pid=confirm_pid, confirm_port=confirm_port, confirm_fake=confirm_fake):
    """Both unhide scans; only objects that verify again are findings."""
    findings, discarded, errors = [], [], []
    linux = linux_binary()
    for command, parser in (([linux, '-m', 'quick', 'reverse'], parse_linux), ([UNHIDE_TCP], parse_tcp)):
        try:
            result = runner(command, capture_output=True, text=True, timeout=900, env=dict(ENV))
            items = parser(result.stdout or '')
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(command[0] + ': ' + str(exc)[:200])
            continue
        for item in items:
            if item['kind'] == 'hidden_pid':
                verdict = confirm_pid(item['pid'])
                keep = verdict == 'hidden'
            elif item['kind'] == 'fake_pid':
                verdict = confirm_fake(item['pid'])
                keep = verdict == 'fake'
            else:
                verdict = confirm_port(item['proto'], item['port'])
                keep = verdict == 'hidden'
            (findings if keep else discarded).append({**item, 'verdict': verdict})
    return {'findings': findings, 'discarded': discarded, 'errors': errors,
            'available': os.path.exists(linux) and os.path.exists(UNHIDE_TCP)}


# 2.2.48: ending a hidden process the user chose (Antivirüs → Taramalar).
# Only a PID that verifies as hidden at that moment is signalled, through a
# pidfd so a reused PID can never be hit; kernel threads and Satsuma refused.
# Kullanıcının seçtiği gizli süreci sonlandırma; yalnızca o anda gizli
# doğrulanan süreç, pidfd üzerinden; çekirdek iş parçacıkları reddedilir.
def _identity(pid):
    def read(name, limit=500):
        try:
            with open(f'/proc/{pid}/{name}', 'rb') as handle:
                return handle.read(limit).replace(b'\0', b' ').decode('utf-8', 'replace').strip()
        except OSError:
            return ''
    try:
        exe = os.readlink(f'/proc/{pid}/exe')
    except OSError:
        exe = ''
    return {'exe': exe[:500], 'cmdline': read('cmdline'), 'comm': read('comm', 64)}


def _gone(fd, seconds):
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    return bool(poller.poll(int(seconds * 1000)))


def terminate(pid, *, confirm=None, status=_status, own_pid=os.getpid, pidfd_open=None, send=None, gone=_gone,
              wait=3.0, identity=_identity):
    """End one hidden process: SIGTERM, then SIGKILL; the result says what happened."""
    if type(pid) is not int or pid <= 2:
        raise ValueError('Geçerli bir süreç numarası gerekli')
    confirm = confirm or confirm_pid
    pidfd_open = pidfd_open or os.pidfd_open
    send = send or signal.pidfd_send_signal
    verdict = confirm(pid)
    base = {'pid': pid, 'verdict': verdict}
    if verdict != 'hidden':
        return {**base, 'status': 'not_hidden'}
    info = status(pid) or {}
    if pid == own_pid() or info.get('ppid') == 2 or info.get('tgid') == 2:
        return {**base, 'status': 'refused', 'reason': 'kernel_or_satsuma'}
    try:
        fd = pidfd_open(pid)
    except ProcessLookupError:
        return {**base, 'status': 'not_hidden', 'verdict': 'transient'}
    except OSError as exc:
        # EINVAL: a thread, not a process (no pidfd for a non-leader TID).
        return {**base, 'status': 'refused', 'reason': 'no_pidfd:' + (errno.errorcode.get(exc.errno) or str(exc.errno))}
    try:
        # The pidfd pins this exact process; check again that it is the hidden one.
        again = confirm(pid)
        if again != 'hidden':
            return {**base, 'status': 'not_hidden', 'verdict': again}
        evidence = {**identity(pid), **{k: info.get(k) for k in ('name', 'ppid', 'uid')}}
        started = time.time()
        send(fd, signal.SIGTERM)
        if gone(fd, wait):
            return {**base, 'status': 'terminated', 'signal': 'SIGTERM', 'evidence': evidence,
                    'seconds': round(time.time() - started, 2)}
        send(fd, signal.SIGKILL)
        ended = gone(fd, 2.0)
        return {**base, 'status': 'killed' if ended else 'survived', 'signal': 'SIGKILL', 'evidence': evidence,
                'seconds': round(time.time() - started, 2)}
    finally:
        os.close(fd)


VERDICT_TEXT = {
    'thread': 'Görünen bir programın iş parçacığı; gizli süreç değil.',
    'transient': 'Süreç artık yok.',
    'visible': 'Süreç artık normal biçimde görünüyor.',
    'invalid': 'Geçersiz süreç numarası.',
}


def _review_findings(host):
    import json
    for finding_id, body in host.db.execute(
            "SELECT finding_id, body FROM findings WHERE finding_id LIKE 'unhide:hidden_pid:%'").fetchall():
        try:
            item = json.loads(body)
        except (TypeError, ValueError):
            continue
        if item.get('status') == 'REVIEW':
            yield finding_id, item


def _close(host, finding_id, item, status, resolution, **extra):
    import json
    item.update(status=status, resolution=resolution, resolution_text=VERDICT_TEXT.get(resolution, resolution),
                resolved_at=time.time(), **extra)
    host.db.execute('UPDATE findings SET body=?, last_seen=? WHERE finding_id=?',
                    (json.dumps(item, ensure_ascii=False), time.time(), finding_id))


def recheck(host, confirm=None, status=_status):
    """Verify every open hidden-process finding again; close the ones that are not hidden.

    2.2.48: findings written before threads were recognised are closed with
    the reason (for a thread, the program it belongs to).
    """
    confirm = confirm or confirm_pid
    counts, still = {}, []
    for finding_id, item in list(_review_findings(host)):
        pid = (item.get('item') or {}).get('pid')
        if type(pid) is not int:
            continue
        verdict = confirm(pid)
        if verdict == 'hidden':
            still.append(pid)
            continue
        extra = {}
        if verdict == 'thread':
            info = status(pid) or {}
            owner = status(info.get('tgid')) if info.get('tgid') else None
            extra = {'thread_of': info.get('tgid'), 'thread_of_name': (owner or {}).get('name', '')}
        _close(host, finding_id, item, 'DISMISSED', verdict, **extra)
        counts[verdict] = counts.get(verdict, 0) + 1
    host.db.commit()
    return {'checked': len(still) + sum(counts.values()), 'still_hidden': still, 'dismissed': counts}


def end(host, pid, record, **kwargs):
    """Terminate a process the last unhide scan reported and that is still hidden; never any other PID."""
    finding_id = f'unhide:hidden_pid:{pid}'
    item = dict(_review_findings(host)).get(finding_id)
    if item is None:
        raise ValueError('Bu süreç son unhide taramasının açık bulguları arasında değil; yeniden tarayın')
    result = terminate(pid, **kwargs)
    if result['status'] in ('terminated', 'killed'):
        _close(host, finding_id, item, 'RESOLVED', 'terminated', termination=result)
    elif result['status'] == 'not_hidden':
        _close(host, finding_id, item, 'DISMISSED', result['verdict'])
    host.db.commit()
    record({'action': 'process.terminate', 'source': 'unhide', 'pid': pid, 'status': result['status'],
            'exit_verified': result['status'] in ('terminated', 'killed'), 'finding_id': finding_id,
            'reason': 'Gizli süreç; kullanıcı sonlandırdı', **{k: v for k, v in result.items() if k not in ('pid', 'status')}})
    return result
