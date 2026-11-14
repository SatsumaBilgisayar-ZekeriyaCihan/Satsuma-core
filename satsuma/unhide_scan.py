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
import socket
import subprocess

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


def confirm_pid(pid, listed=_proc_pids, alive=_alive):
    if pid <= 1:
        return 'invalid'
    if not alive(pid):
        return 'transient'
    if pid in listed():
        return 'visible'
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
