"""Satsuma's own events, kept apart from everything else.

User request 2026-11-04: the product must no longer show its own commands
(systemctl show for service health, ip for the network identity, runuser
for remote containment, dig for the DNS sentinel) as events or findings;
its own events must be separated from the others. The polling frequency
does not change; only the classification does.

An event is Satsuma's own only when both hold:

- the process, or its parent when the process has already ended, runs in
  a Satsuma system unit (system.slice/satsuma-*.service); a user unit with
  a similar name does not count;
- its executable is a root-owned file with no writable parent directory
  (trusted_path). A payload under /tmp, /home or /dev/shm is never own,
  even when started from a Satsuma unit;
- it is not a shell or a download/network tool (sh, bash, curl, nc, ...),
  and an interpreter counts only when it runs Satsuma's own code under
  /opt/satsuma-core. A command run through a shell from a Satsuma unit is
  therefore always evaluated by the rules.

Own events still follow the process chain in the flow (evidence stays
complete) but are not given to the rules and are counted separately.

Satsuma'nın kendi olayları, diğer olaylardan ayrı tutulur.
Kullanıcı isteği 2026-11-04: ürün kendi komutlarını (servis sağlığı için
systemctl show, ağ kimliği için ip, uzak sınırlama için runuser, DNS
nöbetçisi için dig) artık olay ya da bulgu olarak göstermemeli; kendi olayı
diğer olaylardan ayrılmalı. Sorgu sıklığı değişmez, yalnızca sınıflama
değişir. Bir olay yalnızca iki koşul birlikte sağlanınca Satsuma'nındır:
süreç (bitmişse üst süreci) bir Satsuma sistem biriminde çalışır
(system.slice/satsuma-*.service; benzer adlı kullanıcı birimi sayılmaz) ve
çalıştırılabilir dosyası root sahipli, üst dizinleri yazılamaz bir dosyadır.
/tmp, /home ya da /dev/shm altındaki bir yük, Satsuma biriminden başlatılsa
bile asla kendi olayı sayılmaz. Kabuk ve indirme/ağ araçları (sh, bash, curl,
nc...) hiçbir zaman kendi olayı sayılmaz; yorumlayıcı yalnızca
/opt/satsuma-core altındaki Satsuma kodunu çalıştırıyorsa sayılır. Kendi olaylar akışta süreç zincirini
izlemeye devam eder (kanıt eksiksiz kalır), ama kurallara verilmez ve ayrı
sayılır.
"""
from pathlib import Path
import subprocess
import time

from .trusted_process import system_service, trusted_path

ORIGIN = 'satsuma'
SYSTEMCTL = '/usr/bin/systemctl'
PACKAGED = '/usr/lib/systemd/system/'
SYSTEMD_EVERY = 2.0


def _unix(value):
    value = str(value or '').strip()
    if value.startswith('@'):
        try:
            return float(value[1:])
        except ValueError:
            return None
    return None


def _stamp(value):
    if isinstance(value, (int, float)):
        return float(value)
    try:
        from datetime import datetime
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
    except (TypeError, ValueError):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
_CACHE_SECONDS = 5.0
_TRUST_SECONDS = 60.0
NEVER_OWN = frozenset({'sh', 'bash', 'dash', 'zsh', 'ksh', 'fish', 'busybox', 'curl', 'wget', 'nc', 'ncat',
                       'socat', 'telnet', 'ssh', 'scp', 'sftp', 'perl', 'ruby', 'php', 'node', 'lua'})
INTERPRETERS = ('python', 'python3')
OWN_CODE = '/opt/satsuma-core/'


def _field(raw, key):
    value = raw.get(key)
    if value in (None, ''):
        ext = ((raw.get('metadata') or {}).get('extensions') or {}) if isinstance(raw.get('metadata'), dict) else {}
        value = ext.get('host.' + key)
    return value


class SelfClassifier:
    def __init__(self, proc_root='/proc', clock=time.monotonic, trusted=trusted_path, runner=subprocess.run,
                 wall=time.time):
        self.proc_root, self.clock, self.trusted, self.runner, self.wall = proc_root, clock, trusted, runner, wall
        self._units, self._paths = {}, {}
        self.own = self.other = 0
        # 2.2.57: what systemd itself says about Satsuma units (field 2026-11-19: dns-refresh,
        # a one-minute python3 -m satsuma.dnsmasq_control run, ended before its audit
        # events were judged; its proctitle read "systemd-executor ...").
        self._systemd = {}          # unit -> {'packaged': bool, ...}
        self._mains = {}            # pid -> (unit, start, end) of runs systemd started
        self._systemd_at = -SYSTEMD_EVERY

    def _systemd_units(self):
        """Satsuma units as systemd knows them, at most every SYSTEMD_EVERY seconds."""
        now = self.clock()
        if now - self._systemd_at < SYSTEMD_EVERY:
            return self._systemd
        self._systemd_at = now
        try:
            done = self.runner([SYSTEMCTL, 'show', '--timestamp=unix', '--type=service', '--all',
                                '--property=Id,ExecMainPID,ExecMainStartTimestamp,ExecMainExitTimestamp,'
                                'FragmentPath,DropInPaths', 'satsuma*.service'],
                               capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return self._systemd
        if done.returncode:
            return self._systemd
        units = {}
        for block in done.stdout.split('\n\n'):
            row = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
            unit = row.get('Id', '')
            if not (unit.startswith('satsuma') and unit.endswith('.service')):
                continue
            drop_ins = row.get('DropInPaths', '').split()
            # Only the packaged unit (read-only /usr on Atomic); an /etc copy or drop-in can change ExecStart.
            packaged = (row.get('FragmentPath', '').startswith(PACKAGED)
                        and all(path.startswith(PACKAGED) for path in drop_ins))
            units[unit] = {'packaged': packaged}
            try:
                pid = int(row.get('ExecMainPID') or 0)
            except ValueError:
                pid = 0
            if pid > 1 and packaged:
                self._mains[pid] = (unit, _unix(row.get('ExecMainStartTimestamp')),
                                    _unix(row.get('ExecMainExitTimestamp')))
        if len(self._mains) > 4096:
            self._mains = dict(list(self._mains.items())[-2048:])
        self._systemd = units
        return units

    def _ended_main(self, raw):
        """The packaged Satsuma unit whose main process this was, when it has already ended."""
        try:
            pid = int(_field(raw, 'pid'))
        except (TypeError, ValueError):
            return ''
        if str(_field(raw, 'ppid') or '') not in ('1', ''):
            return ''
        self._systemd_units()
        hit = self._mains.get(pid)
        if not hit:
            return ''
        unit, start, end = hit
        stamp = _stamp(raw.get('timestamp') or (raw.get('raw') or {}).get('timestamp'))
        # The event must fall inside that run: a reused PID is not trusted.
        if stamp is None or start is None or stamp < start - 1 or (end and stamp > end + 1):
            return ''
        return unit

    def _unit(self, pid):
        if pid in (None, ''):
            return ''
        key, now = str(pid), self.clock()
        hit = self._units.get(key)
        if hit and now - hit[0] < _CACHE_SECONDS:
            return hit[1]
        try:
            unit = system_service(Path(self.proc_root, str(int(pid)), 'cgroup').read_text())
        except (OSError, ValueError, TypeError):
            unit = ''
        if len(self._units) > 4096:
            self._units.clear()
        self._units[key] = (now, unit)
        return unit

    def _trusted(self, exe):
        now = self.clock()
        hit = self._paths.get(exe)
        if hit and now - hit[0] < _TRUST_SECONDS:
            return hit[1]
        verdict = bool(self.trusted(exe))
        if len(self._paths) > 4096:
            self._paths.clear()
        self._paths[exe] = (now, verdict)
        return verdict

    def unit_of(self, raw):
        named = system_service(_field(raw, 'cgroup') or '') or str(_field(raw, 'systemd_unit') or '')
        if named.startswith('satsuma') and named.endswith('.service') and '/' not in named:
            return named
        return self._unit(_field(raw, 'pid')) or self._unit(_field(raw, 'ppid'))

    def is_own(self, raw):
        if not isinstance(raw, dict):
            return False
        unit = self.unit_of(raw)
        if not unit:
            unit = self._ended_main(raw)
        exe = str(_field(raw, 'exe') or '')
        name = exe.rsplit('/', 1)[-1].removesuffix(' (deleted)')
        interpreter = name.startswith(INTERPRETERS)
        # An interpreter runs Satsuma's code when its command says so, or when the unit
        # is the packaged one (its ExecStart is ours; e.g. python3 -m satsuma.dnsmasq_control).
        allowed = name not in NEVER_OWN and (not interpreter or OWN_CODE in str(_field(raw, 'cmd') or '')
                                              or (unit.startswith('satsuma')
                                                  and self._systemd_units().get(unit, {}).get('packaged')))
        own = bool(unit.startswith('satsuma') and exe.startswith('/') and allowed and self._trusted(exe))
        if own:
            self.own += 1
        else:
            self.other += 1
        return own

    def health(self):
        return {'own_events': self.own, 'other_events': self.other}
