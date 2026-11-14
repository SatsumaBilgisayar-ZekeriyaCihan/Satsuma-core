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
import time

from .trusted_process import system_service, trusted_path

ORIGIN = 'satsuma'
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
    def __init__(self, proc_root='/proc', clock=time.monotonic, trusted=trusted_path):
        self.proc_root, self.clock, self.trusted = proc_root, clock, trusted
        self._units, self._paths = {}, {}
        self.own = self.other = 0

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
        exe = str(_field(raw, 'exe') or '')
        name = exe.rsplit('/', 1)[-1].removesuffix(' (deleted)')
        allowed = name not in NEVER_OWN and (not name.startswith(INTERPRETERS)
                                              or OWN_CODE in str(_field(raw, 'cmd') or ''))
        own = bool(unit.startswith('satsuma') and exe.startswith('/') and allowed and self._trusted(exe))
        if own:
            self.own += 1
        else:
            self.other += 1
        return own

    def health(self):
        return {'own_events': self.own, 'other_events': self.other}
