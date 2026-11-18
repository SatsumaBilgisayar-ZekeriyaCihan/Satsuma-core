"""Read the kernel settings that protect this machine and write back what was changed.

Only a fixed table is ever touched, and only towards the hardened value; no
caller, finding, rule or file chooses a key or a value. The table:

* network settings against interception (satsuma.kernel_net: rp_filter,
  route_localnet, source routing, ICMP redirects, SYN cookies);
* memory disclosure and cross-process access (satsuma.memory_access:
  ptrace_scope exactly 2, kptr_restrict, dmesg_restrict, suid_dumpable,
  core_pattern). Since 2.2.37 ptrace_scope 3 is not "stronger": it blinds the
  RAM scanner (owner's decision 2026-11-10), so it is an alarm, and the sysctl
  file or boot argument that sets it is undone (satsuma.ptrace_guard);
* IPv6 off (your decision 2026-10-26);
* the strictest profile (satsuma.kernel_profile, your decision 2026-11-10):
  BPF, perf, kexec, SysRq, file protections, user namespaces off; every five
  minutes the late module lock and the boot command line of every installed
  kernel are checked and put back, and the saved pattern is rewritten if it
  was changed;
* units that must never run (ModemManager, tuned, tuned-ppd, avahi: masked
  and stopped, your decisions 2026-10-27 and the avahi that kept coming back);
* units that must keep running while they are enabled (the Suricata IPS and
  USBGuard): started again if something stopped them. Nothing is restarted
  while rpm or dnf is running, so an upgrade is never fought, and a unit the
  operator disabled is left alone.
* /dev and /dev/shm stay nosuid/noexec: a lost option is restored by running
  the boot unit satsuma-memory-hardening again, because a sandboxed service
  would only remount its own copy of the mount.

Settings are read every second; units and mounts every ten. Every change is
recorded (journal, events.jsonl and state.json) whether or not it could be
undone. There is no pause switch: a security guard that can be paused by a
file is a guard an attacker can pause.

Makineyi koruyan çekirdek ayarlarını okur ve değiştirilenleri geri yazar.

Yalnızca sabit bir tabloya dokunulur ve yalnızca sertleştirilmiş yöne; hiçbir
çağıran, bulgu, kural ya da dosya anahtarı veya değeri seçemez. Tablo: araya
girme saldırılarına karşı ağ ayarları (kernel_net); bellek ifşası ve süreçler
arası erişim (memory_access); IPv6 kapalı (2026-10-26 kararınız); en sıkı
profil (kernel_profile, 2026-11-10 kararınız: beş dakikada bir geç modül
kilidi ve kurulu her çekirdeğin açılış komut satırı denetlenip geri konur,
kayıtlı desen değiştirilmişse yeniden yazılır); asla
çalışmaması gereken birimler (ModemManager, tuned, tuned-ppd, avahi: maskelenir
ve durdurulur); etkinken çalışır kalması gereken birimler (Suricata IPS ve
USBGuard): biri durdurduysa yeniden başlatılır. rpm ya da dnf çalışırken hiçbir
şey yeniden başlatılmaz, böylece yükseltme ile savaşılmaz; operatörün kapattığı
birime dokunulmaz. /dev ve /dev/shm nosuid/noexec kalır: kaybolan seçenek,
satsuma-memory-hardening açılış birimi yeniden çalıştırılarak geri konur;
çünkü sandbox içindeki bir servis yalnızca kendi bağlama kopyasını yeniden
bağlardı.

Ayarlar her saniye, birimler ve bağlamalar on saniyede bir okunur. Her
değişiklik, geri alınabilsin ya da alınamasın, kaydedilir (günlük, events.jsonl
ve state.json). Duraklatma anahtarı yoktur: bir dosyayla duraklatılabilen
güvenlik bekçisini saldırgan da duraklatabilir.
"""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from . import account_guard, kernel_net, kernel_profile, memory_access, memory_mounts, ptrace_guard

PROC_SYS = Path('/proc/sys')
STATE_DIR = Path('/var/lib/satsuma-core/kernel-guard')
STATE_FILE = STATE_DIR / 'state.json'
EVENT_FILE = STATE_DIR / 'events.jsonl'

SETTINGS_EVERY = 1.0
UNITS_EVERY = 10.0
THROTTLE = 10.0          # the same finding is written at most this often
RESTART_EVERY = 30.0     # a unit or the hardening unit is started again at most this often
MAX_EVENTS = 20

# IPv6 off on this machine (2026-10-26).
IPV6_OFF = {'net/ipv6/conf/all/disable_ipv6': '1', 'net/ipv6/conf/default/disable_ipv6': '1',
            'net/ipv6/conf/lo/disable_ipv6': '1'}
# Masked and stopped. avahi: mDNS/LLMNR is an interception surface and kept coming back.
NEVER_RUN = ('ModemManager.service', 'tuned.service', 'tuned-ppd.service',
             'avahi-daemon.service', 'avahi-daemon.socket')
# Started again if they were stopped while still enabled. 2.2.37: the RAM scanner's
# ClamAV and satsuma-core (it runs the RAM worker) too: a clean stop is not a crash,
# so systemd alone would leave them stopped (owner's report 2026-11-12).
# Çekirdek bekçisi çalışan ana Satsuma servisini denetler; RAM clamd kaldırıldı.
REQUIRED_RUNNING = ('satsuma-suricata-ips.service', 'usbguard.service',
                    'satsuma-core.service')
# 2.2.38: rpm-ostree (CLI and daemon run the same program) installs packages on
# Fedora Atomic. rpm-ostree de paket yöneticisidir.
PACKAGE_MANAGERS = frozenset(('rpm', 'dnf', 'dnf5', 'microdnf', 'packagekitd', 'yum', 'rpm-ostree'))
HARDENING_UNIT = 'satsuma-memory-hardening.service'
ACTIVE = frozenset(('active', 'activating', 'reloading'))
_KEY = re.compile(r'(?:net/ipv[46]/(?:conf/[A-Za-z0-9_.@-]{1,15}/)?[a-z0-9_]+|kernel/[a-z_/]+|fs/[a-z_]+'
                  r'|net/core/[a-z_]+|dev/tty/[a-z_]+|vm/[a-z_]+|user/[a-z_]+)')
BOOT_EVERY = 300.0       # boot entries (new kernels included) and the late module lock
# ptrace_scope and every source that could set it (owner's decision 2026-11-13: once a minute,
# the first time as soon as the guard starts). The value itself is still read every second.
# ptrace_scope ve onu değiştirebilecek her kaynak dakikada bir; değerin kendisi yine saniyede bir okunur.
PTRACE_EVERY = 60.0
PROFILE_UNIT = 'satsuma-kernel-profile.service'


def _read(path):
    try:
        with open(path) as stream:
            return stream.read().strip()
    except OSError:
        return None


def table(root=PROC_SYS, listdir=os.listdir):
    """Every watched setting on this machine right now: key -> required value."""
    wanted = dict(kernel_net.expected(str(root), listdir))
    wanted.update(memory_access.POLICY)
    wanted.update(IPV6_OFF)
    # The strictest profile (user decision 2026-11-10). En sıkı profil.
    wanted.update(kernel_profile.STRICT)
    return wanted


def _acceptable(key, actual, required):
    """ptrace_scope must be exactly 2: 3 blinds the RAM scanner (2.2.37).

    ptrace_scope tam olarak 2 olmalı: 3 RAM tarayıcısını kör eder (2.2.37).
    """
    if key == ptrace_guard.KEY:
        return actual == ptrace_guard.REQUIRED
    if key in kernel_profile.AT_LEAST:
        return kernel_profile.acceptable(key, actual, required)
    return actual == required


def read_settings(root=PROC_SYS, listdir=os.listdir, read=_read):
    """The kernel reading: key -> {value, required, ok}; unreadable keys are listed with value None."""
    rows = {}
    for key, required in sorted(table(root, listdir).items()):
        actual = read(os.path.join(str(root), key))
        rows[key] = {'value': actual, 'required': required,
                     'ok': actual is not None and _acceptable(key, actual, required)}
    return rows


def drift(root=PROC_SYS, listdir=os.listdir, read=_read):
    """Readable settings whose value is weaker than required."""
    return [{'key': key, 'expected': row['required'], 'actual': row['value']}
            for key, row in read_settings(root, listdir, read).items()
            if row['value'] is not None and not row['ok']]


def restore(items, root=PROC_SYS, listdir=os.listdir):
    """Write drifted keys back. Only keys of the fixed table, only the required value."""
    allowed = table(root, listdir)
    restored, failed = [], []
    for item in items:
        key = item['key']
        if key not in allowed or not _KEY.fullmatch(key) or '..' in key or item['expected'] != allowed[key]:
            failed.append({**item, 'error': 'not_in_fixed_table'})
            continue
        try:
            fd = os.open(os.path.join(str(root), key), os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
            try:
                os.write(fd, (allowed[key] + '\n').encode())
            finally:
                os.close(fd)
            restored.append(item)
        except OSError as exc:
            failed.append({**item, 'error': exc.strerror or str(exc)})
    return {'restored': restored, 'failed': failed}


def _uptime(path='/proc/uptime'):
    try:
        return float(Path(path).read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return 0.0


def unit_states(units, runner=subprocess.run):
    """unit -> {active, file, load}, read with one systemctl call."""
    result = runner(['/usr/bin/systemctl', 'show', '--no-pager', '--property=Id,LoadState,ActiveState,UnitFileState',
                     '--', *units], capture_output=True, text=True, timeout=20)
    states, current = {}, {}
    for line in (result.stdout or '').splitlines() + ['']:
        if not line.strip():
            if current.get('Id'):
                states[current['Id']] = {'load': current.get('LoadState'), 'active': current.get('ActiveState'),
                                         'file': current.get('UnitFileState')}
            current = {}
            continue
        name, _, value = line.partition('=')
        current[name] = value
    return states


def unit_drift(states, package_manager_running=False):
    """What must be undone: never-run units that run or are not masked; required units that stopped."""
    found = []
    for unit in NEVER_RUN:
        state = states.get(unit)
        if not state or state['load'] == 'not-found':
            continue
        if state['active'] in ACTIVE or state['file'] not in ('masked', 'masked-runtime'):
            found.append({'unit': unit, 'want': 'masked_and_stopped', 'active': state['active'],
                          'file': state['file']})
    if not package_manager_running:
        for unit in REQUIRED_RUNNING:
            state = states.get(unit)
            if (state and state['load'] == 'loaded' and state['file'] in ('enabled', 'enabled-runtime', 'static')
                    and state['active'] not in ACTIVE):
                found.append({'unit': unit, 'want': 'running', 'active': state['active'], 'file': state['file']})
    return found


def package_manager_running(proc='/proc'):
    try:
        names = [n for n in os.listdir(proc) if n.isdigit()]
    except OSError:
        return False
    for name in names:
        try:
            if os.path.basename(os.readlink(os.path.join(proc, name, 'exe'))).removesuffix(' (deleted)') in PACKAGE_MANAGERS:
                return True
        except OSError:
            continue
    return False


class Guard:
    def __init__(self, root=PROC_SYS, runner=subprocess.run, clock=time.monotonic, wall=time.time,
                 state_dir=STATE_DIR, mount_reader=memory_mounts.mount_table, pm_running=package_manager_running,
                 listdir=os.listdir, can_write=None, echo=print, uptime=None, modules_path='/proc/modules',
                 ptrace_paths=None, ptrace_evidence=None, account_paths=None):
        self.root, self.runner, self.clock, self.wall = root, runner, clock, wall
        self.state_dir, self.mount_reader, self.pm_running = Path(state_dir), mount_reader, pm_running
        self.listdir, self.echo = listdir, echo
        self.can_write = (os.geteuid() == 0) if can_write is None else can_write
        self.last_units = -UNITS_EVERY
        self.last_boot = -BOOT_EVERY
        self.uptime = uptime or _uptime
        self.modules_path = modules_path
        self.boot = {}
        self.ptrace = {'status': 'NOT_CHECKED'}
        # Where sysctl files and the boot line are read (tests use a temporary tree).
        self.ptrace_paths = dict(ptrace_paths or {})
        self.ptrace_evidence = ptrace_evidence or ptrace_guard.EVIDENCE
        self.last_ptrace = -RESTART_EVERY
        # 2.2.38: system accounts must hold no usable password (satsuma.account_guard).
        self.account_paths = dict(account_paths or {})
        self.accounts = {'status': 'NOT_CHECKED'}
        self.last_ptrace_sweep = -PTRACE_EVERY
        self.recent = {}            # (kind, key) -> last time written
        self.attempts = {}          # unit or 'mounts' -> last time started again
        self.events = []
        self.counts = {'settings_changed': 0, 'settings_restored': 0, 'units_changed': 0, 'units_restored': 0,
                       'mounts_changed': 0, 'mounts_restored': 0, 'restore_failed': 0,
                       'boot_changed': 0, 'boot_restored': 0}
        try:
            saved = kernel_profile.save_pattern(self.state_dir / 'profile.json')
        except OSError as exc:
            saved = 'unwritable: ' + (exc.strerror or str(exc))
        self.pattern_state = saved
        if saved == 'rewritten':
            self.emit('kernel_profile_pattern_changed', 'profile.json', restored=True)

    # -- recording -------------------------------------------------------
    def paused(self):
        # A security guard has no off switch (2.2.16). Güvenlik bekçisinin kapatma anahtarı yoktur.
        return False

    def emit(self, kind, key, **fields):
        now = self.clock()
        if now - self.recent.get((kind, key), -THROTTLE) < THROTTLE:
            return
        self.recent[(kind, key)] = now
        event = {'time': self.wall(), 'kind': kind, 'key': key, **fields}
        self.events = (self.events + [event])[-MAX_EVENTS:]
        line = json.dumps(event, ensure_ascii=False, sort_keys=True)
        self.echo(line)
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            with open(self.state_dir / 'events.jsonl', 'a') as stream:
                stream.write(line + '\n')
        except OSError:
            pass

    def save_state(self, readings):
        state = {'updated_at': self.wall(), 'paused': self.paused(), 'writing_back': self.can_write and not self.paused(),
                 'watched_settings': len(readings), 'settings_ok': sum(1 for r in readings.values() if r['ok']),
                 'counts': self.counts, 'last_events': self.events,
                 'profile_sha256': kernel_profile.pattern()['sha256'], 'profile_pattern': self.pattern_state,
                 'boot': self.boot, 'ptrace_scope': self.ptrace, 'system_accounts': self.accounts}
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            temporary = self.state_dir / 'state.json.tmp'
            temporary.write_text(json.dumps(state, ensure_ascii=False, sort_keys=True))
            os.replace(temporary, self.state_dir / 'state.json')
        except OSError:
            pass
        return state

    # -- one pass --------------------------------------------------------
    def check_settings(self):
        readings = read_settings(self.root, self.listdir)
        bad = [{'key': k, 'expected': r['required'], 'actual': r['value']}
               for k, r in readings.items() if r['value'] is not None and not r['ok']]
        if not bad:
            return readings
        self.counts['settings_changed'] += len(bad)
        writing = self.can_write and not self.paused()
        outcome = restore(bad, self.root, self.listdir) if writing else {'restored': [], 'failed': bad}
        done = {item['key'] for item in outcome['restored']}
        self.counts['settings_restored'] += len(done)
        self.counts['restore_failed'] += len(outcome['failed'])
        reasons = {item['key']: item.get('error') for item in outcome['failed']}
        for item in bad:
            self.emit('kernel_setting_changed', item['key'], expected=item['expected'], actual=item['actual'],
                      restored=item['key'] in done,
                      reason=None if item['key'] in done else ('paused_or_not_root' if not writing else reasons.get(item['key'])))
        blinded = [item for item in bad if item['key'] == ptrace_guard.KEY and item['key'] not in done]
        if blinded:
            # The kernel keeps 3 until reboot: say so, and undo what would bring it back.
            self.emit('ram_scanner_blinded', ptrace_guard.KEY, actual=blinded[0]['actual'],
                      expected=ptrace_guard.REQUIRED, reboot_needed=True)
            self.check_ptrace_sources()
        return read_settings(self.root, self.listdir)

    def sweep_ptrace(self):
        """The minute check: value, sysctl files and the boot line of every installed kernel.

        Dakikalık denetim: değer, sysctl dosyaları ve kurulu her çekirdeğin açılış satırı.
        """
        try:
            entries = kernel_profile.boot_entries(self.runner)
        except (OSError, RuntimeError, subprocess.SubprocessError):
            entries = None
        return self.check_ptrace_sources(entries, force=True)

    def check_ptrace_sources(self, entries=None, force=False):
        """Sysctl files and boot arguments that would set ptrace_scope away from 2.

        ptrace_scope'u 2'den başka değere çekecek sysctl dosyaları ve açılış bağımsız değişkenleri.
        """
        if not force and self.clock() - self.last_ptrace < RESTART_EVERY:
            return self.ptrace
        self.last_ptrace = self.clock()
        found = ptrace_guard.sources(entries=entries, **self.ptrace_paths)
        running = _read(os.path.join(str(self.root), ptrace_guard.KEY))
        if not found:
            self.ptrace = {'status': 'OK' if running in (None, ptrace_guard.REQUIRED) else 'REBOOT_NEEDED',
                           'running': running, 'sources': [], 'checked_at': self.wall()}
            return self.ptrace
        writing = self.can_write and not self.paused()
        results = ptrace_guard.neutralize(found, evidence=self.ptrace_evidence) if writing else \
            [{**item, 'neutralized': False, 'error': 'paused_or_not_root'} for item in found]
        if writing and ptrace_guard.boot_arguments(found) and self._may_start(PROFILE_UNIT):
            # satsuma-kernel-profile removes them from every kernel (it may write /boot).
            started = self.runner(['/usr/bin/systemctl', 'start', '--no-block', '--', PROFILE_UNIT],
                                  capture_output=True, text=True, timeout=30).returncode == 0
            results = [{**r, 'boot_unit_started': started} if r.get('needs_boot_unit') else r for r in results]
        for item in results:
            self.counts['restore_failed' if not item['neutralized'] else 'settings_restored'] += 1
            self.emit('ram_scanner_blinding_source', item.get('path') or item.get('argument'),
                      source=item['kind'], **{k: v for k, v in item.items() if k not in ('path', 'argument', 'kind')})
        self.ptrace = {'status': 'SOURCE_FOUND', 'running': running, 'sources': results,
                       'reboot_needed': running != ptrace_guard.REQUIRED, 'checked_at': self.wall()}
        return self.ptrace

    def _may_start(self, name):
        now = self.clock()
        if now - self.attempts.get(name, -RESTART_EVERY) < RESTART_EVERY:
            return False
        self.attempts[name] = now
        return True

    def check_units(self):
        writing = self.can_write and not self.paused()
        states = unit_states(NEVER_RUN + REQUIRED_RUNNING, self.runner)
        for item in unit_drift(states, self.pm_running()):
            self.counts['units_changed'] += 1
            done = False
            if writing and self._may_start(item['unit']):
                verb = ['mask', '--now', '--no-block'] if item['want'] == 'masked_and_stopped' else ['start', '--no-block']
                done = self.runner(['/usr/bin/systemctl', *verb, '--', item['unit']], capture_output=True, text=True,
                                   timeout=30).returncode == 0
            self.counts['units_restored' if done else 'restore_failed'] += 1
            self.emit('unit_changed', item['unit'], want=item['want'], active=item['active'],
                      unit_file=item['file'], restored=done)
        self.check_mounts(writing)

    def check_mounts(self, writing):
        try:
            result = memory_mounts.check(self.mount_reader)
        except (OSError, ValueError, IndexError):
            return
        if result['ok']:
            return
        self.counts['mounts_changed'] += 1
        done = False
        if writing and self._may_start('mounts'):
            done = self.runner(['/usr/bin/systemctl', 'restart', '--no-block', HARDENING_UNIT], capture_output=True,
                               text=True, timeout=30).returncode == 0
        self.counts['mounts_restored' if done else 'restore_failed'] += int(done) or 1
        self.emit('mount_changed', ','.join(sorted(t for t, r in result['mounts'].items() if not r['ok'])),
                  detail={t: r['missing_options'] for t, r in result['mounts'].items() if not r['ok']},
                  restored=done)

    def check_boot(self):
        """Late module lock and the boot command line of every installed kernel.

        Geç modül kilidi ve kurulu her çekirdeğin açılış komut satırı.
        """
        writing = self.can_write and not self.paused()
        for key, value in kernel_profile.LATE.items():
            actual = _read(os.path.join(str(self.root), key))
            if actual is None or actual == value or self.uptime() < kernel_profile.MODULE_LOCK_AFTER:
                continue
            done = False
            if writing and self._may_start(kernel_profile.MODULE_LOCK_UNIT):
                done = self.runner(['/usr/bin/systemctl', 'start', '--no-block', '--', kernel_profile.MODULE_LOCK_UNIT],
                                   capture_output=True, text=True, timeout=30).returncode == 0
            self.emit('kernel_setting_changed', key, expected=value, actual=actual, restored=done,
                      reason='module_lock_started' if done else 'module_lock_not_started')
        unsigned = kernel_profile.unsigned_modules(self.modules_path) or []
        args = kernel_profile.wanted_args(unsigned)
        try:
            missing = kernel_profile.boot_drift(kernel_profile.boot_entries(self.runner), args)
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            self.boot = {'status': 'UNREADABLE', 'error': str(exc)[:200]}
            return
        self.boot = {'status': 'CHANGED' if missing else 'OK', 'missing': missing,
                     'lockdown_waiting_for': unsigned,
                     'reboot_needed_for': kernel_profile.running_missing(args) or []}
        if not missing:
            return
        self.counts['boot_changed'] += 1
        done = False
        if writing and self._may_start(PROFILE_UNIT):
            done = self.runner(['/usr/bin/systemctl', 'start', '--no-block', '--', PROFILE_UNIT],
                               capture_output=True, text=True, timeout=30).returncode == 0
        self.counts['boot_restored' if done else 'restore_failed'] += 1
        self.emit('boot_cmdline_changed', ','.join(sorted(missing)), missing=missing, restored=done)

    def check_accounts(self):
        """A system account (UID 1-999, not root) with a usable password is locked; evidence first.

        UID 1-999 aralığındaki sistem hesabında kullanılabilir parola varsa kilitlenir; önce kanıt.
        """
        found = account_guard.find(**{k: v for k, v in self.account_paths.items() if k in ('passwd', 'shadow')})
        if found is None:
            self.accounts = {'status': 'UNREADABLE', 'checked_at': self.wall()}
            return
        if not found:
            self.accounts = {'status': 'OK', 'checked_at': self.wall()}
            return
        writing = self.can_write and not self.paused()
        results = (account_guard.lock(found, self.runner, **{k: v for k, v in self.account_paths.items()
                                                             if k in ('shadow', 'evidence')}) if writing else [])
        for entry in found:
            done = next((r for r in results if r['name'] == entry['name']), {})
            kind = 'second_root_account' if entry.get('second_root') else 'system_account_has_password'
            self.emit(kind, entry['name'], uid=entry['uid'], shell=entry['shell'],
                      empty_password=bool(entry.get('empty_password')),
                      locked=bool(done.get('locked')), shell_changed=bool(done.get('shell_changed')),
                      evidence=done.get('evidence'), error=done.get('error'))
        self.accounts = {'status': 'LOCKED' if results and all(r['locked'] for r in results) else 'AT_RISK',
                         'accounts': [e['name'] for e in found], 'checked_at': self.wall()}

    def cycle(self):
        readings = self.check_settings()
        self.check_accounts()
        if self.clock() - self.last_units >= UNITS_EVERY:
            self.last_units = self.clock()
            self.check_units()
        if self.clock() - self.last_boot >= BOOT_EVERY:
            self.last_boot = self.clock()
            self.check_boot()
        if self.clock() - self.last_ptrace_sweep >= PTRACE_EVERY:
            self.last_ptrace_sweep = self.clock()
            self.sweep_ptrace()
        return self.save_state(readings)


def report(root=PROC_SYS):
    """Read-only table for people: no root needed, nothing is written."""
    rows = read_settings(root)
    lines = [f"{'ayar':58} {'değer':18} {'istenen':18} durum"]
    for key, row in rows.items():
        lines.append(f"{key:58} {str(row['value'])[:18]:18} {row['required'][:18]:18} "
                     f"{'tamam' if row['ok'] else ('okunamadı' if row['value'] is None else 'DEĞİŞMİŞ')}")
    return '\n'.join(lines)


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if '--report' in args:
        print(report())
        return 0
    if os.geteuid() != 0:
        print('Root yetkisi gerekli (okumak için --report kullanın).', file=sys.stderr)
        return 1
    guard = Guard()
    if '--once' in args:
        print(json.dumps(guard.cycle(), ensure_ascii=False, sort_keys=True))
        return 0
    stop = []
    import signal
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    while not stop:
        started = time.monotonic()
        try:
            guard.cycle()
        except Exception as exc:  # the guard itself must never stop; the failure is recorded
            guard.emit('guard_error', type(exc).__name__, detail=str(exc)[:200])
        while not stop and time.monotonic() - started < SETTINGS_EVERY:
            time.sleep(0.1)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
