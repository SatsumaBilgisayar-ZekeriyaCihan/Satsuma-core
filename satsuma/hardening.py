"""Try a systemd hardening drop-in on a running Satsuma service; roll it back if it breaks.

Hardening cannot be proven correct without running the service, so the drop-in
is first applied as a runtime drop-in (it disappears at reboot), the unit is
restarted, and the unit must stay active for the whole trial with no
"Operation not permitted" / "Permission denied" in its journal. Any failure
removes the drop-in and restarts the unit as it was. Only a unit whose trial
passed in this boot can be made permanent. Nothing here changes what a
service is allowed to do beyond the drop-in files shipped in
/usr/share/satsuma-core/hardening (tier1.conf for every unit and an optional
<unit>.tier2.conf).

Çalışan bir Satsuma servisinde systemd sertleştirme eklentisini dene; bozarsa geri al.

Sertleştirme, servis çalıştırılmadan doğru olduğu kanıtlanamaz. Bu yüzden
eklenti önce çalışma zamanı eklentisi olarak uygulanır (yeniden başlatmada
kaybolur), birim yeniden başlatılır ve deneme boyunca etkin kalmalı, günlüğünde
"Operation not permitted" / "Permission denied" olmamalıdır. Her başarısızlık
eklentiyi kaldırır ve birimi eski haliyle yeniden başlatır. Yalnızca bu açılışta
denemesi geçen birim kalıcı yapılabilir. Burada, /usr/share/satsuma-core/hardening
altındaki eklenti dosyalarının (her birim için tier1.conf ve isteğe bağlı
<unit>.tier2.conf) ötesinde bir servisin neye izinli olduğu değiştirilmez.
"""
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

UNITS = ('satsuma-suricata-otx-guard', 'satsuma-reader', 'satsuma-guardian', 'satsuma-containment',
         'satsuma-operator', 'satsuma-privd')
DROPIN = '50-satsuma-hardening.conf'
SOURCE = Path('/usr/share/satsuma-core/hardening')
RUNTIME = Path('/run/systemd/system')
PERSISTENT = Path('/etc/systemd/system')
STATE = Path('/run/satsuma-hardening')
MARKERS = re.compile(r'Operation not permitted|Permission denied|Failed at step|EPERM|EACCES', re.I)


def _name(unit):
    unit = str(unit).removesuffix('.service')
    if unit not in UNITS:
        raise ValueError('unknown_unit')
    return unit


def dropin_text(unit, source=SOURCE):
    """tier1 plus the unit's own tier 2 file, if there is one."""
    unit = _name(unit)
    parts = [Path(source, 'tier1.conf')]
    tier2 = Path(source, unit + '.tier2.conf')
    if tier2.exists():
        parts.append(tier2)
    return '\n'.join(part.read_text() for part in parts)


def _ctl(runner, *args, check=False):
    return runner(['systemctl', *args], capture_output=True, text=True, timeout=120, check=check)


def _active(runner, unit):
    return _ctl(runner, 'is-active', unit + '.service').stdout.strip()


def score(unit, runner=subprocess.run):
    """Exposure line of systemd-analyze, e.g. '6.6 MEDIUM'; None if unreadable."""
    out = runner(['systemd-analyze', 'security', '--no-pager', _name(unit) + '.service'],
                 capture_output=True, text=True, timeout=60).stdout
    match = re.search(r'exposure level for \S+: ([0-9.]+) (\w+)', out)
    return f'{match[1]} {match[2]}' if match else None


def _write(directory, unit, text):
    folder = Path(directory, unit + '.service.d')
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / DROPIN
    target.write_text(text)
    os.chmod(target, 0o644)
    return target


def _remove(directory, unit):
    target = Path(directory, unit + '.service.d', DROPIN)
    try:
        target.unlink()
        target.parent.rmdir()
    except OSError:
        pass


def _restore(runner, unit, runtime):
    _remove(runtime, unit)
    _ctl(runner, 'daemon-reload')
    _ctl(runner, 'restart', unit + '.service')


def trial(unit, runner=subprocess.run, source=SOURCE, runtime=RUNTIME, state=STATE, wait=20,
          sleep=time.sleep, clock=time.time):
    """Apply the drop-in at runtime, restart, watch; roll back on any failure."""
    unit = _name(unit)
    report = {'unit': unit, 'ok': False, 'rolled_back': False, 'reason': None, 'journal': []}
    if _active(runner, unit) != 'active':
        report['reason'] = 'unit_not_active_before_trial'
        return report
    text = dropin_text(unit, source)
    report['score_before'] = score(unit, runner)
    started = clock()
    _write(runtime, unit, text)
    _ctl(runner, 'daemon-reload')
    restart = _ctl(runner, 'restart', unit + '.service')
    if restart.returncode:
        _restore(runner, unit, runtime)
        return {**report, 'rolled_back': True, 'reason': 'restart_failed'}
    for _ in range(max(1, int(wait))):
        sleep(1)
        if _active(runner, unit) != 'active':
            _restore(runner, unit, runtime)
            return {**report, 'rolled_back': True, 'reason': 'unit_left_active_state'}
    since = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(started))
    log = runner(['journalctl', '-u', unit + '.service', '--since', since, '--no-pager', '-o', 'cat'],
                 capture_output=True, text=True, timeout=60).stdout
    hits = [line[:200] for line in log.splitlines() if MARKERS.search(line)]
    if hits:
        _restore(runner, unit, runtime)
        return {**report, 'rolled_back': True, 'reason': 'permission_errors_in_journal', 'journal': hits[:10]}
    report.update(ok=True, score_after=score(unit, runner))
    Path(state).mkdir(parents=True, exist_ok=True)
    Path(state, unit + '.json').write_text(json.dumps(
        {'ok': True, 'sha256': hashlib.sha256(text.encode()).hexdigest(), 'boot': _boot_id()}))
    return report


def _boot_id():
    try:
        return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    except OSError:
        return ''


def persist(unit, runner=subprocess.run, source=SOURCE, runtime=RUNTIME, persistent=PERSISTENT, state=STATE):
    """Make a drop-in permanent, only if its trial passed in this boot with this exact text."""
    unit = _name(unit)
    text = dropin_text(unit, source)
    try:
        record = json.loads(Path(state, unit + '.json').read_text())
    except (OSError, ValueError):
        return {'unit': unit, 'ok': False, 'reason': 'no_passed_trial'}
    if (record.get('ok') is not True or record.get('boot') != _boot_id()
            or record.get('sha256') != hashlib.sha256(text.encode()).hexdigest()):
        return {'unit': unit, 'ok': False, 'reason': 'trial_not_valid_for_this_boot_and_text'}
    _write(persistent, unit, text)
    _remove(runtime, unit)
    _ctl(runner, 'daemon-reload')
    return {'unit': unit, 'ok': True, 'reason': None}


def rollback(unit, runner=subprocess.run, runtime=RUNTIME, persistent=PERSISTENT, state=STATE):
    """Remove the drop-in everywhere and restart the unit as shipped."""
    unit = _name(unit)
    _remove(persistent, unit)
    Path(state, unit + '.json').unlink(missing_ok=True)
    _restore(runner, unit, runtime)
    return {'unit': unit, 'ok': True, 'active': _active(runner, unit)}


def status(runner=subprocess.run, persistent=PERSISTENT, runtime=RUNTIME):
    """Per unit: where the drop-in applies and the current exposure score."""
    rows = []
    for unit in UNITS:
        where = [name for name, base in (('permanent', persistent), ('runtime', runtime))
                 if Path(base, unit + '.service.d', DROPIN).exists()]
        rows.append({'unit': unit, 'dropin': where or ['none'], 'score': score(unit, runner)})
    return rows
