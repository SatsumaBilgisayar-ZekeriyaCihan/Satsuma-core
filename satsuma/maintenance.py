"""Bakım kiti: the whole product checked, and what can safely be repaired, repaired.

Owner's request 2026-11-18: "tam kontrol scriptini tüm ürünü kapsayacak ve oto
onaracak bir bakım kiti". satsuma.full_check switches the protection functions
on; satsuma.self_health repairs 14 services every ten minutes. Neither looked at
the deep engine, the reader socket, the image mount, the databases, the system
accounts, the service identities, file modes or the ostree first boot. This
module does, for every Satsuma unit the package ships.

Repairs follow the rules self_health already keeps:
* nothing is repaired unless the signed installation verifies (a modified
  payload is reported, never restarted or "fixed");
* a masked unit is an administrator's deliberate block: reported, not unmasked;
* at most three repairs of one thing in 30 minutes (budget written before acting);
* tampering signs (a file not owned by root, an integrity mismatch, a corrupt
  database) are reported as critical with what to do, never changed;
* every step is written to /var/lib/satsuma-core/maintenance (0600).
Safe repairs: start/restart a stopped or failed unit (start limit cleared),
enable a unit the package enables, lock a system account with a password, take
the account snapshot, recreate the service identities with systemd-sysusers,
put the mode of a root-owned Satsuma file back, run the deferred ostree steps.

Bakım kiti: ürünün tamamı denetlenir, güvenle onarılabilen onarılır. İmza
doğrulanmadan onarım yapılmaz; maskelenmiş birim yöneticinin kararıdır, açılmaz;
bir şey 30 dakikada en çok üç kez onarılır; kurcalama işaretleri yalnızca
bildirilir. Her adım /var/lib/satsuma-core/maintenance altına yazılır.
"""
import grp
import json
import os
import pwd
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

STATE = Path('/var/lib/satsuma-core/maintenance')
DATA = Path('/var/lib/satsuma-core')
UNIT_DIR = Path('/usr/lib/systemd/system')
SYSTEMCTL = '/usr/bin/systemctl'
BUDGET, WINDOW = 3, 1800
# Units the package enables in %posttrans (tests/test_maintenance.py keeps this
# in step with the spec). Paketin %posttrans'ta etkinleştirdiği birimler.
ENABLED = (
    'satsuma-image.service', 'satsuma-memory-hardening.service', 'satsuma-early-guard.service',
    'satsuma-app-control.service', 'satsuma-integrity-check.timer', 'satsuma-self-health.timer',
    'satsuma-boot-inventory.timer', 'satsuma-quarantine-rollback.service', 'satsuma-quarantine-confirm.timer',
    'satsuma-mitm-watch.timer', 'satsuma-boot-lockdown.service', 'satsuma-kernel-guard.service',
    'satsuma-exec-guard.service', 'satsuma-clamonacc.service', 'satsuma-onaccess-listener.service',
    'satsuma-temporary-scan.timer', 'satsuma-privd.service', 'satsuma-configuration.path',
    'satsuma-core-gateway.service', 'satsuma-core-sentinel.service', 'satsuma-rescue.service',
    'satsuma-udev.service', 'satsuma-network.service', 'satsuma-network-identity.service',
    'satsuma-suricata-ips.service', 'satsuma-suricata-otx-guard.service', 'satsuma-core.service',
    'satsuma-deep-engine.service', 'satsuma-teams.service', 'satsuma-reader.service',
    'satsuma-operator.service', 'satsuma-guardian.service', 'satsuma-network-modes.service',
    'satsuma-core-audit.service', 'satsuma-core-otx.service', 'satsuma-core-subnet.service',
    'satsuma-core-finding.service', 'satsuma-core-security-scan.timer', 'satsuma-core-dns-refresh.timer', 'satsuma-firewall-watch.timer',
    'satsuma-module-lock.timer', 'satsuma-flow-guard.service', 'satsuma-maintenance.timer',
)
IDENTITIES = {'group': ('satsuma-dns', 'satsuma-core', 'satsuma-reader', 'satsuma-engine', 'satsuma-priv'),
              'user': ('satsuma-dns', 'satsuma-core', 'satsuma-engine')}
SYSUSERS = ('/usr/bin/systemd-sysusers', '/usr/lib/sysusers.d/satsuma-core.conf')
# (path or glob, wanted mode, kind) for root-owned Satsuma files.
MODES = (('/usr/bin/satsuma-*', 0o755, 'file'), ('/usr/libexec/satsuma-*', 0o755, 'file'),
         ('/var/lib/satsuma-core', 0o700, 'dir'), ('/etc/satsuma-core/trust/manifest.key', 0o600, 'file'))
DEEP_EVENTS = Path('/run/satsuma-deep/events.sock')
DEEP_RESULTS = Path('/run/satsuma-deep-results/results.sock')
KERNEL_GUARD_STATE = Path('/var/lib/satsuma-core/kernel-guard/state.json')
FRESH = {'flow': 120, 'kernel_guard': 300}


def row(name, ok, detail, severity=None, repaired=None, repair=None):
    """One line of the report; severity 'critical' marks a tampering sign."""
    return {'name': name, 'ok': bool(ok), 'detail': detail, 'severity': severity or ('ok' if ok else 'warning'),
            'repaired': repaired, 'repair': repair}


def condition_unmet(props):
    """True when systemd evaluated the unit's Condition*= and it did not hold.

    ConditionResult is "no" also for a unit never started; the timestamp tells
    an evaluated condition apart.
    """
    return props.get('ConditionResult') == 'no' and props.get('ConditionTimestampMonotonic', '0') not in ('', '0')


class Kit:
    def __init__(self, runner=subprocess.run, repair=True, state=STATE, clock=time.time, unit_dir=UNIT_DIR,
                 store=None, verify=None, reader_ping=None, data=DATA, modes=MODES, identities=IDENTITIES,
                 ostree_marker=None, accounts=None):
        self.runner, self.repair, self.state, self.clock = runner, repair, Path(state), clock
        self.unit_dir, self.store, self.data, self.modes = Path(unit_dir), store, Path(data), modes
        self.verify, self.reader_ping, self.identities = verify, reader_ping, identities
        self.ostree_marker, self.accounts = ostree_marker, accounts
        self.rows, self.history = [], self._load_history()
        self.integrity_ok = False

    # -- bookkeeping -----------------------------------------------------
    def _load_history(self):
        try:
            data = json.loads((self.state / 'history.json').read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write(self, name, payload):
        try:
            self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.state, 0o700)
            temporary = self.state / (name + '.tmp')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump(payload, stream, ensure_ascii=False, sort_keys=True)
            os.replace(temporary, self.state / name)
        except OSError:
            pass

    def allowed(self, key):
        """Repair budget: three per 30 minutes per thing, recorded before acting."""
        if not self.repair or not self.integrity_ok:
            return False
        now = self.clock()
        recent = [t for t in self.history.get(key, []) if 0 <= now - t < WINDOW]
        # 2.2.62: no cap for unit starts; satsuma.repair_budget spaces them out (a cap let a killer
        # keep a protection service down). Other repairs keep three per 30 minutes.
        if len(recent) >= BUDGET and not key.startswith('start:'):
            return False
        self.history[key] = recent + [now]
        self._write('history.json', self.history)
        return True

    def why_not(self, key):
        if not self.repair:
            return 'yalnız kontrol istendi'
        if not self.integrity_ok:
            return 'kurulum bütünlüğü doğrulanmadı; onarım yapılmadı'
        return 'onarım sınırı doldu (30 dakikada 3)'

    def run(self, argv, timeout=60):
        try:
            done = self.runner(argv, capture_output=True, text=True, timeout=timeout)
            return done.returncode, (done.stdout or ''), (done.stderr or '')
        except (OSError, subprocess.SubprocessError) as exc:
            return 1, '', str(exc)

    # -- checks ------------------------------------------------------------
    def check_integrity(self):
        try:
            if self.verify is None:
                from installer.integrity import verify
                count = verify()
            else:
                count = self.verify()
            self.integrity_ok = True
            self.rows.append(row('Kurulum bütünlüğü', True, f'İmzalı envanter doğrulandı ({count} dosya)'))
        except Exception as exc:
            self.integrity_ok = False
            self.rows.append(row('Kurulum bütünlüğü', False,
                                 f'{type(exc).__name__}: {str(exc)[:200]}. Hiçbir şey onarılmadı; paketi yeniden kurun '
                                 '(sudo dnf reinstall satsuma-core ya da rpm-ostree) ve nedenini inceleyin.',
                                 severity='critical'))

    def units(self):
        names = sorted(p.name for p in self.unit_dir.glob('satsuma-*') if p.suffix in ('.service', '.timer', '.path'))
        return names

    def show(self, unit):
        code, out, _ = self.run([SYSTEMCTL, 'show', unit, '-p',
                                 'ActiveState,SubState,UnitFileState,Type,RemainAfterExit,Result,LoadState,'
                                 'ConditionResult,ConditionTimestampMonotonic'])
        props = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
        return props if code == 0 else {}

    def check_units(self):
        names = self.units()
        # The image first: every other unit requires it.
        names.sort(key=lambda n: (n != 'satsuma-image.service', n))
        bad = []
        for unit in names:
            props = self.show(unit)
            if not props:
                bad.append(row('Birim ' + unit, False, 'systemctl okunamadı'))
                continue
            active, filestate = props.get('ActiveState', ''), props.get('UnitFileState', '')
            oneshot = props.get('Type') == 'oneshot' and props.get('RemainAfterExit') != 'yes'
            if unit == 'satsuma-ostree-firstboot.service' or unit.endswith('-now.service'):
                continue   # handled by check_ostree / started by hand
            if filestate.startswith('masked'):
                bad.append(row('Birim ' + unit, False, 'Maskelenmiş: yöneticinin kararı sayılır, açılmadı. '
                               'Açmak için: sudo systemctl unmask ' + unit, severity='critical'))
                continue
            wanted = unit in ENABLED
            if wanted and filestate not in ('enabled', 'static', 'enabled-runtime', 'alias', 'indirect', 'generated'):
                fixed = None
                if self.allowed('enable:' + unit):
                    code, _, err = self.run([SYSTEMCTL, 'enable', '--now', unit])
                    fixed = code == 0
                    detail = 'Etkin değildi; etkinleştirildi' if fixed else 'Etkinleştirilemedi: ' + err[-200:]
                else:
                    detail = 'Etkin değil (' + filestate + '); ' + self.why_not('enable:' + unit)
                bad.append(row('Birim ' + unit, fixed, detail, repaired=fixed, repair='enable --now'))
                continue
            if oneshot:
                if props.get('Result') not in ('', 'success') and active == 'failed':
                    bad.append(row('Birim ' + unit, False, 'Son çalışma başarısız (' + props.get('Result', '') +
                                   '); günlük: journalctl -u ' + unit))
                continue
            if wanted and active != 'active':
                if condition_unmet(props):
                    continue   # e.g. quarantine-rollback with nothing pending: inactive by design
                bad.append(self.start(unit, active))
            elif not wanted and active == 'failed':
                # 2.2.40: a failed unit the package does not enable at install
                # (satsuma-core-dns after setup) was not reported at all.
                bad.append(self.start(unit, active))
        if bad:
            self.rows.extend(bad)
        self.rows.append(row('Satsuma birimleri', not any(not r['ok'] for r in bad),
                             f'{len(names)} birim denetlendi; sorunlu {sum(1 for r in bad if not r["ok"])}'))

    def start(self, unit, active, reason=None):
        key = 'start:' + unit
        if not self.allowed(key):
            return row('Birim ' + unit, False, (reason or active or 'çalışmıyor') + '; ' + self.why_not(key))
        from .repair_budget import claim
        granted, why = claim([unit], 'maintenance', now=self.clock())
        if not granted:
            return row('Birim ' + unit, False, (reason or active or 'çalışmıyor') + '; ' + why)
        self.run([SYSTEMCTL, 'reset-failed', unit])
        verb = 'restart' if active == 'active' else 'start'
        code, _, err = self.run([SYSTEMCTL, verb, unit], timeout=120)
        shown = self.show(unit)
        after = shown.get('ActiveState', '')
        if code == 0 and after == 'inactive' and condition_unmet(shown):
            return row('Birim ' + unit, True, 'Başlatma koşulu sağlanmıyor; birimin çalışmaması beklenen durum')
        fixed = code == 0 and after in ('active', 'activating')
        return row('Birim ' + unit, fixed, (reason or ('Durumu ' + (active or 'bilinmiyor'))) + (
            '; yeniden başlatıldı' if fixed else '; başlatılamadı: ' + (err[-200:] or after)),
            repaired=fixed, repair='reset-failed + ' + verb)

    def check_image(self):
        mounted = os.path.ismount('/opt/satsuma-core')
        if mounted:
            self.rows.append(row('Uygulama imajı', True, '/opt/satsuma-core salt okunur imaj olarak bağlı'))
        else:
            self.rows.append(row('Uygulama imajı', False, '/opt/satsuma-core bağlı değil; satsuma-image.service '
                                 'başlatılmalı (birim denetimi bunu dener)', severity='critical'))

    def check_deep_engine(self):
        events, results = DEEP_EVENTS.exists(), DEEP_RESULTS.exists()
        flow = (self.store.get('flow.health', {}) if self.store is not None else {}) or {}
        link = flow.get('deep_engine') or {}
        if events and results and link.get('running') is not False:
            self.rows.append(row('Derin motor bağlantısı', True, 'Motor soketi ve sonuç soketi yerinde'))
            return
        parts = [] if events else ['motor soketi yok']
        parts += [] if results else ['teams sonuç soketi yok']
        if link.get('error'):
            parts.append('son hata: ' + str(link['error'])[:120])
        unit = 'satsuma-deep-engine.service' if not events else 'satsuma-teams.service'
        fixed = self.start(unit, self.show(unit).get('ActiveState', ''), 'Derin motor: ' + ', '.join(parts))
        fixed['name'] = 'Derin motor bağlantısı'
        self.rows.append(fixed)

    def check_reader(self):
        ping = self.reader_ping
        if ping is None:
            def ping():
                from .dashboard_api_client import ReaderClient
                return ReaderClient(timeout=5).ping()
        try:
            ok = ping()
            error = ''
        except Exception as exc:
            ok, error = False, f'{type(exc).__name__}: {str(exc)[:150]}'
        if ok:
            self.rows.append(row('Panel okuyucusu (reader)', True, 'Soket yanıt veriyor'))
            return
        fixed = self.start('satsuma-reader.service', self.show('satsuma-reader.service').get('ActiveState', ''),
                           'Panel okuyucusu yanıt vermiyor: ' + error)
        fixed['name'] = 'Panel okuyucusu (reader)'
        if fixed['repaired']:
            try:
                time.sleep(2)
                fixed['ok'] = fixed['repaired'] = bool(ping())
            except Exception:
                fixed['ok'] = fixed['repaired'] = False
        self.rows.append(fixed)

    def check_freshness(self):
        flow = (self.store.get('flow.health', {}) if self.store is not None else {}) or {}
        age = self.clock() - float(flow.get('updated_at') or 0)
        if self.store is not None:
            if 0 <= age <= FRESH['flow']:
                self.rows.append(row('Olay akışı (teams)', True, f'{int(age)} sn önce güncellendi'))
            else:
                fixed = self.start('satsuma-teams.service', 'active', f'Olay akışı {int(age)} sn güncellenmedi')
                fixed['name'] = 'Olay akışı (teams)'
                self.rows.append(fixed)
        try:
            age = self.clock() - float(json.loads(KERNEL_GUARD_STATE.read_text()).get('updated_at') or 0)
        except (OSError, ValueError, AttributeError):
            age = None
        if age is not None and 0 <= age <= FRESH['kernel_guard']:
            self.rows.append(row('Çekirdek bekçisi', True, f'{int(age)} sn önce çalıştı'))
        else:
            fixed = self.start('satsuma-kernel-guard.service', 'active',
                               'Çekirdek bekçisi durumu ' + ('yok' if age is None else f'{int(age)} sn eski'))
            fixed['name'] = 'Çekirdek bekçisi'
            self.rows.append(fixed)

    def check_databases(self):
        for name in ('core.db', 'host/host.db'):
            path = self.data / name
            if not path.exists():
                self.rows.append(row('Veritabanı ' + name, name != 'core.db', 'Yok' + (' (henüz oluşmamış olabilir)' if name != 'core.db' else '')))
                continue
            try:
                from .dashboard_api import _connect_at
                with _connect_at(str(path)) as db:
                    result = db.execute('PRAGMA quick_check(1)').fetchone()[0]
                ok = result == 'ok'
                self.rows.append(row('Veritabanı ' + name, ok, 'Bütünlük denetimi: ' + str(result)[:150] + (
                    '' if ok else '. Onarılmadı: kayıtlar kanıttır; servisleri durdurup kopyasını alın ve inceleyin.'),
                    severity=None if ok else 'critical'))
            except sqlite3.Error as exc:
                self.rows.append(row('Veritabanı ' + name, False, 'Okunamadı: ' + str(exc)[:150]))
        try:
            usage = shutil.disk_usage(self.data)
            free = usage.free / usage.total if usage.total else 1
            self.rows.append(row('Veri diski', free >= 0.05, f'Boş alan %{free * 100:.1f}' +
                                 ('' if free >= 0.05 else '; kayıt yazılamayabilir, yer açın')))
        except OSError as exc:
            self.rows.append(row('Veri diski', False, 'Okunamadı: ' + str(exc)[:100]))

    def check_accounts(self):
        from . import account_change, account_guard
        paths = self.accounts or {}
        found = account_guard.find(**{k: v for k, v in paths.items() if k in ('passwd', 'shadow')})
        if found is None:
            self.rows.append(row('Sistem hesapları', False, '/etc/passwd veya /etc/shadow okunamadı'))
        elif not found:
            self.rows.append(row('Sistem hesapları', True, 'Hiçbir sistem hesabında kullanılabilir parola yok; ikinci root yok'))
        else:
            names = ', '.join(e['name'] for e in found)
            if self.allowed('accounts'):
                results = account_guard.lock(found, self.runner, **{k: v for k, v in paths.items() if k in ('shadow', 'evidence')})
                fixed = bool(results) and all(r.get('locked') for r in results)
                self.rows.append(row('Sistem hesapları', fixed, 'Parolalı/riskli hesap: ' + names +
                                     ('; kanıt alındı ve kilitlendi' if fixed else '; kilitlenemedi'),
                                     severity='critical' if not fixed else None, repaired=fixed, repair='usermod -L'))
            else:
                self.rows.append(row('Sistem hesapları', False, 'Parolalı/riskli hesap: ' + names + '; ' +
                                     self.why_not('accounts'), severity='critical'))
        tracker = account_change.TRACKER if not paths else account_change.Tracker(
            paths.get('passwd', account_change.PASSWD), paths.get('shadow', account_change.SHADOW),
            paths.get('snapshot', account_change.SNAPSHOT))
        had = Path(tracker.snapshot).exists()
        ok = tracker.baseline() if (had or self.allowed('account-snapshot')) else False
        self.rows.append(row('Hesap özeti', ok, 'Var' if had else ('Yoktu; alındı' if ok else 'Yok'),
                             repaired=None if had else ok, repair=None if had else 'snapshot'))

    def check_identities(self):
        missing = []
        for name in self.identities.get('group', ()):
            try:
                grp.getgrnam(name)
            except KeyError:
                missing.append('grup ' + name)
        for name in self.identities.get('user', ()):
            try:
                pwd.getpwnam(name)
            except KeyError:
                missing.append('kullanıcı ' + name)
        if not missing:
            self.rows.append(row('Servis kimlikleri', True, 'Hepsi var'))
            return
        fixed = None
        if self.allowed('sysusers'):
            code, _, err = self.run(list(SYSUSERS))
            fixed = code == 0
        self.rows.append(row('Servis kimlikleri', fixed, 'Eksik: ' + ', '.join(missing) + (
            '; systemd-sysusers ile yeniden oluşturuldu' if fixed else '; ' + (self.why_not('sysusers') if fixed is None else 'oluşturulamadı')),
            repaired=fixed, repair='systemd-sysusers'))

    def check_modes(self):
        from . import ostree
        wrong, fixed_any, tamper = [], False, []
        for pattern, mode, kind in self.modes:
            for path in sorted(Path('/').glob(pattern.lstrip('/'))) if '*' in pattern else [Path(pattern)]:
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(info.st_mode) or (kind == 'dir') != stat.S_ISDIR(info.st_mode):
                    tamper.append(f'{path}: beklenmeyen dosya türü')
                    continue
                if info.st_uid != 0:
                    tamper.append(f'{path}: sahibi root değil (uid {info.st_uid})')
                    continue
                if stat.S_IMODE(info.st_mode) == mode:
                    continue
                note = f'{path}: {oct(stat.S_IMODE(info.st_mode))} (olması gereken {oct(mode)})'
                if str(path).startswith('/usr/') and ostree.booted(self.ostree_marker):
                    wrong.append(note + ' — ostree /usr salt okunur')
                elif self.allowed('mode:' + str(path)):
                    try:
                        os.chmod(path, mode)
                        fixed_any = True
                        continue
                    except OSError as exc:
                        wrong.append(note + ': ' + str(exc)[:80])
                else:
                    wrong.append(note)
        if tamper:
            self.rows.append(row('Dosya sahipliği', False, '; '.join(tamper)[:500] + '. Değiştirilmedi: kurcalama işareti, inceleyin.',
                                 severity='critical'))
        self.rows.append(row('Dosya izinleri', not wrong, '; '.join(wrong)[:500] if wrong else
                             ('Düzeltildi' if fixed_any else 'Doğru'), repaired=True if fixed_any else None, repair='chmod'))

    def check_ostree(self):
        from . import ostree
        if not ostree.booted(self.ostree_marker):
            return
        code, version, _ = self.run(['/usr/bin/rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}', 'satsuma-core'])
        try:
            done = (self.data / '.ostree-installed').read_text().strip()
        except OSError:
            done = ''
        if code == 0 and done == version.strip():
            self.rows.append(row('ostree ilk açılış kurulumu', True, 'Tamamlandı (' + done + ')'))
            return
        fixed = self.start('satsuma-ostree-firstboot.service', 'inactive',
                           'ostree kurulum adımları tamamlanmamış (işaret: ' + (done or 'yok') + ')')
        fixed['name'] = 'ostree ilk açılış kurulumu'
        self.rows.append(fixed)

    # -- run ----------------------------------------------------------------
    def check(self):
        started = self.clock()
        self.check_integrity()
        for step in (self.check_image, self.check_units, self.check_deep_engine, self.check_reader,
                     self.check_freshness, self.check_databases, self.check_accounts, self.check_identities,
                     self.check_modes, self.check_ostree):
            try:
                step()
            except Exception as exc:
                self.rows.append(row('Bakım adımı ' + step.__name__, False, f'{type(exc).__name__}: {str(exc)[:200]}'))
        summary = {'updated_at': self.clock(), 'duration_s': round(self.clock() - started, 1), 'repair': self.repair,
                   'integrity_ok': self.integrity_ok, 'ok': all(r['ok'] for r in self.rows),
                   'critical': sum(1 for r in self.rows if r['severity'] == 'critical'),
                   'repaired': sum(1 for r in self.rows if r['repaired']), 'rows': self.rows}
        self._write('last.json', summary)
        try:
            self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.state / 'history.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'a') as stream:
                stream.write(json.dumps({k: v for k, v in summary.items() if k != 'rows'} |
                                        {'problems': [r['name'] for r in self.rows if not r['ok']]}, ensure_ascii=False) + '\n')
        except OSError:
            pass
        if self.store is not None:
            try:
                self.store.set('maintenance', {k: v for k, v in summary.items() if k != 'rows'} |
                               {'problems': [r for r in self.rows if not r['ok'] or r['repaired']][:40]})
            except Exception:
                pass
        return summary


def report(summary):
    marks = {'ok': 'TAMAM ', 'warning': 'SORUN ', 'critical': 'KRİTİK'}
    lines = []
    for item in summary['rows']:
        mark = 'ONARILDI' if item['repaired'] else marks.get(item['severity'], 'SORUN ')
        lines.append(f"[{mark:8}] {item['name']}: {item['detail']}")
    lines.append('')
    lines.append(f"Bakım: {len(summary['rows'])} denetim, {summary['repaired']} onarım, {summary['critical']} kritik; "
                 + ('her şey yolunda.' if summary['ok'] else 'çözülmeyen sorunlar yukarıda.'))
    if not summary['integrity_ok']:
        lines.append('Kurulum bütünlüğü doğrulanmadığı için hiçbir onarım yapılmadı.')
    return '\n'.join(lines)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if os.geteuid() != 0:
        print('Root yetkisi gerekli: sudo satsuma-admin bakim', file=sys.stderr)
        return 1
    store = None
    try:
        from .store import Store
        store = Store()
    except Exception:
        store = None
    try:
        summary = Kit(repair='--yalniz-kontrol' not in argv, store=store).check()
    finally:
        if store is not None:
            store.close()
    print(json.dumps(summary, ensure_ascii=False) if '--json' in argv else report(summary))
    return 0 if summary['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
