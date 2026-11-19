"""Boot problem correlator: one problem per cause instead of scattered findings.

Once per boot, after it settled (5 minutes uptime), and on manual scans,
for the current boot:

- collects the journal's warnings and errors of the first 10 minutes, the
  failed units (satsuma.systemd_audit), the loaded kernel modules with
  their taint flags, the default gateway and DNS servers, and every
  finding (core and scan databases) recorded in the same window;
- joins them by PID, program or unit; a finding with none of these is
  joined to journal errors within 10 seconds as "close in time";
- compares with the previous boot: a new kernel module (high when it is
  unsigned or out of tree) and a changed gateway or DNS server (high:
  where a man-in-the-middle starts) are problems of their own;
- writes one finding per problem (SATSUMA-BOOT-PROBLEM) with a plain
  Turkish sentence, the time from boot start and the evidence lines.
  Journal warnings that join nothing are counted, not reported.

Açılış sorun eşleyicisi: dağınık bulgular yerine her neden için tek sorun.
Her açılıştan sonra (5 dakika sonra) bir kez ve elle taramalarda; ilk 10
dakikanın günlük uyarılarını, başarısız birimleri, yüklü çekirdek
modüllerini, modem ve DNS'i ve aynı aralıktaki bütün bulguları toplar; PID,
program ya da birim üzerinden, yoksa 10 saniye içindeki hatalarla
birleştirir; önceki açılışla karşılaştırır (yeni çekirdek modülü, değişen
modem ya da DNS); her sorun için açılıştan bu yana geçen süreyi, sade
Türkçe bir cümleyi ve kanıt satırlarını taşıyan tek bulgu yazar.
"""
import json
import sqlite3
import subprocess
import time
from pathlib import Path

WINDOW = 600
SETTLE = 300
NEAR = 10
SEVERITY_ORDER = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
# 2.2.54 (field 2026-11-19): known boot messages that are not security problems. They
# were grouped as "kernel" and took the severity of an unrelated critical finding seen
# within NEAR seconds, so every boot showed a critical "kernel problem". The debugfs
# lines come from Satsuma's own debugfs=off kernel option (kernel_profile.CMDLINE).
# Güvenlik sorunu olmayan bilinen açılış mesajları; debugfs satırları Satsuma'nın kendi
# debugfs=off ayarından gelir.
import re as _re
BENIGN_MESSAGES = _re.compile('|'.join((
    r'failed to create debugfs director',
    r'TDX not supported by the host platform',
    r'bridge has subordinate \S+ but max busn',
    r"dracut-crypt-generator' failed with exit status",
    r'overlay: No changes allowed in reconfigure',
)), _re.I)


def relevant(entries):
    """Journal entries without the known harmless boot messages."""
    return [e for e in entries if not BENIGN_MESSAGES.search(str(e.get('message') or ''))]
CORE_DB = '/var/lib/satsuma-core/core.db'


def boot_id(path='/proc/sys/kernel/random/boot_id'):
    return Path(path).read_text().strip()


def boot_time(path='/proc/stat'):
    for line in Path(path).read_text().splitlines():
        if line.startswith('btime '):
            return float(line.split()[1])
    raise RuntimeError('boot time unknown')


def modules(path='/proc/modules'):
    """{name: taint flags}; flags such as (OE) mean out of tree / unsigned."""
    result = {}
    for line in Path(path).read_text().splitlines():
        parts = line.split()
        if parts:
            flags = parts[-1][1:-1] if parts[-1].startswith('(') else ''
            result[parts[0]] = flags
    return result


def journal(start, runner=subprocess.run, window=WINDOW, limit=5000):
    args = ['journalctl', '-b', '0', '-o', 'json', '--no-pager', '-p', '4',
            '--since', '@%d' % int(start), '--until', '@%d' % int(start + window)]
    try:
        result = runner(args, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return []
    entries = []
    for line in result.stdout.splitlines()[:limit]:
        try:
            raw = json.loads(line)
        except ValueError:
            continue
        message = raw.get('MESSAGE')
        if isinstance(message, list):
            message = bytes(message).decode('utf-8', 'replace')
        try:
            stamp = int(raw.get('__REALTIME_TIMESTAMP', 0)) / 1e6
        except (TypeError, ValueError):
            continue
        entries.append({'time': stamp, 'priority': int(raw.get('PRIORITY', 6)), 'message': str(message or '')[:300],
                        'pid': str(raw.get('_PID') or ''), 'exe': raw.get('_EXE') or '', 'comm': raw.get('_COMM') or '',
                        'unit': raw.get('_SYSTEMD_UNIT') or raw.get('UNIT') or '',
                        'kernel': raw.get('_TRANSPORT') == 'kernel'})
    return entries


def core_findings(start, end, path=CORE_DB):
    try:
        db = sqlite3.connect('file:' + path + '?mode=ro', uri=True, timeout=5)
    except sqlite3.Error:
        return []
    try:
        rows = db.execute("SELECT created, body FROM records WHERE kind='findings' AND created BETWEEN ? AND ?",
                          (start, end)).fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        db.close()
    found = []
    for created, body in rows:
        try:
            data = json.loads(body)
        except ValueError:
            continue
        found.append({**data, '_time': float(data.get('timestamp') or created)})
    return found


def host_findings(store, start, end):
    found = []
    for (body,) in store.db.execute('SELECT body FROM findings WHERE last_seen BETWEEN ? AND ?', (start, end)).fetchall():
        try:
            data = json.loads(body)
        except ValueError:
            continue
        if data.get('rule_id') == 'SATSUMA-BOOT-PROBLEM':
            continue
        try:
            stamp = float(data.get('timestamp') or 0)
        except (TypeError, ValueError):
            stamp = 0
        found.append({**data, '_time': stamp if start <= stamp <= end else start})
    return found


def _identity(finding):
    event = finding.get('event') if isinstance(finding.get('event'), dict) else {}
    process = finding.get('process') if isinstance(finding.get('process'), dict) else {}
    pid = finding.get('pid') or event.get('pid') or process.get('pid')
    exe = finding.get('executable') or event.get('exe') or process.get('exe') or ''
    comm = event.get('comm') or ''
    unit = finding.get('unit') or event.get('unit') or ''
    return str(pid or ''), str(exe), str(comm), str(unit)


def correlate(start, entries, findings, failed=(), new_modules=None, network_change=None):
    groups = {}
    def group(key, label):
        return groups.setdefault(key, {'key': key, 'label': label, 'journal': [], 'findings': [], 'failed': False,
                                       'events': []})
    by_pid, by_exe, by_comm = {}, {}, {}
    for entry in entries:
        key = ('unit:' + entry['unit']) if entry['unit'] else ('exe:' + entry['exe']) if entry['exe'] else \
              ('kernel' if entry['kernel'] else 'comm:' + entry['comm'])
        g = group(key, entry['unit'] or entry['exe'] or ('çekirdek' if entry['kernel'] else entry['comm']))
        g['journal'].append(entry)
        if entry['pid']:
            by_pid.setdefault(entry['pid'], key)
        if entry['exe']:
            by_exe.setdefault(entry['exe'], key)
        if entry['comm']:
            by_comm.setdefault(entry['comm'], key)
    for unit in failed:
        group('unit:' + unit, unit)['failed'] = True
    for finding in findings:
        pid, exe, comm, unit = _identity(finding)
        key = (('unit:' + unit) if unit and 'unit:' + unit in groups else by_pid.get(pid) or by_exe.get(exe)
               or by_comm.get(comm) or by_comm.get(Path(exe).name if exe else ''))
        how = 'aynı süreç ya da program' if key else None
        if not key:
            near = [e for e in entries if e['priority'] <= 3 and abs(e['time'] - finding['_time']) <= NEAR]
            if near:
                e = near[0]
                key = ('unit:' + e['unit']) if e['unit'] else ('exe:' + e['exe']) if e['exe'] else \
                      ('kernel' if e['kernel'] else 'comm:' + e['comm'])
                how = 'yakın zamanlı (±%d sn)' % NEAR
        if not key:
            key = 'finding:' + str(finding.get('rule_id') or finding.get('type') or finding.get('title'))
        group(key, key.split(':', 1)[-1])['findings'].append({**finding, '_how': how or 'tek başına'})
    if new_modules:
        g = group('kernel-modules', 'çekirdek modülleri')
        g['events'].append({'kind': 'new_modules', 'modules': new_modules})
    if network_change:
        g = group('network', 'modem ve DNS')
        g['events'].append({'kind': 'network_change', **network_change})
    problems = []
    for g in groups.values():
        if not (g['findings'] or g['failed'] or g['events']):
            continue
        severities = [str(f.get('severity', 'medium')).lower() for f in g['findings']]
        for event in g['events']:
            if event['kind'] == 'network_change':
                severities.append('high')
            elif event['kind'] == 'new_modules':
                severities.append('high' if any(set(flags) & set('OE') for flags in event['modules'].values()) else 'medium')
        if g['failed']:
            severities.append('medium')
        severity = max(severities, key=lambda s: SEVERITY_ORDER.get(s, 2))
        times = [e['time'] for e in g['journal']] + [f['_time'] for f in g['findings']]
        first = min(times) if times else start
        problems.append({'key': g['key'], 'severity': severity, 'at': round(first - start, 1),
                         'sentence': sentence(g, first - start), 'journal': [
                             {'at': round(e['time'] - start, 1), 'message': e['message']} for e in g['journal'][:5]],
                         'findings': [{'title': f.get('title') or f.get('summary'), 'severity': f.get('severity'),
                                       'how': f['_how'], 'at': round(f['_time'] - start, 1)} for f in g['findings'][:10]],
                         'events': g['events'], 'failed': g['failed']})
    problems.sort(key=lambda p: (-SEVERITY_ORDER.get(p['severity'], 2), p['at']))
    noise = sum(len(g['journal']) for g in groups.values() if not (g['findings'] or g['failed'] or g['events']))
    return problems, noise


def sentence(g, at):
    parts = []
    if g['failed']:
        parts.append(f"Açılışın {at:.0f}. saniyesinde {g['label']} başarısız oldu")
    elif g['journal']:
        parts.append(f"Açılışın {at:.0f}. saniyesinde {g['label']} hata/uyarı verdi ({len(g['journal'])} kayıt)")
    for event in g['events']:
        if event['kind'] == 'new_modules':
            parts.append('bu açılışta yeni çekirdek modülü yüklendi: ' + ', '.join(
                name + (' (' + flags + ')' if flags else '') for name, flags in sorted(event['modules'].items())[:10]))
        if event['kind'] == 'network_change':
            parts.append('modem ya da DNS önceki açılıştan farklı: ' + json.dumps(
                {k: v for k, v in event.items() if k != 'kind'}, ensure_ascii=False))
    if g['findings']:
        f = g['findings'][0]
        title = f.get('title') or f.get('summary') or f.get('rule_id')
        delay = f['_time'] - (g['journal'][0]['time'] if g['journal'] else f['_time'])
        link = '' if not g['journal'] else (f" ({f['_how']}; {abs(delay):.0f} sn {'sonra' if delay >= 0 else 'önce'})")
        more = f" ve {len(g['findings']) - 1} bulgu daha" if len(g['findings']) > 1 else ''
        parts.append(f"ilgili bulgu: {title}{link}{more}")
    return '; '.join(parts) + '.'


def run(store, manual=False, runner=subprocess.run, now=time.time, current_boot=None, start=None,
        entries=None, failed=None, current_modules=None, network=None, core=None):
    current_boot = current_boot or boot_id()
    start = start if start is not None else boot_time()
    last = store.get('boot_correlation', {}) or {}
    if not manual and (last.get('boot_id') == current_boot or now() - start < SETTLE):
        return last
    previous = store.get('boot_correlation_previous', {}) or {}
    if previous.get('boot_id') == current_boot:
        previous = store.get('boot_correlation_before', {}) or {}
    entries = relevant(entries if entries is not None else journal(start, runner))
    if failed is None:
        audit = store.get('systemd_audit', {}) or {}
        if audit.get('updated_at', 0) >= start:
            failed = (audit.get('timing') or {}).get('failed') or []
        else:
            # The daily systemd audit may describe an earlier boot.
            from .systemd_audit import boot_timing
            failed = boot_timing(runner)['failed']
    mods = current_modules if current_modules is not None else modules()
    if network is None:
        from .full_protection import _gateways, _resolvers
        network = {'gateways': sorted(_gateways()), 'resolvers': sorted(_resolvers())}
    new_modules = {n: f for n, f in mods.items() if previous.get('modules') is not None and n not in previous['modules']}
    change = None
    if previous.get('network') and previous['network'] != network:
        change = {'önce': previous['network'], 'şimdi': network}
    findings = (core if core is not None else core_findings(start, start + WINDOW)) + host_findings(store, start, start + WINDOW)
    problems, noise = correlate(start, entries, findings, failed, new_modules, change)
    stamp = now()
    for problem in problems:
        if SEVERITY_ORDER.get(problem['severity'], 2) < 2:
            continue
        ident = 'SATSUMA-BOOT-PROBLEM:' + current_boot + ':' + problem['key']
        body = {'finding_id': ident, 'rule_id': 'SATSUMA-BOOT-PROBLEM', 'timestamp': stamp,
                'severity': problem['severity'], 'classification': 'indicator', 'source': 'boot_correlator',
                'title': 'Açılış sorunu: ' + problem['key'].split(':', 1)[-1], 'summary': problem['sentence'],
                'problem': problem, 'boot_id': current_boot}
        store.db.execute('INSERT OR IGNORE INTO findings(finding_id,last_seen,body) VALUES(?,?,?)',
                         (ident, time.time(), json.dumps(body, ensure_ascii=False)))
    store.db.commit()
    snapshot = {'boot_id': current_boot, 'modules': sorted(mods), 'network': network}
    if previous.get('boot_id') and previous.get('boot_id') != current_boot:
        store.set('boot_correlation_before', previous)
    store.set('boot_correlation_previous', snapshot)
    state = {'boot_id': current_boot, 'boot_time': start, 'updated_at': stamp, 'problems': problems[:100],
             'unrelated_warnings': noise, 'journal_entries': len(entries)}
    store.set('boot_correlation', state)
    return state
