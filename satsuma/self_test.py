"""Field self-test: each protection path, run for real on harmless targets (2.2.62).

Field 2026-11-19: file quarantine failed for four releases while every test passed; the
tests stood in for privd and never used the real client. `sudo satsuma-admin oz-test` runs
the real chain end to end on this machine (sensor -> rule -> decision -> privd -> effect)
and reports PASS/FAIL, cleaning up after each step:

* privd:      a request with a file path over the real socket (no change: a refused path);
* stop:       a process with an attack pattern (sleep, then "curl ... | sh" to 127.0.0.1:9,
              run as nobody) must be stopped by Satsuma within 45 s;
* quarantine: a harmless cron file (a comment line) must be quarantined within 60 s;
* firewall:   Satsuma's OTX guard table is deleted and must come back within 75 s;
              otherwise the test rebuilds it itself and reports FAIL;
* account:    a temporary account (oztest...) must be locked within 45 s; it is
              deleted at the end whatever happened.

Saha öz testi: her koruma yolu zararsız hedeflerle gerçekten çalıştırılır; GEÇTİ/KALDI.
"""
import json
import os
import secrets
import subprocess
import time
from pathlib import Path

NFT = '/usr/sbin/nft'
SYSTEMCTL = '/usr/bin/systemctl'
GUARD_TABLE = 'satsuma_otx_guard'
GUARD_UNIT = 'satsuma-suricata-otx-guard.service'
RESULT_KEY = 'self_test_last'


def _wait(condition, seconds, step=1.0, clock=time.monotonic, sleep=time.sleep):
    deadline = clock() + seconds
    while clock() < deadline:
        if condition():
            return True
        sleep(step)
    return bool(condition())


def check_privd(request=None):
    """The real client and socket carry a request with a file path (field bug 2.2.56-2.2.59)."""
    from . import privd
    request = request or privd.request
    try:
        answer = request('remediate', action='quarantine_file', path='/nonexistent-satsuma-oz/x',
                         rule_id='SATSUMA-SELFTEST', reason='öz test: privd yolu')
    except Exception as exc:
        return {'name': 'privd', 'passed': False, 'detail': f'privd yanıt vermedi: {exc}'}
    passed = isinstance(answer, dict) and answer.get('status') == 'refused'
    return {'name': 'privd', 'passed': passed,
            'detail': 'privd isteği aldı ve geçersiz yolu reddetti' if passed else f'beklenmeyen yanıt: {answer}'}


def _nobody():
    os.setgid(65534)
    os.setuid(65534)


def check_stop(popen=subprocess.Popen, wait=_wait):
    probe = popen(['/bin/sh', '-c', 'sleep 120; curl -s http://127.0.0.1:9/satsuma-oz | sh'],
                  preexec_fn=_nobody, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        stopped = wait(lambda: probe.poll() is not None, 45)
        code = probe.poll()
        passed = stopped and code is not None and code < 0
        return {'name': 'süreç durdurma', 'passed': passed, 'pid': probe.pid,
                'detail': (f'Satsuma süreci durdurdu (sinyal {-code})' if passed
                           else 'süreç 45 saniyede durdurulmadı')}
    finally:
        if probe.poll() is None:
            probe.kill()
            probe.wait(5)


def check_quarantine(run=subprocess.run, wait=_wait, directory='/etc/cron.d'):
    path = Path(directory) / f'oztest-{secrets.token_hex(4)}'
    run(['/usr/bin/tee', str(path)], input='# satsuma oz-test, zararsız\n', capture_output=True, text=True, timeout=10)
    if not path.exists():
        return {'name': 'dosya karantinası', 'passed': False, 'detail': f'test dosyası yazılamadı: {path}'}
    gone = wait(lambda: not path.exists(), 60)
    if not gone:
        path.unlink(missing_ok=True)
    return {'name': 'dosya karantinası', 'passed': gone, 'path': str(path),
            'detail': 'cron dosyası karantinaya alındı' if gone else 'dosya 60 saniyede karantinaya alınmadı (test sildi)'}


def _tables(run):
    done = run([NFT, '-j', 'list', 'tables'], capture_output=True, text=True, timeout=10)
    rows = json.loads(done.stdout or '{}').get('nftables', []) if done.returncode == 0 else []
    return {r['table'].get('name') for r in rows if 'table' in r}


def check_firewall(run=subprocess.run, wait=_wait):
    if GUARD_TABLE not in _tables(run):
        return {'name': 'güvenlik duvarı', 'passed': None, 'detail': f'{GUARD_TABLE} tablosu zaten yok; atlandı'}
    run([NFT, 'delete', 'table', 'inet', GUARD_TABLE], capture_output=True, text=True, timeout=10)
    back = wait(lambda: GUARD_TABLE in _tables(run), 75, step=3.0)
    if not back:
        run([SYSTEMCTL, 'restart', GUARD_UNIT], capture_output=True, text=True, timeout=60)
    return {'name': 'güvenlik duvarı', 'passed': back,
            'detail': 'silinen tablo Satsuma tarafından geri kuruldu' if back
            else '75 saniyede geri gelmedi (test kendisi geri kurdu)'}


def _locked(user, shadow='/etc/shadow'):
    try:
        for line in Path(shadow).read_text().splitlines():
            parts = line.split(':')
            if parts[0] == user:
                return parts[1].startswith('!') or (len(parts) > 7 and parts[7] == '1')
    except OSError:
        return False
    return False


def check_account(run=subprocess.run, wait=_wait, locked=_locked):
    user = 'oztest' + secrets.token_hex(3)
    run(['/usr/sbin/useradd', '-M', '-s', '/sbin/nologin', user], capture_output=True, text=True, timeout=20)
    try:
        done = wait(lambda: locked(user), 45)
        return {'name': 'hesap kilitleme', 'passed': done, 'user': user,
                'detail': 'yeni hesap kilitlendi' if done else 'hesap 45 saniyede kilitlenmedi'}
    finally:
        run(['/usr/sbin/userdel', user], capture_output=True, text=True, timeout=20)


CHECKS = (('privd', check_privd), ('stop', check_stop), ('quarantine', check_quarantine),
          ('firewall', check_firewall), ('account', check_account))


def run_all(store=None, checks=CHECKS, policy_on=True):
    results = []
    for key, check in checks:
        if key != 'privd' and not policy_on:
            results.append({'name': key, 'passed': None, 'detail': 'durdurma politikası kapalı; atlandı'})
            continue
        try:
            results.append(check())
        except Exception as exc:
            results.append({'name': key, 'passed': False, 'detail': f'test hatası: {type(exc).__name__}: {exc}'[:300]})
    summary = {'timestamp': time.time(), 'results': results,
               'passed': all(r['passed'] is not False for r in results)}
    if store is not None:
        store.set(RESULT_KEY, summary)
        store.add('actions', {'action': 'self_test.run', 'status': 'passed' if summary['passed'] else 'failed',
                              'timestamp': summary['timestamp'],
                              'failed': [r['name'] for r in results if r['passed'] is False]})
    return summary
