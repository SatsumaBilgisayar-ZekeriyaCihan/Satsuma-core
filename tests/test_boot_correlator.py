"""2.2.15: boot events and findings become one problem per cause.

2.2.15: açılış olayları ve bulgular her neden için tek soruna dönüşür.
"""
import json
from types import SimpleNamespace as NS

from satsuma import boot_correlator as b
from satsuma.host_store import HostStore

START = 1_800_000_000.0


def entry(at, message, unit='', exe='', pid='', priority=3, kernel=False):
    return {'time': START + at, 'priority': priority, 'message': message, 'pid': pid, 'exe': exe,
            'comm': exe.rsplit('/', 1)[-1], 'unit': unit, 'kernel': kernel}


def test_failure_and_finding_of_the_same_program_are_one_problem():
    entries = [entry(12, 'Failed with result exit-code', unit='updater.service', exe='/opt/u/updater', pid='900'),
               entry(30, 'random warning', exe='/usr/bin/gnome-shell', pid='1', priority=4)]
    findings = [{'title': 'Şüpheli süreç', 'severity': 'high', '_time': START + 15,
                 'event': {'pid': 900, 'exe': '/opt/u/updater'}}]
    problems, noise = b.correlate(START, entries, findings, failed=['updater.service'])
    assert len(problems) == 1 and noise == 1
    p = problems[0]
    assert p['severity'] == 'high' and p['at'] == 12.0 and p['failed']
    assert 'Açılışın 12. saniyesinde updater.service başarısız oldu' in p['sentence']
    assert '3 sn sonra' in p['sentence'] and p['findings'][0]['how'] == 'aynı süreç ya da program'


def test_finding_without_identity_joins_a_nearby_error():
    entries = [entry(40, 'segfault', exe='/usr/bin/foo', pid='77')]
    findings = [{'title': 'Bellek farkı', 'severity': 'medium', '_time': START + 45}]
    problems, _ = b.correlate(START, entries, findings)
    assert problems[0]['findings'][0]['how'].startswith('yakın zamanlı')


def test_new_unsigned_module_and_network_change_are_high():
    problems, _ = b.correlate(START, [], [], new_modules={'rootkitmod': 'OE'},
                              network_change={'önce': {'gateways': ['192.168.1.1']}, 'şimdi': {'gateways': ['192.168.1.66']}})
    assert {p['key'] for p in problems} == {'kernel-modules', 'network'}
    assert all(p['severity'] == 'high' for p in problems)


def test_run_compares_with_the_previous_boot_and_waits_for_the_boot_to_settle(tmp_path):
    store = HostStore(tmp_path / 'host', test=True)
    common = dict(entries=[], failed=[], core=[], start=START)
    try:
        early = b.run(store, now=lambda: START + 60, current_boot='boot1', current_modules={'ext4': ''},
                      network={'gateways': ['192.168.1.1'], 'resolvers': ['192.168.1.1']}, **common)
        assert early == {}
        first = b.run(store, now=lambda: START + 400, current_boot='boot1', current_modules={'ext4': ''},
                      network={'gateways': ['192.168.1.1'], 'resolvers': ['192.168.1.1']}, **common)
        assert first['problems'] == []
        assert b.run(store, now=lambda: START + 900, current_boot='boot1', current_modules={'ext4': ''},
                     network={'gateways': ['192.168.1.1']}, **common) == first  # once per boot
        second = b.run(store, now=lambda: START + 400, current_boot='boot2', current_modules={'ext4': '', 'evil': 'OE'},
                       network={'gateways': ['192.168.1.66'], 'resolvers': ['192.168.1.66']}, **common)
        assert {p['key'] for p in second['problems']} == {'kernel-modules', 'network'}
        rules = [json.loads(x)['rule_id'] for (x,) in store.db.execute('SELECT body FROM findings')]
        assert rules.count('SATSUMA-BOOT-PROBLEM') == 2
        again = b.run(store, manual=True, now=lambda: START + 999, current_boot='boot2',
                      current_modules={'ext4': '', 'evil': 'OE'},
                      network={'gateways': ['192.168.1.66'], 'resolvers': ['192.168.1.66']}, **common)
        assert {p['key'] for p in again['problems']} == {'kernel-modules', 'network'}  # manual re-run of the same boot
    finally:
        store.close()


def test_journal_and_proc_parsing(tmp_path):
    line = json.dumps({'__REALTIME_TIMESTAMP': str(int((START + 5) * 1e6)), 'PRIORITY': '3', 'MESSAGE': 'boom',
                       '_PID': '42', '_EXE': '/usr/bin/x', '_COMM': 'x', '_SYSTEMD_UNIT': 'x.service'})
    entries = b.journal(START, runner=lambda *a, **k: NS(stdout=line + '\nnot json\n'))
    assert entries[0]['unit'] == 'x.service' and entries[0]['pid'] == '42' and round(entries[0]['time']) == START + 5
    mods = tmp_path / 'modules'
    mods.write_text('ext4 1 2 - Live 0x0\nevil 16384 0 - Live 0x0 (OE)\n')
    assert b.modules(str(mods)) == {'ext4': '', 'evil': 'OE'}
    stat = tmp_path / 'stat'
    stat.write_text('cpu 1 2 3\nbtime 1800000000\n')
    assert b.boot_time(str(stat)) == START


def test_failed_units_of_an_earlier_boot_are_not_reused(tmp_path):
    store = HostStore(tmp_path / 'host', test=True)
    calls = []
    def runner(args, **kw):
        calls.append(tuple(args))
        out = 'fresh.service loaded failed failed X\n' if args[:2] == ['systemctl', '--failed'] else ''
        return NS(returncode=0, stdout=out, stderr='')
    try:
        store.set('systemd_audit', {'updated_at': START - 3600, 'timing': {'failed': ['old.service']}})
        state = b.run(store, manual=True, runner=runner, now=lambda: START + 400, current_boot='b', start=START,
                      entries=[], core=[], current_modules={}, network={})
        assert [p['key'] for p in state['problems']] == ['unit:fresh.service']
    finally:
        store.close()
