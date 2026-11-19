"""Audit K4/K6: locked kernel audit rules, and every execve reaches the process rules.

Denetim K4/K6: kilitli çekirdek audit kuralları; her execve süreç kurallarına ulaşır.
"""
import stat
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from satsuma import audit_rules as ar
from satsuma.smart_rules import SmartRuleEngine
from satsuma.worker_audit_bridge import WorkerAuditBridge

ROOT = Path(__file__).parents[1]
DIR, LINK = stat.S_IFDIR | 0o755, stat.S_IFLNK | 0o777


def fake_fs(entries):
    def lstat(path):
        if path not in entries:
            raise FileNotFoundError(path)
        return NS(st_mode=entries[path][0])

    def readlink(path):
        return entries[path][1]
    return lstat, readlink


def everything_real(extra=None):
    entries = {path: (DIR, None) for path, _ in ar.WATCHES}
    for parent in ('/usr', '/usr/lib', '/usr/share', '/usr/lib64', '/home', '/home/u', '/home/u/.local', '/home/u/.local/share'):
        entries[parent] = (DIR, None)
    entries.update(extra or {})
    return entries


def test_rules_watch_every_sensitive_tree_and_end_locked():
    lstat, readlink = fake_fs(everything_real({'/home/u/.local/share/fonts': (DIR, None)}))
    targets, refused = ar.watch_targets(['/home/u'], lstat, readlink)
    text = ar.render(targets)
    lines = text.splitlines()
    assert lines[-1] == '-e 2'
    assert '-a always,exit -F arch=b64 -S execve,execveat -k satsuma_exec' in lines
    for path in ('/etc', '/usr/bin', '/boot', '/usr/share/man', '/usr/local', '/usr/share/fonts',
                 '/usr/share/locale', '/usr/lib/locale', '/usr/lib64/gconv', '/home/u/.local/share/fonts'):
        assert any(line.startswith(f'-w {path} -p wa -k ') for line in lines), path
    assert refused == []


def test_fedora_merged_sbin_is_not_an_alarm_but_a_planted_link_is():
    entries = everything_real({'/usr/sbin': (LINK, 'bin'), '/usr/lib/locale': (LINK, '/tmp/x')})
    lstat, readlink = fake_fs(entries)
    targets, refused = ar.watch_targets([], lstat, readlink)
    paths = [p for p, _ in targets]
    assert '/usr/sbin' not in paths and '/usr/lib/locale' not in paths
    assert refused == [{'path': '/usr/lib/locale', 'reason': 'symlink'}]


def test_a_redirected_parent_is_refused_too():
    entries = everything_real({'/home/u/.local': (LINK, '/tmp/evil'), '/home/u/.local/share/fonts': (DIR, None)})
    lstat, readlink = fake_fs(entries)
    _, refused = ar.watch_targets(['/home/u'], lstat, readlink)
    assert {'path': '/home/u/.local/share/fonts', 'reason': 'symlink'} in refused


def kernel(enabled, rules, calls, load_rc=0, after=None):
    state = {'enabled': enabled, 'rules': rules}

    def runner(args, **kwargs):
        calls.append(args)
        if args[-1] == '--load':
            if after:
                state.update(after)
            return NS(returncode=load_rc, stdout='', stderr='')
        if args[-1] == '-s':
            return NS(returncode=0, stdout=f"enabled {state['enabled']}\nfailure 1\n", stderr='')
        return NS(returncode=0, stdout='\n'.join(state['rules']), stderr='')
    return runner


def kernel_listing(text):
    out = []
    for line in text.splitlines():
        if line.startswith('-a '):
            out.append(line.rsplit(' -k ', 1)[0] + ' -F key=' + line.rsplit(' -k ', 1)[1])
        elif line.startswith('-w '):
            out.append(line)
    return out


@pytest.fixture
def real(tmp_path):
    lstat, readlink = fake_fs(everything_real())
    targets, _ = ar.watch_targets([], lstat, readlink)
    return {'path': tmp_path / '99-satsuma-core.rules', 'lstat': lstat, 'readlink': readlink,
            'listing': kernel_listing(ar.render(targets))}


def test_unlocked_kernel_is_loaded_and_ends_locked(real):
    calls = []
    runner = kernel('1', [], calls, after={'enabled': '2', 'rules': real['listing']})
    report = ar.apply(runner, real['path'], [], real['lstat'], real['readlink'])
    assert report['status'] == 'LOCKED' and report['immutable']
    assert ['/usr/sbin/augenrules', '--load'] in calls
    assert real['path'].read_text().endswith('-e 2\n')


def test_locked_kernel_with_our_rules_is_left_alone(real):
    calls = []
    report = ar.apply(kernel('2', real['listing'], calls), real['path'], [], real['lstat'], real['readlink'])
    assert report['status'] == 'LOCKED'
    assert ['/usr/sbin/augenrules', '--load'] not in calls


def test_locked_kernel_without_our_rules_asks_for_a_reboot(real):
    report = ar.apply(kernel('2', [], []), real['path'], [], real['lstat'], real['readlink'])
    assert report['status'] == 'REBOOT_REQUIRED'


def test_failed_load_is_reported_not_hidden(real):
    report = ar.apply(kernel('1', [], [], load_rc=1), real['path'], [], real['lstat'], real['readlink'])
    assert report['status'] == 'LOAD_FAILED'


@pytest.fixture(scope='module')
def engine():
    return SmartRuleEngine(ROOT / 'rules')


def audit_execve(cmd):
    return {'source': 'audit', 'kind': 'execve', 'action': 'execve', 'cmd': cmd, 'pid': 77}


def test_kernel_reported_execve_reaches_process_rules(engine):
    ids = {f['rule_id'] for f in engine.match(audit_execve('rm -rf /var/log/messages'))}
    assert 'SATSUMA-EVASION-001' in ids


def test_other_audit_events_do_not_pose_as_processes(engine):
    event = {'source': 'audit', 'kind': 'file_access', 'action': 'file_access', 'cmd': 'rm -rf /var/log/messages'}
    assert 'SATSUMA-EVASION-001' not in {f['rule_id'] for f in engine.match(event)}


def test_padding_cannot_push_the_payload_out_of_the_audit_command():
    args = {'argc': '502', **{f'a{i}': 'x' * 10 for i in range(1, 501)}, 'a0': 'rm', 'a501': '/var/log/secure'}
    cmd = WorkerAuditBridge._cmd({'execve': args})
    assert cmd.startswith('rm ') and cmd.endswith('/var/log/secure')


def test_audit_worker_loads_rules_first_and_never_fails_because_of_them():
    unit = (ROOT / 'systemd/satsuma-core-audit.service').read_text()
    assert 'ExecStartPre=-+/usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -I -B /opt/satsuma-core/main.py --audit-rules' in unit
    assert 'auditd.service' in unit
    assert "'--audit-rules'" in (ROOT / 'satsuma/app.py').read_text()  # main.py delegates to satsuma.app


def test_task_never_rule_from_another_file_is_reported(real):
    listing = ['-a never,task'] + real['listing']
    report = ar.apply(kernel('2', listing, []), real['path'], [], real['lstat'], real['readlink'])
    assert report['status'] == 'SYSCALL_AUDIT_SUPPRESSED'


def test_conflicting_lines_in_other_files_are_disabled_with_a_backup(tmp_path):
    rules = tmp_path / 'rules.d'; rules.mkdir()
    own = rules / '99-satsuma-core.rules'
    (rules / '10-no-audit.rules').write_text('## no audit\n-D\n-a task,never\n')
    (rules / '50-site.rules').write_text('-w /srv -p wa -k site\n-e 1\n')
    (rules / 'zz-late.rules').write_text('-D\n')
    (rules / '20-keep.rules').write_text('-w /opt -p wa -k keep\n')
    changes = ar.neutralize_conflicts(own, tmp_path / 'backup', now=100)
    assert {Path(c['file']).name: c['lines'] for c in changes} == {
        '10-no-audit.rules': ['-a task,never'], '50-site.rules': ['-e 1'], 'zz-late.rules': ['-D']}
    text = (rules / '10-no-audit.rules').read_text()
    assert '\n-D\n' in text  # -D before our file is harmless and kept
    assert '# Disabled by Satsuma (audit K6)' in text and '\n-a task,never' not in text
    assert (tmp_path / 'backup/10-no-audit.rules.100').read_text() == '## no audit\n-D\n-a task,never\n'
    assert (rules / '20-keep.rules').read_text() == '-w /opt -p wa -k keep\n'
    assert ar.neutralize_conflicts(own, tmp_path / 'backup', now=200) == []


def test_removed_suppression_on_a_locked_kernel_asks_for_reboot(real):
    (real['path'].parent / '10-no-audit.rules').write_text('-a task,never\n')
    listing = ['-a never,task'] + real['listing']
    report = ar.apply(kernel('2', listing, []), real['path'], [], real['lstat'], real['readlink'],
                      backup_dir=real['path'].parent / 'backup')
    assert report['status'] == 'REBOOT_REQUIRED' and report['neutralized'][0]['lines'] == ['-a task,never']


def test_atomic_homes_root_and_usr_local_are_watched_under_their_real_paths():
    """2.2.54: on Fedora Atomic /home, /root and /usr/local are links into /var."""
    entries = everything_real({
        '/home': (LINK, 'var/home'), '/root': (LINK, 'var/roothome'), '/usr/local': (LINK, '../var/usrlocal'),
        '/var': (DIR, None), '/var/home': (DIR, None), '/var/home/u': (DIR, None), '/var/home/u/.ssh': (DIR, None),
        '/var/home/u/.config': (DIR, None), '/var/roothome': (DIR, None), '/var/usrlocal': (DIR, None),
        '/var/spool': (DIR, None), '/var/spool/cron': (DIR, None)})
    lstat, readlink = fake_fs(entries)
    targets, refused = ar.watch_targets(['/home/u'], lstat, readlink)
    text = ar.render(targets)
    assert refused == []
    assert '-w /var/home/u/.ssh -p rwa -k satsuma_home_ssh' in text
    # Not there yet, but its folder is: watched so that its creation is seen.
    assert '-w /var/home/u/.bashrc -p wa -k satsuma_home' in text
    assert '-w /var/home/u/.config/autostart -p wa -k satsuma_home' in text
    # Folder missing: not watched (audit cannot place it).
    assert '.config/systemd/user' not in text
    assert '-w /var/roothome/.bashrc -p wa -k satsuma_home' in text
    assert '-w /var/spool/cron -p wa -k satsuma_cron' in text
    assert '-w /var/usrlocal -p wa -k satsuma_local' in text
    assert '-w /usr/local ' not in text and '-w /home/u' not in text
    lines = text.splitlines()
    assert lines[1:3] == ['-b 8192', '--loginuid-immutable'] and lines[-1] == '-e 2'


def test_a_planted_home_link_is_still_refused():
    entries = everything_real({'/home': (LINK, '/tmp/evil')})
    lstat, readlink = fake_fs(entries)
    targets, refused = ar.watch_targets(['/home/u'], lstat, readlink)
    assert {'path': '/home/u/.local/share/fonts', 'reason': 'symlink'} in refused or not any(
        t[0].startswith('/home/u') for t in targets)
