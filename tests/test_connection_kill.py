"""The runner is replaced so command lines and verification can be checked.
Real socket destruction needs a kernel with CONFIG_INET_DIAG_DESTROY.

Çalıştırıcı taklit edilir; komut satırları ve doğrulama denetlenir. Gerçek
soket yok etme CONFIG_INET_DIAG_DESTROY'lu bir çekirdek ister.
"""
import subprocess

from satsuma.connection_kill import kill_connection


class Result:
    def __init__(self, stdout='', returncode=0, stderr=''):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


class FakeSS:
    """Behaves like ss: lists a connection until -K destroys it."""
    def __init__(self, live, destroy_works=True, rc=0):
        self.live, self.destroy_works, self.rc, self.calls = live, destroy_works, rc, []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        key = ' '.join(argv[argv.index('src'):])
        present = key == self.live
        if '-K' in argv:
            if self.rc:
                return Result(returncode=self.rc, stderr='denied')
            if present and self.destroy_works:
                self.live = None
            return Result('ESTAB' if present else '')
        return Result('ESTAB 0 0 x y' if present else '')


A, B = ('203.0.113.5', 4444), ('198.51.100.7', 51000)


def test_destroys_and_verifies_when_ends_are_given_in_either_order():
    for given in ((A, B), (B, A)):
        ss = FakeSS('src 198.51.100.7:51000 dst 203.0.113.5:4444')
        report = kill_connection(given[0][0], given[0][1], given[1][0], given[1][1], 'tcp', runner=ss)
        assert report['terminated'] is True and report['verified'] is True
        assert any('-K' in call for call in ss.calls)


def test_missing_connection_is_reported_not_claimed():
    ss = FakeSS(None)
    report = kill_connection(*A, *B, 'tcp', runner=ss)
    assert report['terminated'] is False and report['reason'] == 'connection_not_found'
    assert not any('-K' in call for call in ss.calls)


def test_destroy_that_leaves_the_socket_is_not_success():
    ss = FakeSS('src 198.51.100.7:51000 dst 203.0.113.5:4444', destroy_works=False)
    report = kill_connection(*A, *B, 'tcp', runner=ss)
    assert report['terminated'] is False and report['reason'] == 'connection_still_present_after_destroy'


def test_kernel_refusal_is_reported():
    ss = FakeSS('src 198.51.100.7:51000 dst 203.0.113.5:4444', rc=1)
    report = kill_connection(*A, *B, 'tcp', runner=ss)
    assert report['terminated'] is False and report['reason'] == 'socket_destroy_failed'


def test_refuses_protected_or_invalid_flows_without_running_anything():
    ss = FakeSS('x')
    for args in (('127.0.0.1', 1, *B, 'tcp'), ('0.0.0.0', 1, *B, 'tcp'), ('224.0.0.1', 1, *B, 'tcp'),
                 (*A, *B, 'udp'), ('nonsense', 1, *B, 'tcp'), (*A, 'x', 70000, 'tcp')):
        report = kill_connection(*args, runner=ss)
        assert report['terminated'] is False and report['reason']
    assert ss.calls == []


def test_missing_ss_is_reported():
    def missing(argv, **kwargs):
        raise FileNotFoundError('ss')
    report = kill_connection(*A, *B, 'tcp', runner=missing)
    assert report['terminated'] is False and report['reason'] == 'ss_unavailable'


def test_timeout_is_reported():
    def slow(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 5)
    assert kill_connection(*A, *B, 'tcp', runner=slow)['reason'] == 'ss_unavailable'
