"""2.2.15: privd is the one gate for blocking and stopping (stage 1).

2.2.15: engelleme ve durdurmanın tek kapısı privd (1. aşama).
"""
import os
import threading
from types import SimpleNamespace
from pathlib import Path

import pytest

from satsuma import privd
from satsuma.response import ResponseWorker


class FakeWorker:
    def __init__(self):
        self.calls = []
    def block_ip(self, ip, reason, raw_id=None, manual=False, duration=0):
        self.calls.append(('block', ip, manual, duration)); return {'status': 'set_membership_confirmed', 'ip': ip}
    def unblock_ip(self, ip, reason, manual=False):
        self.calls.append(('unblock', ip)); return {'ok': True, 'status': 'removed'}
    def terminate_process(self, pid, reason, evidence=None, context=None):
        self.calls.append(('terminate', pid, context)); return {'status': 'terminated', 'signal_sent': True}


def test_requests_are_validated_and_audited():
    worker, audit = FakeWorker(), []
    root = {'pid': 1, 'uid': 0, 'gid': 0}
    assert privd.handle({'op': 'block_ip', 'ip': '203.0.113.9', 'reason': 'x', 'duration': 60}, root, worker, audit.append)['status'] == 'set_membership_confirmed'
    for bad in ({'op': 'rm', 'reason': 'x'}, {'op': 'block_ip', 'ip': 'not-ip', 'reason': 'x'},
                {'op': 'block_ip', 'ip': '203.0.113.9', 'reason': 'x', 'shell': 'rm -rf /'},
                {'op': 'terminate', 'pid': 1, 'reason': 'x'}, None):
        assert privd.handle(bad, root, worker, audit.append)['status'] == 'privd_refused'
    stranger = {'pid': 9, 'uid': 1000, 'gid': 1000}
    assert privd.handle({'op': 'unblock_ip', 'ip': '203.0.113.9', 'reason': 'x'}, stranger, worker, audit.append)['status'] == 'privd_refused'
    assert worker.calls == [('block', '203.0.113.9', False, 60)]
    assert len(audit) == 7 and audit[0]['status'] == 'set_membership_confirmed'


def test_end_to_end_over_a_real_unix_socket(tmp_path, monkeypatch):
    # Real SO_PEERCRED is unchanged. This fixture models the satsuma-priv
    # group with the current process's *actual primary GID*, without creating
    # a host group, changing socket permissions or accepting arbitrary peers.
    production_allowed = privd.allowed
    def test_group(name):
        assert name == privd.GROUP
        return SimpleNamespace(gr_gid=os.getgid())
    monkeypatch.setattr(privd, 'allowed', lambda identity: production_allowed(identity, group_lookup=test_group))
    path = tmp_path / 'privd.sock'
    worker, audit = FakeWorker(), []
    class Store:
        def add(self, kind, record): audit.append(record)
    old = os.environ.get(privd.SERVER_ENV)
    thread = threading.Thread(target=privd.serve, kwargs={'path': path, 'worker_factory': lambda: (Store(), worker),
                                                          'once': True}, daemon=True)
    thread.start()
    try:
        for _ in range(200):
            if path.exists():
                break
            threading.Event().wait(0.01)
        answer = privd.request('terminate', socket_path=path, pid=4242, reason='attack', context={'rule_id': 'R'})
        thread.join(5)
        assert answer == {'status': 'terminated', 'signal_sent': True}
        assert worker.calls == [('terminate', 4242, {'rule_id': 'R'})]
        assert audit[0]['caller']['uid'] == os.getuid() and audit[0]['op'] == 'terminate'
    finally:
        if old is None:
            os.environ.pop(privd.SERVER_ENV, None)
        else:
            os.environ[privd.SERVER_ENV] = old


def test_response_worker_hands_over_and_falls_back(monkeypatch):
    sent = []
    monkeypatch.setattr(privd, 'delegate', lambda op, **p: sent.append((op, p)) or {'status': 'via_privd'})
    worker = ResponseWorker(store=None, config={'response_enabled': True})
    assert worker.block_ip('203.0.113.9', 'r')['status'] == 'via_privd'
    assert worker.terminate_process(4242, 'r', context={'a': 1})['status'] == 'via_privd'
    assert [s[0] for s in sent] == ['block_ip', 'terminate']
    # Tests (runner given) and replays never leave the process.
    sent.clear()
    ResponseWorker(store=None, config={}, runner=lambda *a: {'returncode': 1}).block_ip('203.0.113.9', 'r')
    ResponseWorker(store=None, config={}, replay=True)._privd('block_ip')
    assert sent == []


def test_unreachable_privd_means_act_locally(tmp_path, monkeypatch):
    monkeypatch.setattr(privd, 'SOCKET_PATH', tmp_path / 'missing.sock')
    assert privd.delegate('block_ip', ip='203.0.113.9', reason='r') is None
    (tmp_path / 'dead.sock').write_text('')
    monkeypatch.setattr(privd, 'SOCKET_PATH', tmp_path / 'dead.sock')
    assert privd.delegate('block_ip', ip='203.0.113.9', reason='r') is None
    monkeypatch.setenv(privd.SERVER_ENV, '1')
    assert privd.delegate('block_ip', ip='203.0.113.9', reason='r') is None


def test_unit_and_group():
    unit = Path('systemd/satsuma-privd.service').read_text()
    assert 'SATSUMA_PRIVD_SERVER=1' in unit and '-m satsuma.privd' in unit and 'Group=satsuma-priv' in unit
    assert 'g satsuma-priv -' in Path('packaging/root/usr/lib/sysusers.d/satsuma-core.conf').read_text()


def test_unauthorized_caller_is_refused_before_fake_worker(monkeypatch):
    production_allowed = privd.allowed
    monkeypatch.setattr(privd,'allowed',lambda identity:production_allowed(identity,group_lookup=lambda name:SimpleNamespace(gr_gid=424242)))
    worker,audit=FakeWorker(),[]
    answer=privd.handle({'op':'terminate','pid':4242,'reason':'unauthorized'},
                       {'pid':4321,'uid':65534,'gid':65534},worker,audit.append)
    assert answer['status']=='privd_refused' and worker.calls==[]
    assert audit[0]['status']=='privd_refused'


def test_verified_peer_with_wrong_group_is_not_authorized():
    identity={'pid':os.getpid(),'uid':os.getuid(),'gid':os.getgid()}
    if identity['uid']==0:
        # Root is deliberately authorized by the production contract; use
        # an explicitly synthetic non-root identity for this negative branch.
        identity={'pid':4321,'uid':65534,'gid':65534}
    assert not privd.allowed(identity,group_lookup=lambda name:SimpleNamespace(gr_gid=identity['gid']+1))


def test_remediation_request_with_a_file_path_reaches_privd(tmp_path, monkeypatch):
    """2.2.60 (field 2026-11-19): ``path=<file>`` was taken for the socket path; every
    quarantine request connected to the file itself and got "Connection refused"."""
    from satsuma import remediation
    monkeypatch.setattr(privd, 'allowed', lambda identity: True)
    monkeypatch.setattr(remediation, 'execute',
                        lambda action, store=None, audit=None: {'status': 'quarantined', 'got': action})
    sock = tmp_path / 'privd.sock'

    class Store:
        def add(self, kind, record): pass
    thread = threading.Thread(target=privd.serve, kwargs={'path': sock, 'worker_factory': lambda: (Store(), FakeWorker()),
                                                          'once': True}, daemon=True)
    old = os.environ.get(privd.SERVER_ENV)
    thread.start()
    try:
        for _ in range(200):
            if sock.exists():
                break
            threading.Event().wait(0.01)
        answer = privd.request('remediate', socket_path=sock, action='quarantine_file', path='/etc/cron.d/x',
                               rule_id='SATSUMA-PERS-001', reason='r')
        thread.join(5)
        assert answer['status'] == 'quarantined'
        assert answer['got']['path'] == '/etc/cron.d/x' and answer['got']['action'] == 'quarantine_file'
    finally:
        if old is None:
            os.environ.pop(privd.SERVER_ENV, None)
        else:
            os.environ[privd.SERVER_ENV] = old


def test_privd_only_services_never_act_themselves(monkeypatch, tmp_path):
    from satsuma import privd
    monkeypatch.setenv(privd.ONLY_ENV, '1')
    monkeypatch.delenv(privd.SERVER_ENV, raising=False)
    monkeypatch.setattr(privd, 'SOCKET_PATH', tmp_path / 'missing.sock')
    answer = privd.delegate('terminate', pid=1234, reason='x')
    assert answer['status'] == 'privd_unavailable' and answer['executed'] is False
    (tmp_path / 'dead.sock').write_text('')
    monkeypatch.setattr(privd, 'SOCKET_PATH', tmp_path / 'dead.sock')
    monkeypatch.setattr(privd, 'request', lambda op, **kw: (_ for _ in ()).throw(privd.PrivdUnavailable('refused')))
    assert privd.delegate('block_ip', ip='203.0.113.9', reason='x')['status'] == 'privd_unavailable'
    monkeypatch.delenv(privd.ONLY_ENV)
    assert privd.delegate('block_ip', ip='203.0.113.9', reason='x') is None     # other callers still act


def test_terminate_tree_is_a_privd_operation():
    from satsuma import privd
    calls = []

    class Worker:
        def kill_process_tree(self, pid, reason, evidence=None, context=None):
            calls.append(pid)
            return {'status': 'tree_terminated'}
    out = privd.handle({'op': 'terminate_tree', 'pid': 4321, 'reason': 'test'}, {'pid': 1, 'uid': 0, 'gid': 0},
                       Worker(), lambda row: None)
    assert out['status'] == 'tree_terminated' and calls == [4321]


def test_phase2_callers_hold_no_kill_capability():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / 'systemd'
    for unit, net_admin in (('satsuma-teams.service', False), ('satsuma-core-sentinel.service', False),
                            ('satsuma-core.service', True)):
        text = (root / unit).read_text()
        assert 'Environment=SATSUMA_PRIVD_ONLY=1' in text and 'CAP_KILL' not in text, unit
        assert ('CAP_NET_ADMIN' in text) is net_admin, unit
    assert 'SATSUMA_PRIVD_ONLY' not in (root / 'satsuma-privd.service').read_text()
