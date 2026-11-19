"""2.2.57: a short Satsuma service run is recognised from systemd's own record (field 2026-11-19)."""
from types import SimpleNamespace as NS

from satsuma.self_events import SelfClassifier

SHOW = """Id=satsuma-core-dns-refresh.service
ExecMainPID=45116
ExecMainStartTimestamp=@1795109066
ExecMainExitTimestamp=@1795109067
FragmentPath=/usr/lib/systemd/system/satsuma-core-dns-refresh.service
DropInPaths=

Id=satsuma-evil.service
ExecMainPID=500
ExecMainStartTimestamp=@1795109066
ExecMainExitTimestamp=@1795109067
FragmentPath=/etc/systemd/system/satsuma-evil.service
DropInPaths=
"""


def classifier(show=SHOW):
    calls = []
    runner = lambda args, **kw: calls.append(args) or NS(returncode=0, stdout=show)
    c = SelfClassifier(proc_root='/nonexistent', trusted=lambda exe: True, runner=runner)
    return c, calls


def event(pid='45116', ts=1795109066.187, cmd='systemd-executor --deserialize 100', ppid='1'):
    return {'source': 'audit', 'pid': pid, 'ppid': ppid, 'exe': '/usr/bin/python3.15', 'cmd': cmd,
            'timestamp': ts, 'file_path': '/etc/satsuma-core/dns/.refresh.lock'}


def test_ended_dns_refresh_run_is_own():
    c, calls = classifier()
    assert c.is_own(event())
    assert calls and calls[0][:2] == ['/usr/bin/systemctl', 'show']


def test_not_own_when_outside_the_run_or_another_pid():
    c, _ = classifier()
    assert not c.is_own(event(ts=1795109200.0))      # reused PID after that run
    assert not c.is_own(event(pid='45117'))
    assert not c.is_own(event(ppid='3000'))          # not a unit's main process


def test_unit_from_etc_is_never_trusted():
    c, _ = classifier()
    assert not c.is_own(event(pid='500'))


def test_shell_from_packaged_unit_is_still_evaluated():
    c, _ = classifier()
    raw = {**event(), 'exe': '/usr/bin/bash'}
    assert not c.is_own(raw)


def test_systemd_is_asked_at_most_every_two_seconds():
    c, calls = classifier()
    for _ in range(20):
        c.is_own(event(pid='45117'))
    assert len(calls) == 1


def test_one_stop_per_process():
    from satsuma import auto_process

    class Store(dict):
        db = None
        def add(self, kind, body): self.setdefault(kind, []).append(body)
        def get(self, k, d=None): return super().get(k, d)
        def set(self, k, v): self[k] = v
    store = Store()
    sent = []
    finding = {'rule_id': 'SATSUMA-GAP-047', 'finding_id': 'f', 'classification': 'suspicious',
               'event': {'pid': 4242, 'exe': '/usr/bin/x', 'starttime': 7, 'timestamp': 1}}
    class Response:
        def terminate_process(self, pid, reason, **kw):
            sent.append(pid); return {'status': 'identity_verification_failed'}
    import satsuma.auto_process as ap
    real = ap.authorize_destructive
    ap.authorize_destructive = lambda *a, **k: NS(reasons=[])
    real_time = ap.event_time_evidence
    ap.event_time_evidence = lambda *a, **k: {'state': 'CURRENT'}
    try:
        first = ap.respond(store, {'auto_action_process_enabled': True}, finding, Response())
        second = ap.respond(store, {'auto_action_process_enabled': True}, {**finding, 'finding_id': 'g'}, Response())
    finally:
        ap.authorize_destructive, ap.event_time_evidence = real, real_time
    assert sent == [4242] and second['status'] == 'already_decided'
