"""2.2.62: the field self-test runs each protection path for real; here its logic with fakes."""
from types import SimpleNamespace as NS

from satsuma import self_test as st

now = lambda: None
instant = lambda condition, seconds, **kw: bool(condition())


def test_privd_check_uses_a_file_path_and_expects_a_refusal():
    sent = []
    request = lambda op, **kw: sent.append((op, kw)) or {'status': 'refused', 'reason': 'not_a_persistence_location'}
    assert st.check_privd(request)['passed'] is True
    assert sent[0][0] == 'remediate' and sent[0][1]['path'].startswith('/nonexistent')
    def broken(op, **kw):
        raise ConnectionRefusedError(111, 'Connection refused')
    out = st.check_privd(broken)
    assert out['passed'] is False and 'Connection refused' in out['detail']


def test_stop_check_passes_only_when_the_process_was_signalled():
    killed = NS(pid=7, poll=lambda: -15, kill=lambda: None, wait=lambda t: None)
    assert st.check_stop(popen=lambda *a, **k: killed, wait=instant)['passed'] is True
    state = {'code': None}
    alive = NS(pid=8, poll=lambda: state['code'], wait=lambda t: None)
    alive.kill = lambda: state.update(code=-9)
    out = st.check_stop(popen=lambda *a, **k: alive, wait=lambda c, s, **k: False)
    assert out['passed'] is False and state['code'] == -9      # the test cleans up its probe


def test_quarantine_check(tmp_path):
    def tee(args, input='', **kw):
        __import__('pathlib').Path(args[1]).write_text(input)
        return NS(returncode=0)
    out = st.check_quarantine(run=tee, wait=lambda c, s, **k: False, directory=tmp_path)
    assert out['passed'] is False and not list(tmp_path.iterdir())   # not quarantined: the test removed it
    def vanish(condition, seconds, **kw):
        for f in tmp_path.iterdir():
            f.unlink()
        return condition()
    assert st.check_quarantine(run=tee, wait=vanish, directory=tmp_path)['passed'] is True


def test_firewall_check_rebuilds_when_satsuma_does_not():
    calls, tables = [], {'satsuma_otx_guard', 'satsuma_core'}
    def run(args, **kw):
        calls.append(args)
        if args[1:3] == ['-j', 'list']:
            import json
            return NS(returncode=0, stdout=json.dumps({'nftables': [{'table': {'name': n}} for n in tables]}))
        if args[1] == 'delete':
            tables.discard(args[-1])
        return NS(returncode=0, stdout='')
    out = st.check_firewall(run=run, wait=lambda c, s, **k: c())
    assert out['passed'] is False and ['/usr/bin/systemctl', 'restart', st.GUARD_UNIT] in calls


def test_account_check_always_deletes_the_account():
    calls = []
    run = lambda args, **kw: calls.append(args) or NS(returncode=0)
    out = st.check_account(run=run, wait=instant, locked=lambda u: True)
    assert out['passed'] is True and calls[-1][0] == '/usr/sbin/userdel' and out['user'].startswith('oztest')
    calls.clear()
    st.check_account(run=run, wait=instant, locked=lambda u: False)
    assert calls[-1][0] == '/usr/sbin/userdel'


def test_run_all_records_and_skips_without_policy():
    class Store(dict):
        added = []
        def set(self, k, v): self[k] = v
        def add(self, kind, body): self.added.append(body)
    store = Store()
    ok = lambda: {'name': 'x', 'passed': True, 'detail': ''}
    bad = lambda: 1 / 0
    summary = st.run_all(store, checks=(('privd', ok), ('stop', bad)), policy_on=True)
    assert summary['passed'] is False and store[st.RESULT_KEY]['results'][1]['passed'] is False
    skipped = st.run_all(None, checks=(('privd', ok), ('stop', bad)), policy_on=False)
    assert skipped['passed'] is True and skipped['results'][1]['passed'] is None


def test_teams_probes_privd_hourly_and_alarms():
    import run_satsuma_teams as T

    class Store(dict):
        def get(self, k, d=None): return super().get(k, d)
        def set(self, k, v): self[k] = v
        def add(self, kind, body): pass
    store, alarms = Store(), []
    original = T._privd_unreachable
    T._privd_unreachable = lambda s, action, now=None: alarms.append(action)
    try:
        def broken(op, **kw):
            raise OSError(111, 'Connection refused')
        assert T._privd_probe(store, now=1.8e9, request=broken)['passed'] is False
        assert T._privd_probe(store, now=1.8e9 + 500, request=broken) is None       # once an hour
    finally:
        T._privd_unreachable = original
    assert len(alarms) == 1
