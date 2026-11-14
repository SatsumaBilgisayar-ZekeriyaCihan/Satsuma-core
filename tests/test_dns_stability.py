"""DNS filter stability: start-limit retries, big-list wait, no needless rollback.

DNS filtresi kararlılığı: başlatma sınırı yeniden denemeleri, büyük liste
beklemesi, gereksiz geri alma yok.
"""
import struct
from types import SimpleNamespace

import pytest

from satsuma import dnsmasq_control as dns, custom_dns_lists, dns_readiness


@pytest.fixture
def env(tmp_path, monkeypatch):
    state = {'dns_policy': {'enabled': True, 'upstream': '192.0.2.53'}}

    class Store:
        def get(self, key, default=None):
            return state.get(key, default)

        def set(self, key, value):
            state[key] = value

    extra = set()
    monkeypatch.setattr(custom_dns_lists, 'blocked_domains', lambda store: set(extra))
    monkeypatch.setattr(dns.grp, 'getgrnam', lambda name: SimpleNamespace(gr_gid=0))
    monkeypatch.setattr(dns.os, 'chown', lambda *a: None)
    monkeypatch.setattr(dns, 'atomic', lambda path, content, gid: path.write_text(content))
    monkeypatch.setattr(dns, 'verify_config', lambda path: True)
    monkeypatch.setattr(dns, 'probe', lambda: None)
    return SimpleNamespace(store=Store(), state=state, dir=tmp_path, extra=extra)


def fake_systemctl(refuse=0, verbs=('start', 'restart'), active=False):
    """Refuses the first `refuse` start/restart calls like systemd does at its rate limit.

    ``is-active`` reports the service down unless ``active`` (2.2.27)."""
    calls = []
    left = [refuse]

    def runner(args, **kwargs):
        calls.append(args[1:])
        if args[1] == 'is-active':
            return SimpleNamespace(returncode=0 if active else 3, stderr='')
        if args[1] in verbs and left[0] > 0:
            left[0] -= 1
            return SimpleNamespace(returncode=1, stderr='Start request repeated too quickly.')
        return SimpleNamespace(returncode=0, stderr='')
    runner.calls = calls
    return runner


def test_restart_refused_by_the_start_limit_is_reset_and_retried_once(env):
    dns._refresh(env.store, fake_systemctl(), env.dir)
    env.extra.add('new-bad.example')          # a changed block list means a restart
    runner = fake_systemctl(refuse=1)
    assert dns._refresh(env.store, runner, env.dir)['status'] == 'configured'
    verbs = [c[0] for c in runner.calls if c[0] in ('restart', 'reset-failed')]
    assert verbs == ['restart', 'reset-failed', 'restart']


def test_start_of_an_unchanged_service_recovers_from_a_start_limit_too(env):
    dns._refresh(env.store, fake_systemctl(), env.dir)
    runner = fake_systemctl(refuse=1)
    assert dns._refresh(env.store, runner, env.dir)['status'] == 'unchanged'
    assert [c[0] for c in runner.calls] == ['is-active', 'start', 'reset-failed', 'start']


def test_a_service_that_still_refuses_after_the_reset_is_reported(env):
    dns._refresh(env.store, fake_systemctl(), env.dir)
    with pytest.raises(RuntimeError, match='could not be started'):
        dns._refresh(env.store, fake_systemctl(refuse=2), env.dir)


def test_wait_for_readiness_grows_with_the_block_list_and_is_capped():
    assert dns.scaled_timeout(0) == 15
    assert dns.scaled_timeout(10 * 1024 * 1024) == 35
    assert dns.scaled_timeout(10 ** 12) == 120
    assert dns.scaled_timeout(-5) == 15


def _daemon_answers_with_nothing(monkeypatch):
    def probe():
        raise dns.UpstreamNotUsable('daemon answers, upstream gives nothing')
    monkeypatch.setattr(dns, 'probe', probe)


def test_unchanged_upstream_and_a_silent_upstream_keep_the_new_valid_rules(env, monkeypatch):
    dns._refresh(env.store, fake_systemctl(), env.dir)
    before = (env.dir / 'blocked.conf').read_text()
    env.extra.add('new-bad.example')
    _daemon_answers_with_nothing(monkeypatch)
    with pytest.raises(dns.UpstreamNotUsable):
        dns._refresh(env.store, fake_systemctl(), env.dir)
    after = (env.dir / 'blocked.conf').read_text()
    assert after != before and 'new-bad.example' in after   # not rolled back


def test_changed_upstream_that_gives_nothing_is_still_rolled_back(env, monkeypatch):
    dns._refresh(env.store, fake_systemctl(), env.dir)
    original = {n: (env.dir / n).read_text() for n in ('dnsmasq.conf', 'blocked.conf')}
    env.state['dns_policy']['upstream'] = '192.0.2.54'
    attempts = []

    def probe():
        attempts.append(1)
        if len(attempts) == 1:
            raise dns.UpstreamNotUsable('typo in the new upstream')
    monkeypatch.setattr(dns, 'probe', probe)
    with pytest.raises(dns.UpstreamNotUsable):
        dns._refresh(env.store, fake_systemctl(), env.dir)
    assert len(attempts) == 2
    assert all((env.dir / n).read_text() == c for n, c in original.items())


def test_refresh_stops_dnsmasq_and_removes_its_configuration(env):
    # 2.2.38 (owner, 2026-11-13): dnsmasq never runs again; its unit needs dnsmasq.conf.
    env.dir.mkdir(parents=True, exist_ok=True)
    for name in ('dnsmasq.conf', 'dnsmasq.conf.sig', 'blocked.conf', 'blocked.conf.sig'):
        (env.dir / name).write_text('x')
    calls = []
    def runner(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    result = dns.refresh(env.store, runner, env.dir)
    assert result['status'] == 'DNSMASQ_RETIRED' and result['ok'] is True
    assert ['/usr/bin/systemctl', 'stop', dns.SERVICE] in calls
    assert not any(c[:2] == ['/usr/bin/systemctl', 'start'] or c[:2] == ['/usr/bin/systemctl', 'restart'] for c in calls)
    assert not list(env.dir.glob('*.conf*'))


def _reply(flags, answers=b'', count=0, ident=7):
    question = b'\x07example\x03com\0' + struct.pack('!HH', 1, 1)
    return struct.pack('!6H', ident, flags, 1, count, 0, 0) + question + answers


def test_readiness_reply_errors_say_whether_the_daemon_answered():
    with pytest.raises(dns_readiness.DaemonAnswered):
        dns_readiness.validate_reply(_reply(0x8182), 7)          # SERVFAIL: it answered
    with pytest.raises(dns_readiness.DaemonAnswered):
        dns_readiness.validate_reply(_reply(0x8180), 7)          # NOERROR but no address
    with pytest.raises(RuntimeError) as other:
        dns_readiness.validate_reply(_reply(0x8180, ident=9), 7)  # someone else's reply
    assert not isinstance(other.value, dns_readiness.DaemonAnswered)


def test_probe_that_times_out_raises_the_matching_error_kind(monkeypatch):
    monkeypatch.setattr(dns.time if hasattr(dns, 'time') else __import__('time'), 'sleep', lambda s: None)
    for raised, kind in ((dns_readiness.DaemonAnswered('x'), dns.UpstreamNotUsable), (OSError('refused'), RuntimeError)):
        def once(error=raised):
            raise error
        monkeypatch.setattr(dns, '_probe_once', once)
        with pytest.raises(kind) as caught:
            dns.probe(timeout=0)
        assert type(caught.value) is kind
