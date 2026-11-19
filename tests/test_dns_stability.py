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
    env.state['dns_filter_restarted_at'] = 0  # 2.2.51: a full reload only after the 30-minute window
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
    env.state['dns_filter_restarted_at'] = 0  # 2.2.51: the full reload path
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


def test_refresh_runs_dnsmasq_again_and_pins_the_upstream_to_opendns(env, monkeypatch):
    # 2.2.44 (owner, 2026-11-13): dnsmasq is back in its own namespace; the host
    # forwards its queries only to OpenDNS, so another upstream is replaced.
    env.dir.chmod(0o750)
    seen = []
    monkeypatch.setattr(dns, '_refresh', lambda store, runner, directory: seen.append(dict(store.get('dns_policy'))) or {'status': 'configured'})
    assert dns.refresh(env.store, fake_systemctl(), env.dir)['status'] == 'configured'
    assert seen[0]['upstream'] == '208.67.222.222' and seen[0]['previous_upstream'] == '192.0.2.53'
    env.state['dns_policy'] = {'enabled': True, 'upstream': '208.67.220.220'}
    dns.refresh(env.store, fake_systemctl(), env.dir)
    assert seen[1]['upstream'] == '208.67.220.220' and 'previous_upstream' not in seen[1]


def test_generated_config_listens_only_in_the_namespace(env):
    dns._refresh(env.store, fake_systemctl(), env.dir)
    config = (env.dir / 'dnsmasq.conf').read_text()
    assert 'listen-address=169.254.53.2\n' in config and 'port=53\n' in config
    assert '127.0.0.1' not in config and '53053' not in config and 'bind-interfaces' in config


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


# -- 2.2.51: a newly blocked name is applied without a restart (no DNS gap)

def hot_runner(active=True):
    runner = fake_systemctl(active=active)
    inner = runner

    def wrapped(args, **kwargs):
        if args[1] == 'show':
            inner.calls.append(args[1:])
            return SimpleNamespace(returncode=0, stdout='4242\n', stderr='')
        return inner(args, **kwargs)
    wrapped.calls = inner.calls
    return wrapped


def test_a_new_name_is_hot_added_with_sighup_not_a_restart(env, monkeypatch):
    dns._refresh(env.store, fake_systemctl(), env.dir)
    assert 'addn-hosts=' + str(env.dir / 'added.hosts') in (env.dir / 'dnsmasq.conf').read_text()
    assert (env.dir / 'added.hosts').read_text() == ''
    signals = []
    monkeypatch.setattr(dns.os, 'kill', lambda pid, sig: signals.append((pid, sig)))
    monkeypatch.setattr(dns.os, 'readlink', lambda path: '/usr/sbin/dnsmasq')
    env.extra.add('new-bad.example')
    runner = hot_runner()
    assert dns._refresh(env.store, runner, env.dir)['status'] == 'hot_added'
    assert (env.dir / 'added.hosts').read_text() == '0.0.0.0 new-bad.example\n:: new-bad.example\n'
    assert 'new-bad.example' not in (env.dir / 'blocked.conf').read_text()
    assert not any(c[0] == 'restart' for c in runner.calls)
    import signal
    assert signals == [(4242, signal.SIGHUP)]
    # The next minute changes nothing and sends nothing.
    again = hot_runner()
    assert dns._refresh(env.store, again, env.dir)['status'] == 'unchanged' and len(signals) == 1
    # After the window the full list (with subdomains) is loaded once and added.hosts is emptied.
    env.state['dns_filter_restarted_at'] = 0
    full = hot_runner()
    assert dns._refresh(env.store, full, env.dir)['status'] == 'configured'
    assert 'address=/new-bad.example/#' in (env.dir / 'blocked.conf').read_text()
    assert (env.dir / 'added.hosts').read_text() == ''


def test_sighup_goes_only_to_the_real_dnsmasq(env, monkeypatch):
    signals = []
    monkeypatch.setattr(dns.os, 'kill', lambda pid, sig: signals.append(pid))
    monkeypatch.setattr(dns.os, 'readlink', lambda path: '/usr/bin/bash')
    assert dns.reload_hosts(hot_runner()) is False and signals == []
    none = lambda args, **k: SimpleNamespace(returncode=0, stdout='0\n', stderr='')
    assert dns.reload_hosts(none) is False


def test_a_failed_reload_is_reported(env, monkeypatch):
    dns._refresh(env.store, fake_systemctl(), env.dir)
    monkeypatch.setattr(dns.os, 'readlink', lambda path: '/usr/bin/bash')
    env.extra.add('new-bad.example')
    with pytest.raises(RuntimeError, match='re-read the added names'):
        dns._refresh(env.store, hot_runner(), env.dir)


def test_an_allowed_name_leaves_added_hosts_at_once(env, monkeypatch):
    dns._refresh(env.store, fake_systemctl(), env.dir)
    monkeypatch.setattr(dns.os, 'kill', lambda pid, sig: None)
    monkeypatch.setattr(dns.os, 'readlink', lambda path: '/usr/sbin/dnsmasq')
    env.extra.update({'a-bad.example', 'b-bad.example'})
    dns._refresh(env.store, hot_runner(), env.dir)
    env.state['dns_allowed_domains'] = ['a-bad.example']
    assert dns._refresh(env.store, hot_runner(), env.dir)['status'] == 'hot_added'
    assert 'a-bad.example' not in (env.dir / 'added.hosts').read_text()
    assert 'b-bad.example' in (env.dir / 'added.hosts').read_text()


def test_added_hosts_lists_only_new_names():
    old = 'address=/a.example/#\nlocal=/a.example/\n'
    new = old + 'address=/b.example/#\nlocal=/b.example/\n'
    assert dns.added_hosts(old, new) == ('0.0.0.0 b.example\n:: b.example\n', 1)
    assert dns.added_hosts(new, old) == ('', 0)
