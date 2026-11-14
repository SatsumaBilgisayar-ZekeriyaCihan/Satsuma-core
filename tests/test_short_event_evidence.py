from satsuma.short_event_evidence import ShortEvidenceWindow


def event(pid=9, starttime=100, source='audit', ident='e1', **kwargs):
    return {'id': ident, 'pid': pid, 'starttime': starttime, 'source': source,
            'kind': 'exec', 'cmd': 'sensitive secret', **kwargs}


def test_bounded_short_window_and_source_count():
    now = [1.0]
    w = ShortEvidenceWindow(window_seconds=2, max_events=2, clock=lambda: now[0])
    first = w.observe(event())
    assert first['event_count'] == 1
    now[0] += 0.1
    second = w.observe(event(source='sys_proc', ident='e2'))
    assert second['event_count'] == 2 and second['independent_sources'] == 2
    assert 'sensitive' not in str(second)
    now[0] += 0.1
    third = w.observe(event(ident='e3'))
    assert third['event_count'] == 2
    assert [e['id'] for e in third['events']] == ['e2', 'e3']


def test_pid_reuse_kept_separate_and_no_identity_rejected():
    w = ShortEvidenceWindow()
    assert w.observe(event(starttime=0)) is None
    assert w.observe(event(pid=-1)) is None
    assert w.observe(event(pid=8, starttime=1))['event_count'] == 1
    assert w.observe(event(pid=8, starttime=2))['event_count'] == 1
    assert w.health()['rejected'] == 2


def test_monotonic_expiry_and_process_cap():
    now = [0.0]
    w = ShortEvidenceWindow(window_seconds=1, max_processes=1, clock=lambda: now[0])
    w.observe(event(pid=1))
    w.observe(event(pid=2))
    assert w.health()['groups'] == 1 and w.health()['evictions'] == 1
    now[0] = 2.0
    assert w.observe(event(pid=2))['event_count'] == 1


def test_untrusted_payload_cannot_change_window_or_control_result():
    w = ShortEvidenceWindow()
    result = w.observe(event(source='audit', ident='e1', classification='confirmed',
                             actions=['kill_process'], timestamp='2099-01-01'))
    assert set(result) == {'pid', 'starttime', 'window_seconds', 'event_count',
                           'independent_sources', 'events'}
    assert 'actions' not in str(result) and 'confirmed' not in str(result)


def test_invalid_bounds_fail_closed():
    import pytest
    with pytest.raises(ValueError):
        ShortEvidenceWindow(window_seconds=0)
    with pytest.raises(ValueError):
        ShortEvidenceWindow(max_events=1000)


def test_flow_finding_receives_short_evidence_without_new_termination(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace
    from satsuma.flow import ProcessFlow, FlowReceiver
    from satsuma.pipeline import Pipeline
    from satsuma.store import Store
    import run_satsuma_teams as brain

    store = Store(tmp_path, test=True)
    pipeline = Pipeline(store, {'response_enabled': False})
    receiver = FlowReceiver(path=tmp_path / 'unused.sock')
    pipeline.flow_sink = receiver.put
    pipeline._self = SimpleNamespace(is_own=lambda raw: False, health=lambda: {})
    called = []
    for name in ('_dispatch_safe_actions', '_automatic_actions', '_sudo_autoblock', '_confirmed_actions'):
        monkeypatch.setattr(brain, name, lambda *args, _name=name, **kwargs: called.append(_name))

    class Match:
        def match(self, ev):
            return [{'classification': 'suspicious', 'severity': 'high',
                     'rule_id': 'TEST-31-' + str(ev['source']), 'event': {'pid': ev['pid'], 'starttime': ev['starttime']}}]

    for source in ('audit', 'sys_proc'):
        receiver.put({'raw_id': 'id-' + source,
                      'event': {'source': {'type': source},
                                'event': {'action': 'exec'},
                                'raw': {'data': {'pid': 123, 'starttime': 444, 'kind': 'exec'}}}})
    brain._flow_tick(store, {'investigation_enabled': False}, pipeline, Match(),
                     ProcessFlow(), receiver, short_window=ShortEvidenceWindow())
    records = [json.loads(body)['metadata']['finding'] for (body,) in store.db.execute(
        "SELECT body FROM records WHERE kind='events' AND json_extract(body,'$.event.category')='finding'")]
    assert records
    assert any(row.get('short_evidence', {}).get('independent_sources') == 2 for row in records)
    assert '_confirmed_actions' in called
    store.close()
