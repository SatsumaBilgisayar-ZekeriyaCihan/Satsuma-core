"""bootc's temporary self-copy is recognised only with audit evidence of the same process (2.2.45).

bootc'nin geçici kopyası yalnızca aynı sürecin denetim kanıtıyla tanınır.
"""
import copy

from satsuma import self_copy

FIELD = {  # field report 2026-11-18, trimmed
    'rule_id': 'SATSUMA-FILELESS-002', 'rule_name': "Fileless — /dev/shm veya /tmp'den yürütme",
    'classification': 'suspicious', 'severity': 'high',
    'event': {'exe': '/tmp/.tmpR0JZc2', 'cmd': 'bootc status --format=json --format-version=1', 'pid': '14573', 'uid': '0'},
    'flow': {'chain': [
        {'pid': '14573', 'events': [
            {'action': 'syscall'},
            {'action': 'execve', 'cmd': '/usr/bin/bootc status --format=json --format-version=1'},
            {'action': 'file_access', 'path': '/usr/bin/bootc'},
            {'action': 'file_access', 'path': '/lib64/ld-linux-x86-64.so.2'},
            {'action': 'execve', 'cmd': 'bootc status --format=json --format-version=1'}]},
        {'pid': '6242', 'exe': '/usr/bin/python3.15', 'events': []}]},
}
TRUSTED = lambda path: path == '/usr/bin/bootc'


def test_field_case_is_recognised_and_not_recorded():
    finding = self_copy.apply(copy.deepcopy(FIELD), trusted=TRUSTED)
    assert finding['self_copy']['packaged'] == '/usr/bin/bootc'
    assert finding['log_only'] is True and finding['classification'] == 'indicator'
    assert finding['original_severity'] == 'high' and 'bootc kendi geçici kopyasından' in finding['rule_name']


def test_without_the_earlier_exec_of_the_packaged_tool_it_stays_a_finding():
    finding = copy.deepcopy(FIELD)
    finding['flow']['chain'][0]['events'] = finding['flow']['chain'][0]['events'][-1:]
    assert self_copy.apply(finding, trusted=TRUSTED)['classification'] == 'suspicious'


def test_other_arguments_other_names_other_users_and_untrusted_tools_stay_findings():
    cases = []
    changed = copy.deepcopy(FIELD); changed['event']['cmd'] = 'bootc upgrade --apply'; cases.append(changed)
    renamed = copy.deepcopy(FIELD); renamed['event']['exe'] = '/tmp/payload'; cases.append(renamed)
    user = copy.deepcopy(FIELD); user['event']['uid'] = '1000'; cases.append(user)
    shell = copy.deepcopy(FIELD); shell['event']['cmd'] = 'bash -c x'; cases.append(shell)
    for finding in cases:
        assert self_copy.recognize(finding, trusted=TRUSTED) is None
    assert self_copy.recognize(copy.deepcopy(FIELD), trusted=lambda path: False) is None
    other_rule = copy.deepcopy(FIELD); other_rule['rule_id'] = 'RAM-001'
    assert self_copy.recognize(other_rule, trusted=TRUSTED) is None


def test_reader_collects_provenance_at_most_every_ten_minutes(monkeypatch):
    from satsuma import dashboard_api as api
    calls = []
    monkeypatch.setattr(api, '_m_host_provenance', lambda: calls.append(1) or {'mode': 'bootc'})
    monkeypatch.setattr(api, '_PROVENANCE', {'at': 0.0, 'data': None})
    assert api.m_host_provenance()['mode'] == 'bootc'
    api.m_host_provenance(); api.m_host_provenance()
    assert len(calls) == 1


def test_provenance_page_does_not_poll():
    from pathlib import Path
    text = (Path(__file__).parents[1] / 'satsuma/dashboard_qt/panels/host_provenance.py').read_text()
    assert 'REFRESH_MS = 0' in text


def test_flow_tick_drops_the_verified_copy_but_keeps_an_unexplained_one(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace as NS
    from satsuma import flow as F
    from satsuma.pipeline import Pipeline
    from satsuma.smart_rules import SmartRuleEngine
    from satsuma.store import Store
    import run_satsuma_teams as T
    monkeypatch.setattr(self_copy, 'trusted_path', TRUSTED)
    for name in ('_dispatch_safe_actions', '_automatic_actions', '_sudo_autoblock', '_confirmed_actions'):
        monkeypatch.setattr(T, name, lambda *a, **k: None)

    def run(events):
        store = Store(tmp_path / str(len(events)), test=True)
        flow, receiver = F.ProcessFlow(), F.FlowReceiver(path=tmp_path / ('s%d' % len(events)))
        pipeline = Pipeline(store, {'response_enabled': False})
        pipeline.flow_sink = receiver.put
        pipeline._self = NS(is_own=lambda raw: False, health=lambda: {})
        for event in events:
            pipeline.ingest_host({'source': 'audit', 'pid': '14573', 'ppid': '6242', 'uid': '0', 'starttime': None, **event})
        T._flow_tick(store, {'investigation_enabled': False}, pipeline, SmartRuleEngine(), flow, receiver)
        return [json.loads(b)['metadata']['finding'].get('rule_id') for (b,) in store.db.execute(
            "select body from records where kind='events' and json_extract(body,'$.event.category')='finding'")]

    copy_exec = {'action': 'execve', 'exe': '/tmp/.tmpR0JZc2', 'cmd': 'bootc status --format=json --format-version=1'}
    alone = run([copy_exec])
    assert 'SATSUMA-FILELESS-002' in alone
    verified = run([{'action': 'execve', 'exe': '/usr/bin/bootc', 'cmd': '/usr/bin/bootc status --format=json --format-version=1'},
                    {'action': 'file_access', 'path': '/usr/bin/bootc', 'exe': '/usr/bin/bootc'},
                    copy_exec])
    assert 'SATSUMA-FILELESS-002' not in verified
