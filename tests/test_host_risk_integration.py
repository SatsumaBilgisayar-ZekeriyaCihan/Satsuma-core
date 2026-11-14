import json
from types import SimpleNamespace
from satsuma.host_risk_integration import parse_advisories, collect_risk, python_findings, ADVISORY_COMMAND


def test_cached_advisory_matches_installed_name_not_new_name():
    data = [{'name': 'FEDORA-2026-ab12', 'type': 'security', 'severity': 'Important',
             'nevra': 'python3-pip-0:25.0-1.fc45.noarch'},
            {'name': 'FEDORA-2026-ab14', 'type': 'bugfix', 'severity': 'Low',
             'nevra': 'python3-pip-0:25.0-1.fc45.noarch'},
            {'name': 'FEDORA-2026-ab16', 'type': 'security', 'severity': 'Critical',
             'nevra': 'uninstalled-1-2.x86_64'}]
    found = parse_advisories(json.dumps(data), ['python3', 'python3-pip'])
    assert len(found) == 1
    assert found[0]['package'] == 'python3-pip'
    assert found[0]['interpretation'] == 'cached_security_update_candidate'


def test_reject_invalid_advisory_payload():
    for payload in ['{}', 'null', '"bad"']:
        try:
            parse_advisories(payload, ['test'])
        except ValueError:
            pass
        else:
            assert False


def test_run_only_cacheonly_and_no_network_switches():
    def runner(argv, **kw):
        assert argv == ADVISORY_COMMAND
        assert '--cacheonly' in argv and '--refresh' not in argv
        assert kw['timeout'] == 8 and kw['check'] is False
        return SimpleNamespace(returncode=0, stdout='[]')
    result = collect_risk(['a'], runner=runner)
    assert result['advisories']['status'] == 'CACHE_OBSERVED'
    assert result['assurances']['mutations'] is False
    assert result['python_audit']['status'] == 'NOT_SCANNED'


def test_no_silent_success_if_dnf_missing():
    def runner(argv, **kw):
        raise FileNotFoundError('dnf5')
    result = collect_risk(['a'], runner=runner)
    assert result['advisories']['status'] == 'UNAVAILABLE'


def test_python_state_redacts_source_text_and_credentials():
    state = {'updated_at': 123, 'modified': ['/opt/a.py'], 'items': [
        {'path': '/tmp/test.py', 'points': 5,
         'hits': [{'rule': 'download_exec', 'text': 'SECRET PASSWORD'}],
         'virustotal': {'api_key': 'SECRET'}}]}
    result = python_findings(state)
    assert result['items'][0]['rules'] == ['download_exec']
    assert 'SECRET' not in json.dumps(result)


def test_bad_python_state_does_not_crash():
    assert python_findings(None)['status'] == 'NOT_SCANNED'


def test_dashboard_api_integrates_cached_evidence(monkeypatch):
    from satsuma import dashboard_api
    from satsuma import host_provenance, host_risk_integration
    from contextlib import contextmanager
    data = {'deployments': [], 'script_exposure': [], 'unit_entrypoints': [],
            'errors': {}, 'packages': {'names': ['python3-pip'], 'count_observed': 1},
            'os_release': {'PRETTY_NAME': 'Fedora Test'}, 'mode': 'rpm-ostree'}
    monkeypatch.setattr(host_provenance, 'collect', lambda: data.copy())
    @contextmanager
    def fake_db():
        yield object()
    monkeypatch.setattr(dashboard_api, '_connect_host', fake_db)
    monkeypatch.setattr(dashboard_api, '_state', lambda *args: {'updated_at': 123, 'items': [
        {'path': '/opt/test.py', 'points': 4, 'hits': [{'rule': 'download_exec', 'text': 'HIDDEN'}]}]})
    def fake_runner(argv, **kwargs):
        return SimpleNamespace(returncode=0, stdout=json.dumps([{'name': 'FEDORA-2026-aa12',
            'type': 'security', 'severity': 'Important',
            'nevra': 'python3-pip-0:25.0-1.fc45.noarch'}]))
    def fake_collect(installed_names, state):
        return collect_risk(installed_names, state=state, runner=fake_runner)
    monkeypatch.setattr(host_risk_integration, 'collect_risk', fake_collect)
    result = dashboard_api.m_host_provenance()
    assert any(row['kind'] == 'Fedora guvenlik guncellemesi' for row in result['items'])
    assert any(row['kind'] == 'Python sezgisel bulgu' for row in result['items'])
    assert 'HIDDEN' not in json.dumps(result)
    assert result['data_state'] == 'OK'
