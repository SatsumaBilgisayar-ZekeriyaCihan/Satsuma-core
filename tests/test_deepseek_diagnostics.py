"""DeepSeek errors name their real cause (2.2.18).

DeepSeek hataları gerçek sebebini söyler (2.2.18): anahtar izni, oturum, sınır.
"""
import os
from pathlib import Path

import pytest

from satsuma import deepseek_client as client
from satsuma import deepseek_workflow as workflow
from satsuma.dashboard_qt.panels import deepseek as panel

root_only = pytest.mark.skipif(os.geteuid() != 0, reason='key checks run as root like the backend')


@root_only
@pytest.mark.parametrize('mode,expected', [(0o644, 'key_mode_must_be_0600'), (0o600, None)])
def test_key_problem_names_the_mode(tmp_path, monkeypatch, mode, expected):
    key = tmp_path / 'deepseek.key'
    key.write_text('sk-' + 'a' * 32 + '\n')
    os.chown(key, 0, 0)
    os.chmod(key, mode)
    monkeypatch.setattr(client, 'KEY_PATH', key)
    assert client.key_problem() == expected


@root_only
def test_key_problem_missing_link_and_content(tmp_path, monkeypatch):
    key = tmp_path / 'deepseek.key'
    monkeypatch.setattr(client, 'KEY_PATH', key)
    assert client.key_problem() == 'key_file_missing'
    real = tmp_path / 'real.key'
    real.write_text('sk-x\n'); os.chmod(real, 0o600)
    key.symlink_to(real)
    assert client.key_problem() == 'key_not_regular_file'
    key.unlink(); key.write_text('two words\n'); os.chmod(key, 0o600)
    assert client.key_problem() == 'key_content_invalid'


def test_workflow_keeps_own_codes_and_hides_other_text():
    assert workflow._code(ValueError('api_rate_limit_8_per_hour_10_second_spacing')) == 'api_rate_limit_8_per_hour_10_second_spacing'
    assert workflow._code(OSError('[Errno 2] /etc/secret path')) == 'operation_preconditions_failed'


def test_panel_explains_codes_and_detects_expired_session():
    assert 'chmod 600' in panel.explain('key_mode_must_be_0600')
    assert panel.explain('something new') == 'something new'
    assert panel.session_expired('Yönetici oturumu gerekli / süresi doldu')
    assert not panel.session_expired('request_timeout')


def test_panel_no_longer_hides_backend_errors():
    source = Path(panel.__file__).read_text()
    assert 'Yetkili arka uca erişilemedi veya işlem reddedildi' not in source


def test_rate_limit_is_configurable_and_failed_requests_do_not_count(tmp_path):
    import json
    import time
    from satsuma.store import Store
    store = Store(tmp_path / 'data', test=True)
    try:
        store.db.execute('CREATE TABLE deepseek_requests (uid INTEGER, request_id TEXT, request_hash TEXT, method TEXT, '
                         'created REAL, result TEXT, PRIMARY KEY(uid,request_id))')
        now = time.time() - 100
        rows = [(1, 'a', 'h', 'deepseek_generate', now, json.dumps({'ok': False, 'error': 'request_timeout'})),
                (1, 'b', 'h', 'deepseek_generate', now, json.dumps({'ok': True})),
                (1, 'c', 'h', 'deepseek_generate', now, None)]
        store.db.executemany('INSERT INTO deepseek_requests VALUES(?,?,?,?,?,?)', rows)
        store.db.commit()
        assert workflow._recent_network_requests(store)[0] == 2  # the timeout is not counted
        status = workflow._perform(store, 1, 'deepseek_status', {}, {'deepseek_requests_per_hour': 3})
        assert status['network_requests_per_hour'] == 3 and status['network_requests_left_this_hour'] == 1
        assert workflow._limit({}) == 60 and workflow._limit({'deepseek_requests_per_hour': 0}) == 60
    finally:
        store.close()


def test_panel_names_the_failing_case_and_the_and_rule():
    import json
    from satsuma import ai_rule_package as pkg
    field = json.loads((Path(__file__).parent / 'fixtures/deepseek-field-revshell-20261104.json').read_text())
    report = pkg.test_package(field)  # nc -e has no cmd_arg_contains match: AND fails
    assert panel.failed_cases({'test_report': report}) == 'olumlu örnek 2 yakalanmadı'
    field['detection']['base_match']['cmd_arg_contains'] += ['/bin/sh', '/bin/bash']
    field['response_proposal'].pop('detection_sha256')
    assert pkg.test_package(pkg.bind_detection_digest(field))['passed']


def test_a_rejected_rule_can_be_resubmitted_and_leaves_the_list(tmp_path):
    import copy
    import json
    from satsuma import ai_rule_package as pkg, rule_adapter as adapter
    from satsuma.store import Store
    field = json.loads((Path(__file__).parent / 'fixtures/deepseek-field-revshell-20261104.json').read_text())
    field['detection']['base_match']['cmd_arg_contains'] += ['/bin/sh', '/bin/bash']
    field['response_proposal'].pop('detection_sha256')
    package = pkg.bind_detection_digest(field)
    store = Store(tmp_path / 'data', test=True)
    try:
        assert adapter.queue_package(store, package, authorized=True, reviewer=1000)['queued']
        assert adapter.queue_package(store, package, authorized=True)['error'] == 'identical_rule_already_present'
        assert adapter.reject_rule(store, package['rule_id'], authorized=True, reviewer=1000, reason='Yalıtılmış testte yetersiz bulundu')['rejected']
        assert [r['rule_id'] for r in adapter.list_rules(store)] == []
        again = copy.deepcopy(package)
        assert adapter.queue_package(store, again, authorized=True, reviewer=1000)['queued']
        assert [r['status'] for r in adapter.list_rules(store)] == ['pending_review']
        operations = [r[0] for r in store.db.execute('SELECT operation FROM rule_adapter_history ORDER BY rowid')]
        assert operations[-2:] == ['reject', 'resubmit_after_reject']
    finally:
        store.close()


def test_the_approval_envelope_is_unwrapped_to_its_package(tmp_path):
    import json
    from satsuma.store import Store
    field = json.loads((Path(__file__).parent / 'fixtures/deepseek-field-revshell-20261104.json').read_text())
    field['detection']['base_match']['cmd_arg_contains'] += ['/bin/sh', '/bin/bash']
    field['response_proposal'].pop('detection_sha256')
    envelope = {'approval': {'operator_uid': 1000, 'reviewed_at': 1.0, 'package_sha256': 'x'}, 'package': field}
    store = Store(tmp_path / 'data', test=True)
    try:
        result = workflow._perform(store, 1000, 'deepseek_test_rule', {'package': envelope}, {})
        assert result['test_report']['passed'] is True, result
    finally:
        store.close()
