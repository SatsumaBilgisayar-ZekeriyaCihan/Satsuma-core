"""Application-scope upgrade and authenticated management regressions."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from installer import boot_setup, integrity, upgrade_setup
from satsuma import aide_support
from satsuma.action_executor import TypedActionExecutor
from satsuma.operator_service import OperatorController
from satsuma.store import Store

SOURCE = Path(__file__).resolve().parents[1]




def test_user_enrollment_never_updates_or_reinitializes_application_baseline(tmp_path, monkeypatch):
    import pwd
    monkeypatch.setattr(pwd, 'getpwnam', lambda _: SimpleNamespace(pw_uid=1000))
    monkeypatch.setattr(boot_setup, 'provision', lambda: None)
    runner = Mock()
    boot_setup.enroll_user('desktop', runner)
    assert runner.call_count == 1
    assert runner.call_args.args[0] == ['/usr/sbin/usermod', '-a', '-G', 'satsuma-reader', 'desktop']


@pytest.mark.parametrize('action', ['file.quarantine', 'file.restore'])
def test_missing_quarantine_is_explicitly_unsupported_without_breaking_network_executor(action):
    executor = TypedActionExecutor(Mock(), response_worker=Mock())
    assert executor.execute(action)['status'] == 'ACTION_UNSUPPORTED'


@pytest.mark.parametrize('status,persisted,linked,success', [
    ('set_membership_confirmed', True, True, True),
    ('set_membership_confirmed', False, True, False),
    ('set_membership_confirmed', True, False, False),
    ('set_membership_confirmed_state_unpersisted', False, True, False),
    ('failed', True, True, False),
])
def test_network_executor_honors_existing_readback_and_persistence_contract(status, persisted, linked, success):
    worker = Mock()
    worker.block_ip.return_value = {'status': status, 'persisted': persisted, 'drop_rule_linked': linked}
    result = TypedActionExecutor(Mock(), response_worker=worker).execute('network.block', {'ip': '8.8.8.8'})
    assert result['ok'] is success


def test_application_management_requires_same_authenticated_uid_and_healthy_boot(tmp_path):
    class Auth:
        def login(self, password, client): return {'ok': True, 'token': 'session'}
        def validate_session(self, token): return token == 'session'
    store = Store(tmp_path / 'store', test=True)
    runner = Mock(return_value=SimpleNamespace(returncode=0, stdout='{"enabled":false}', stderr=''))
    controller = OperatorController(store, auth=Auth(), runner=runner, boot_provider=lambda: {'response_unlocked': False})
    try:
        with pytest.raises(PermissionError):
            controller.dispatch(1000, 'application_control', {'action': 'enable'})
        controller.dispatch(1000, 'login', {})
        with pytest.raises(PermissionError):
            controller.dispatch(1001, 'application_control', {'token': 'session', 'action': 'status'})
        with pytest.raises(RuntimeError):
            controller.dispatch(1000, 'application_control', {'token': 'session', 'action': 'enable'})
        assert runner.call_count == 0
        from unittest.mock import patch
        with patch('satsuma.app_firewall.control', return_value={'status':'DISABLED','enabled':False}) as control:
            result = controller.dispatch(1000, 'application_control', {'token': 'session', 'action': 'status'})
            assert result['application_control']['enabled'] is False
            control.assert_called_once_with('status', {})
        with pytest.raises(ValueError):
            controller.dispatch(1000, 'application_control', {'token': 'session', 'action': 'revoke'})
    finally:
        store.close()




@pytest.mark.parametrize('unit', ['gnome-user-share.service', 'rygel.service', 'vsftpd.service', 'wsdd.service', 'minidlna.service'])
def test_additional_file_shares_are_contained_without_targeting_vendor_clients(unit):
    from installer.remote_containment import server_unit
    assert server_unit(unit)
    assert not server_unit('anydesk.service')
    assert not server_unit('teamviewerd.service')
