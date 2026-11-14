from tools_onaccess_service_contract import inspect

def test_service_contract_reports_known_permission_blocker():
    state = inspect()
    assert state['ready_for_verified_quarantine'] is False
    assert any('ProtectHome=read-only' in issue for issue in state['issues'])
