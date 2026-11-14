import pytest
from installer import integrity
from satsuma.early_guard import run_guard
from satsuma.configuration_status import ConfigurationError


@pytest.mark.parametrize('failure,code',[
    (integrity.ApplicationTampered('bytes differ'),'APPLICATION_TAMPERED'),
    (integrity.ApplicationSignatureMismatch('signature differs'),'APPLICATION_TAMPERED'),
    (FileNotFoundError('helper missing'),'INTEGRITY_CHECK_FAILED'),
])
def test_application_failures_are_distinguished_without_unlocking_response(failure,code):
    def fail():raise failure
    result=run_guard(verifier=fail,boot_id='test')
    assert not result['response_unlocked']
    assert result['checks']['application']['status']==code
    assert result['failure_reasons'][0]['code']==code


@pytest.mark.parametrize('code',['POLICY_INVALID','CONFIG_UNSUPPORTED'])
def test_policy_failure_is_not_application_tampering(code):
    def fail():raise ConfigurationError(code,'/fixture/policy','invalid')
    result=run_guard(verifier=lambda:1,config_checker=fail,boot_id='test')
    assert result['checks']['application']['ok']
    assert result['state']==code and not result['response_unlocked']
