import json
from types import SimpleNamespace as NS
import pytest
from satsuma import vpn_proxy as vp


def inventory_runner(args,**kw):
    if args[0].endswith('/ip'):
        return NS(returncode=0,stdout=json.dumps([{'ifname':'wg0','flags':['UP'],'linkinfo':{'info_kind':'wireguard'}},
                                                 {'ifname':'eth0','flags':['UP']}]))
    return NS(returncode=0,stdout='12345678-1234-1234-1234-123456789abc:wireguard\n')


def test_detector_distinguishes_indicators_and_never_exposes_proxy_secrets():
    processes=[NS(info={'pid':42,'exe':'/usr/bin/tor','create_time':12}),
               NS(info={'pid':43,'exe':'/usr/bin/browser','create_time':12})]
    value=vp.detect(inventory_runner,processes,{'HTTPS_PROXY':'https://user:secret@proxy.example'})
    assert not value['errors'] and len(value['items'])==4
    assert 'secret' not in json.dumps(value) and 'proxy.example' not in json.dumps(value)
    assert value['automatic_blocking'] is False


def test_disconnect_requires_explicit_confirmation_and_current_target():
    def no_commands(*a,**kw):pytest.fail('no commands before confirmation')
    with pytest.raises(ValueError,match='onay'):vp.disconnect('x',False,runner=no_commands)
    with pytest.raises(ValueError,match='Hedef değişti'):
        vp.disconnect('x',True,detector=lambda **kw:{'items':[]})


def test_managed_vpn_disconnect_checks_readback():
    item={'id':'fixture','kind':'managed_vpn','uuid':'12345678-1234-1234-1234-123456789abc','blockable':True}
    reads=iter([{'items':[item]},{'items':[]}]);calls=[]
    def run(args,**kw):calls.append(args);return NS(returncode=0)
    result=vp.disconnect('fixture',True,runner=run,detector=lambda **kw:next(reads))
    assert result['status']=='DISCONNECTED' and not result['persistent_block']
    assert calls==[['/usr/bin/nmcli','connection','down','uuid',item['uuid']]]
    with pytest.raises(RuntimeError,match='hâlâ etkin'):
        vp.disconnect('fixture',True,runner=run,detector=lambda **kw:{'items':[item]})


def test_reused_pid_cannot_receive_signal(monkeypatch):
    import psutil
    item={'id':'fixture','kind':'proxy_process','pid':42,'executable':'/usr/bin/tor',
          'created_at':1,'blockable':True}
    monkeypatch.setattr(psutil,'Process',lambda pid:NS(create_time=lambda:2,
        terminate=lambda:pytest.fail('reused PID must never receive a signal')))
    with pytest.raises(ValueError,match='kimliği değişti'):
        vp.disconnect('fixture',True,detector=lambda **kw:{'items':[item]})


def test_operator_requires_peer_bound_session_before_vpn_action(tmp_path):
    from satsuma.operator_service import OperatorController
    class Auth:
        def validate_session(self,token):return token=='valid'
    controller=OperatorController(NS(),auth=Auth(),boot_provider=lambda:{'response_unlocked':True})
    with pytest.raises(PermissionError):controller.dispatch(1000,'vpn_proxy_disconnect',{'confirmed':True,'token':'valid'})


def test_valid_session_for_another_peer_cannot_disconnect():
    from satsuma.operator_service import OperatorController
    class Auth:
        def validate_session(self,token):return True
    controller=OperatorController(NS(),auth=Auth())
    controller.owners['valid']=1001
    with pytest.raises(PermissionError):controller.dispatch(1000,'vpn_proxy_disconnect',{'confirmed':True,'token':'valid'})
