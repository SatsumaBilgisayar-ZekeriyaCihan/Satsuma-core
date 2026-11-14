from installer import dns_setup
import pytest


def test_uses_existing_resolver_and_excludes_stub(tmp_path):
    path=tmp_path/'resolv.conf';path.write_text('nameserver 127.0.0.53\nnameserver 192.0.2.53\n')
    assert dns_setup.existing_resolver([path])=='192.0.2.53'
    path.write_text('nameserver 127.0.0.53\n')
    with pytest.raises(RuntimeError):dns_setup.existing_resolver([path])


@pytest.mark.parametrize('policy,expected',[({},True),({'enabled':False},False),({'enabled':True,'upstream':'192.0.2.54'},True)])
def test_install_preserves_operator_choice(policy,expected):
    class Store:
        def get(self,key,default=None):return policy
        def set(self,key,value):policy.update(value)
    calls=[]
    dns_setup.configure(Store(),resolver=lambda:'192.0.2.53',refresh=lambda store:calls.append(True))
    assert bool(calls)==expected
    assert policy['enabled']==expected
