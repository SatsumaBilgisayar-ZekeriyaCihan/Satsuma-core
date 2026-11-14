import json
from types import SimpleNamespace

import pytest
from satsuma import application_control as app


def policy():
    return {'schema':1,'enabled':True,'grants':{'browser.service':{'sha256':'a'*64,'access':['https']}}}


@pytest.mark.parametrize('mutate', [
    lambda p:p.update(schema=True),
    lambda p:p['grants'].update({'user.slice':p['grants'].pop('browser.service')}),
    lambda p:p['grants']['browser.service'].update(sha256='short'),
    lambda p:p['grants']['browser.service'].update(access=['all']),
    lambda p:p['grants']['browser.service'].update(access=['dns','dns']),
    lambda p:p['grants']['browser.service'].update(access=[]),
])
def test_invalid_grant_rejected(mutate):
    p=policy();mutate(p)
    with pytest.raises(ValueError):app.validate_policy(p)


def test_explicit_service_policy():
    assert app.validate_policy(policy())==policy()


def test_empty_rules_have_no_external_accept():
    text=app.render([])
    assert text.count('accept')==0 and 'oifname "lo" accept' not in text
    assert text.count('policy drop')==2 and 'established' not in text


def test_permissions_remain_port_scoped():
    grant={'unit':'browser.service','path':'system.slice/browser.service','inode':91234,'access':['https']}
    text=app.render([grant])
    assert 'socket cgroupv2 level 2 "system.slice/browser.service" tcp dport 443' in text
    assert 'dport 53' not in text and 'udp dport 443' not in text
    assert 'priority -5' in text and 'queue' not in text


def test_a_dns_grant_allows_port_53_only_and_nothing_on_loopback():
    # 2.2.38: dnsmasq's 53053 and its loopback exceptions are gone.
    grants=[{'path':'system.slice/dns.service','inode':1234,'access':['dns']}]
    text=app.render(grants)
    assert app.valid_layout(text,grants)
    assert '53053' not in text and 'oifname "lo"' not in text and '127.0.0.1' not in text
    assert app.PORTS['dns']==[('tcp',53),('udp',53)]


def fixture():
    # Independent nft text shape, with live counter statistics.
    return '''table inet satsuma_apps {
        comment "Satsuma application egress"
        chain output {
            type filter hook output priority -5; policy drop;
            counter packets 10 bytes 234 drop
        }
        chain forward {
            type filter hook forward priority -5; policy drop;
            counter packets 0 bytes 0 drop
        }
    }
'''


@pytest.mark.parametrize('mutate',[
    lambda d:d.replace('policy drop','policy accept'),
    lambda d:d.replace('chain output {','chain output {\noifname "lo" accept'),
    lambda d:d.replace('chain output {','chain hidden {}\nchain output {'),
    lambda d:d.replace('chain output {','flowtable bypass {}\nchain output {'),
    lambda d:d.replace('Satsuma application egress','foreign'),
])
def test_readback_rejects_extra_or_weakened_policy(mutate):
    data=fixture()
    assert app.valid_layout(data,[])
    assert not app.valid_layout(mutate(data),[])


def test_atomic_apply_and_readback():
    calls=[]
    def runner(args,**kw):
        calls.append((args,kw))
        result=json.dumps({'nftables':[]}) if args[-1]=='tables' else fixture()
        return SimpleNamespace(returncode=0,stdout=result,stderr='')
    app.apply([],runner)
    assert sum(bool(kw.get('input')) for _,kw in calls)==2  # check then commit


def test_corrupt_policy_revokes_previous_grants(monkeypatch):
    calls=[]
    def broken():raise ValueError('signature mismatch')
    monkeypatch.setattr(app,'load_policy',broken)
    monkeypatch.setattr(app,'apply',lambda grants:calls.append(grants))
    with pytest.raises(ValueError):app.sync()
    assert calls==[[]]


def test_dead_or_changed_service_not_authorized(monkeypatch):
    monkeypatch.setattr(app,'load_policy',policy)
    def changed(*a):raise ValueError('executable changed')
    monkeypatch.setattr(app,'resolve_grant',changed)
    calls=[]
    monkeypatch.setattr(app,'apply',lambda grants:calls.append(grants))
    monkeypatch.setattr(app.RootDataStore,'replace',lambda *a:None)
    status=app.sync()
    assert calls==[[]] and 'browser.service' in status['denied_grants']


@pytest.mark.parametrize('props',[
    'Id=browser.service\nActiveState=inactive\n',
    'Id=browser.service\nActiveState=active\nControlGroup=/user.slice/browser.service\nDelegate=no',
    'Id=browser.service\nActiveState=active\nControlGroup=/system.slice/browser.service\nDelegate=yes',
])
def test_untrusted_service_group_is_rejected(props):
    runner=lambda args:SimpleNamespace(returncode=0,stdout=props)
    with pytest.raises(ValueError):app.resolve_grant('browser.service',policy()['grants']['browser.service'],runner)


def test_policy_is_authenticated_as_one_atomic_record(tmp_path,monkeypatch):
    from installer import integrity
    path=tmp_path/'policy.json'
    monkeypatch.setattr(app,'POLICY',path)
    monkeypatch.setattr(integrity,'read_key',lambda:b'x'*32)
    monkeypatch.setattr(app,'secure_read',lambda p:p.read_bytes())
    monkeypatch.setattr(app.RootDataStore,'replace',lambda self,obj:path.write_text(json.dumps(obj)))
    app.save_policy(policy())
    assert app.load_policy()==policy()
    envelope=json.loads(path.read_text())
    envelope['policy']['grants']['browser.service']['access'].append('dns')
    path.write_text(json.dumps(envelope))
    with pytest.raises(ValueError,match='authentication'):app.load_policy()


def test_failed_deny_recovery_activates_emergency_lockdown(monkeypatch):
    from satsuma import network_control
    def corrupt():raise ValueError('corrupt')
    def unavailable(grants):raise RuntimeError('nft unavailable')
    calls=[]
    monkeypatch.setattr(app,'load_policy',corrupt)
    monkeypatch.setattr(app,'apply',unavailable)
    monkeypatch.setattr(network_control,'lockdown',lambda:calls.append('lockdown'))
    with pytest.raises(ValueError):app.sync()
    assert calls==['lockdown']


def test_boot_closes_application_egress_before_clearing_lockdown(monkeypatch):
    from installer import network_setup
    calls=[]
    from satsuma import app_firewall
    monkeypatch.setattr(app_firewall,'policy',lambda:{'enabled':True})
    monkeypatch.setattr(app_firewall,'apply',lambda enabled:calls.append(('apps',enabled)))
    from satsuma import loopback_guard
    monkeypatch.setattr(loopback_guard,'setup',lambda:calls.append('loopback'))
    monkeypatch.setattr(network_setup,'setup',lambda:calls.append('ports-ips'))
    monkeypatch.setattr(network_setup,'remove_lockdown',lambda:calls.append('remove-lockdown'))
    network_setup.main()
    assert calls==[('apps',True),'loopback','ports-ips','remove-lockdown']


@pytest.mark.parametrize('case',['valid','writable-membership','foreign-owner','changed-executable'])
def test_resolver_checks_running_image_and_group_membership(monkeypatch,case):
    import hashlib
    import stat
    from satsuma import protected_storage
    image=b'verified application image'
    executable=SimpleNamespace(st_dev=1,st_ino=200)
    group=SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0,st_ino=300)
    membership=SimpleNamespace(st_mode=stat.S_IFREG|(0o666 if case=='writable-membership' else 0o644),
                               st_uid=1000 if case=='foreign-owner' else 0)
    class FakePath:
        def __init__(self,path):self.path=path
        def read_text(self):return '0::/system.slice/browser.service\n'
        def stat(self):return executable
        def lstat(self):return group
        def exists(self):return True
    monkeypatch.setattr(app,'Path',FakePath)
    monkeypatch.setattr(app,'secure_read',lambda *a,**kw:image)
    monkeypatch.setattr(app,'os',SimpleNamespace(
        readlink=lambda path:'/usr/bin/browser',
        stat=lambda path,**kw:membership if kw else executable,
        fstat=lambda fd:group,close=lambda fd:None))
    monkeypatch.setattr(protected_storage,'open_directory',lambda p:42)
    props='Id=browser.service\nActiveState=active\nControlGroup=/system.slice/browser.service\nDelegate=no\nMainPID=234'
    runner=lambda args:SimpleNamespace(returncode=0,stdout=props)
    grant={'sha256':hashlib.sha256(image).hexdigest(),'access':['https']}
    if case=='changed-executable':grant['sha256']='0'*64
    if case=='valid':
        assert app.resolve_grant('browser.service',grant,runner)['inode']==300
    else:
        with pytest.raises(ValueError):app.resolve_grant('browser.service',grant,runner)


def test_fresh_install_does_not_enforce_an_empty_application_list(monkeypatch):
    monkeypatch.setattr(app,'load_policy',lambda:{'schema':1,'grants':{}})
    calls=[]
    monkeypatch.setattr(app,'apply',lambda grants,**kw:calls.append((grants,kw)))
    monkeypatch.setattr(app.RootDataStore,'replace',lambda *a:None)
    status=app.sync()
    assert calls==[([],{'enabled':False})] and status['enabled'] is False
    assert status['external_default']=='main_firewall'
    text=app.render([],enabled=False)
    assert text.count('policy accept')==2 and 'drop' not in text
    assert app.valid_layout(text,[],enabled=False)
    assert not app.valid_layout(text,[],enabled=True)
