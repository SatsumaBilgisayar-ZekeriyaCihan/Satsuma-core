import json
"""Validated configuration edits keep protection on its last good policy."""
import copy,json
from pathlib import Path
from types import SimpleNamespace as NS
import pytest
from satsuma import config,policy,configuration_reload as reload
from satsuma.configuration_status import ConfigurationError
from satsuma.store import Store


def test_shipped_feature_switches_roundtrip():
    value=policy.validate(json.loads((Path(__file__).parents[1]/'config_examples/policy.json').read_text()))
    for key in ('network_discovery_enabled','subnet_protection_enabled','app_control_enabled','dns_filter_enabled','hagezi_enabled'):
        assert policy.effective(value)[key] is True
        edited=copy.deepcopy(value);edited['features'][key]=False
        assert policy.effective(edited)[key] is False
    value['scheduled_scans']['enabled']=False;value['scheduled_scans']['order']=['clamav']
    assert not policy.effective(value)['scheduled_scans']['enabled']
    assert policy.validate(value)==policy.validate(policy.validate(value))
    with pytest.raises(ValueError):policy.validate({**value,'features':{'invented':True}})


def test_valid_then_invalid_then_repaired_policy(tmp_path,monkeypatch):
    path=tmp_path/'policy.json';path.write_text('{}')
    cache=tmp_path/'last-valid.json'
    monkeypatch.setattr(policy,'POLICY_PATH',path)
    monkeypatch.setattr(config,'LAST_VALID_POLICY',cache)
    original=policy.from_legacy(config.DEFAULT);documents={path:original}
    def read(selected,raw_bytes=False):
        if Path(selected) not in documents:raise FileNotFoundError(str(selected))
        if raw_bytes:return json.dumps(documents[Path(selected)]).encode()
        return copy.deepcopy(documents[Path(selected)])
    # 2.2.62: no signing key in this test (signature state 'no_key'); signing has its own tests.
    monkeypatch.setattr('satsuma.policy_signing.PUBLIC_PATH',tmp_path/'none.pub')
    monkeypatch.setattr(config,'_read_secure_json',read)
    monkeypatch.setattr(config.os,'geteuid',lambda:0)
    class Writer:
        def __init__(self,name):self.name=name
        def replace(self,value):
            if self.name=='configuration/last-valid-policy.json':documents[cache]=copy.deepcopy(value)
        def read(self):raise FileNotFoundError(self.name)
    monkeypatch.setattr('satsuma.protected_storage.RootDataStore',Writer)
    first,meta,_=config.load_with_policy();assert meta['status']=='validated' and cache not in documents
    first,meta,_=config.load_with_policy(persist=True);assert meta['status']=='validated'
    documents[path]={'broken':'policy'}
    active,meta,_=config.load_with_policy(persist=True)
    assert active==first and meta['status']=='last_valid' and documents[path]=={'broken':'policy'}
    repaired=copy.deepcopy(original);repaired['features']['network_discovery_enabled']=False
    documents[path]=repaired
    active,meta,_=config.load_with_policy(persist=True);assert not active['network_discovery_enabled'] and meta['status']=='validated'
    documents[path]={'broken':True};documents[cache]={'also':'broken'}
    with pytest.raises(ConfigurationError):config.load_with_policy(persist=True)


def test_fallback_keeps_configuration_gate_but_never_approves_changed_code():
    from satsuma.early_guard import run_guard
    checker=lambda:({}, {'status':'last_valid','error':'bad JSON'}, {})
    result=run_guard(verifier=lambda:3,config_checker=checker)
    assert result['response_unlocked'] and result['checks']['configuration']['fallback_active']
    def broken():raise RuntimeError('code changed')
    assert not run_guard(verifier=broken,config_checker=checker)['response_unlocked']


def test_reload_applies_once_and_reports_fallback(tmp_path,monkeypatch):
    store=Store(tmp_path/'core',test=True);meta={'status':'validated','sha256':'fixture'}
    monkeypatch.setattr(config,'load_with_policy',lambda **kw:({'response_enabled':True},meta,{}))
    # Running as root would persist into /var/lib; persistence has its own tests.
    monkeypatch.setattr(config,'remember_policy',lambda *a,**k:None)
    calls=[]
    def runner(args,**kw):return NS(stdout='ActiveState=active\nUnitFileState=enabled\n',returncode=0)
    try:
        result=reload.reload_configuration(store,monitor=lambda:{'status':'HEALTHY'},runner=runner,apply=lambda s,c:calls.append(c))
        assert result['status']=='APPLY_REQUESTED' and len(calls)==1
        meta['status']='last_valid'
        result=reload.reload_configuration(store,monitor=lambda:{'status':'HEALTHY'},runner=runner,apply=lambda *a:pytest.fail('unchanged snapshot'))
        assert result['status']=='LAST_VALID' and result['protection_unlocked']
        assert store.recent('findings')[0]['rule_id']=='SATSUMA-CONFIG-001'
        assert reload.reload_configuration(store,monitor=lambda:{'status':'UNTRUSTED'})['status']=='FAILED'
    finally:store.close()


def test_disabled_scan_and_configured_interval(tmp_path):
    from satsuma.host_store import HostStore
    from satsuma.security_scan import run_once,scan_due
    host=HostStore(tmp_path/'host',test=True)
    try:
        assert run_once(host,which=lambda *a:pytest.fail('disabled'),scan_policy={'enabled':False,'order':['clamav']})==[]
        assert host.get('security_scan_health')['status']=='DISABLED'
        assert not scan_due({'status':'COMPLETED','updated_at':100},{'interval_seconds':3600},200)
        assert scan_due({'status':'COMPLETED','updated_at':100},{'interval_seconds':3600},3700)
    finally:host.close()
