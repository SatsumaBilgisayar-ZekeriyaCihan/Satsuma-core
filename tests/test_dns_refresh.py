"""DNS readiness rollback and health freshness without host DNS changes."""
from types import SimpleNamespace
import pytest
from satsuma import dnsmasq_control as dns, custom_dns_lists


@pytest.fixture
def configured(tmp_path,monkeypatch):
    state={'dns_policy':{'enabled':True,'upstream':'192.0.2.53'}}
    class Store:
        def get(self,key,default=None):return state.get(key,default)
        def set(self,key,value):state[key]=value
    monkeypatch.setattr(custom_dns_lists,'blocked_domains',lambda store:set())
    monkeypatch.setattr(dns.grp,'getgrnam',lambda name:SimpleNamespace(gr_gid=0))
    monkeypatch.setattr(dns.os,'chown',lambda *a:None)
    monkeypatch.setattr(dns,'atomic',lambda path,content,gid:path.write_text(content))
    monkeypatch.setattr(dns,'verify_config',lambda path:True)
    monkeypatch.setattr(dns,'probe',lambda:None)
    calls=[]
    def runner(args,**kwargs):calls.append(args);return SimpleNamespace(returncode=0,stderr='')
    return Store(),state,tmp_path,calls,runner


def test_unchanged_refresh_renews_health_and_checks_readiness(configured,monkeypatch):
    store,state,directory,calls,runner=configured
    dns._refresh(store,runner,directory)
    state['dns_filter_health']={'status':'STALE','updated_at':0}
    probes=[];monkeypatch.setattr(dns,'probe',lambda:probes.append(True))
    assert dns._refresh(store,runner,directory)['status']=='unchanged'
    assert probes and state['dns_filter_health']['status']=='LOCAL_READY'
    assert state['dns_filter_health']['updated_at']>0


def test_failed_readiness_restores_both_previous_files(configured,monkeypatch):
    store,state,directory,calls,runner=configured
    dns._refresh(store,runner,directory)
    original={name:(directory/name).read_text() for name in ('dnsmasq.conf','blocked.conf')}
    state['dns_policy']['upstream']='192.0.2.54'
    attempts=[]
    def probe():
        attempts.append(True)
        if len(attempts)==1:raise RuntimeError('candidate did not answer')
    monkeypatch.setattr(dns,'probe',probe)
    with pytest.raises(RuntimeError,match='did not answer'):dns._refresh(store,runner,directory)
    assert len(attempts)==2
    assert all((directory/name).read_text()==content for name,content in original.items())


def test_changed_signature_is_not_resigned_as_new_baseline(configured,monkeypatch):
    store,state,directory,calls,runner=configured
    dns._refresh(store,runner,directory);calls.clear()
    (directory/'blocked.conf').write_text('tampered')
    def reject(path):raise PermissionError('signature mismatch')
    monkeypatch.setattr(dns,'verify_config',reject)
    with pytest.raises(PermissionError):dns._refresh(store,runner,directory)
    assert (directory/'blocked.conf').read_text()=='tampered' and not calls


@pytest.mark.parametrize('active', [True, False])
def test_unchanged_refresh_starts_dns_only_when_inactive(configured, active):
    """2.2.27: the minute refresh no longer runs ``systemctl start`` on a running service."""
    store, state, directory, calls, _ = configured
    def runner(args, **kwargs):
        calls.append(args)
        code = 0 if 'is-active' not in args or active else 3
        return SimpleNamespace(returncode=code, stderr='')
    dns._refresh(store, runner, directory)
    calls.clear()
    assert dns._refresh(store, runner, directory)['status'] == 'unchanged'
    starts = [c for c in calls if c[:2] == ['/usr/bin/systemctl', 'start']]
    assert bool(starts) is (not active)
