"""Strict policy rejects broad accepts, queue bypass and wrong IPS ownership."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from network_fixture import table_json
from satsuma import network_control as nft, ips, otx
from satsuma.store import Store
from satsuma.response import ResponseWorker
from satsuma.subnet_protection import evaluate
from satsuma.response_policy import authorize_destructive

@pytest.mark.parametrize('change',['policy','queue','bypass','extra_accept','udp443','missing_forward','ordering'])
def test_strict_verifier_rejects_weakened_policy(change):
    data=json.loads(table_json());entries=data['nftables']
    assert nft.validate_layout(data)
    if change=='policy':next(x['chain'] for x in entries if 'chain' in x)['policy']='accept'
    elif change=='missing_forward':entries[:]=[x for x in entries if x.get('chain',{}).get('name')!='forward']
    elif change in ('queue','bypass'):
        queue=next(expr['queue'] for x in entries for expr in x.get('rule',{}).get('expr',[]) if 'queue' in expr)
        if change=='queue':queue['num']=1
        else:queue['flags']=['bypass']
    elif change=='extra_accept':entries.append({'rule':{'chain':'input','expr':[{'accept':None}]}})
    elif change=='udp443':
        m=next(expr['match'] for x in entries for expr in x.get('rule',{}).get('expr',[]) if expr.get('match',{}).get('left')=={'payload':{'protocol':'udp','field':'dport'}})
        m['right']={'set':[53,443]}
    elif change=='ordering':
        positions=[i for i,x in enumerate(entries) if x.get('rule',{}).get('chain')=='input'];a,b=positions[2],positions[4];entries[a],entries[b]=entries[b],entries[a]
    assert not nft.validate_layout(data)

def test_packaged_rules_match_managed_policy():
    path=Path(__file__).resolve().parents[1]/'packaging/root/etc/satsuma-core/nftables.nft'
    assert path.read_text()==nft.render_ruleset()
    assert 'bypass' not in path.read_text()
    assert '853' not in path.read_text()
    assert path.read_text().count('policy drop')==3


def test_dnsmasq_port_is_closed_and_never_named():
    # 2.2.38 (owner, 2026-11-13): Satsuma's only relation to loopback is blocking it.
    text=nft.render_ruleset()
    assert '53053' not in text and 'proto-dst' not in text
    assert 53053 not in nft.LO_TCP and 53053 not in nft.LO_UDP
    assert '53053' not in json.dumps(json.loads(table_json()))


@pytest.fixture
def otx_store(tmp_path):
    store=Store(tmp_path/'data',test=True)
    yield store
    store.close()

def run_otx(store, mode=True, boot=True, fail=False):
    import time
    cfg={'api_key':'fixture-only','cache_ttl_seconds':3600,'max_queries_per_cycle':12}
    core={'otx_enabled':True,'otx_blocker_mode':mode,'otx_pulse_threshold':11,'otx_recent_pulse_days':14}
    data={'pulse_info':{'count':11,'pulses':[{'modified':time.time()}]}}
    calls=[]
    def runner(command):
        calls.append(command)
        return {'returncode':1 if fail else 0,'stdout':table_json() if '-j' in command else '', 'stderr':'fixture failure' if fail else ''}
    worker=ResponseWorker(store,{'response_enabled':True,'nft_family':'inet','nft_table':'satsuma_core','nft_set':'blocked_ips'},runner=runner)
    def incoming(worker,ip,*args):
        calls.append(['incoming_original_only',ip])
        return {'status':'failed' if fail else 'set_membership_confirmed','drop_rule_linked':not fail}
    with patch('satsuma.incoming_response.block',side_effect=incoming), patch.object(otx,'load_config',return_value=cfg), patch.object(otx,'load_with_policy',return_value=(core,{},{})), patch.object(otx,'request_ipv4',return_value=(data,{'verified':True,'version':'TLSv1.3','cipher':'fixture','host':otx.HOST})), patch.object(otx,'run_domains'), patch('satsuma.early_guard.read_verdict',return_value={'response_unlocked':boot}):
        return otx.run_once(store,worker,['8.8.8.8']),calls


def test_otx_explicit_threshold_reaches_verified_nft_set_without_fabricating_classification(otx_store):
    result,calls=run_otx(otx_store)
    assert result[0]['decision']=='block'
    assert result[0]['classification']=='suspicious'
    assert result[0]['block_result']=='set_membership_confirmed'
    assert ['incoming_original_only','8.8.8.8'] in calls

@pytest.mark.parametrize('mode,boot',[(False,True),(True,False)])
def test_otx_no_block_without_selected_mode_and_boot_verification(otx_store,mode,boot):
    result,calls=run_otx(otx_store,mode,boot)
    assert result[0]['decision']!='block' and not calls

def test_otx_firewall_failure_is_not_reported_as_a_block_or_cached_for_an_hour(otx_store):
    result,calls=run_otx(otx_store,fail=True)
    assert result[0]['decision']=='review'
    assert '8.8.8.8' not in otx_store.get('otx_cache')

def test_subnet_failed_firewall_can_retry_and_is_reported_degraded(otx_store):
    otx_store.set('subnet_protection_policy',{'enabled':True,'threshold':10})
    worker=SimpleNamespace(block_ip=lambda *a,**kw:{'status':'failed'})
    boot=lambda:{'response_unlocked':True}
    assert evaluate(otx_store,{f'8.8.8.{n}':1 for n in range(1,11)},{},worker,now=100,boot_provider=boot)
    assert otx_store.get('subnet_health')['status']=='degraded'
    assert evaluate(otx_store,{f'8.8.8.{n}':1 for n in range(1,11)},{},worker,now=105,boot_provider=boot)


def test_auto_authorization_needs_one_source_without_nameerror():
    cfg={'response_enabled':True,'destructive_response_enabled':True,'destructive_allowed_actions':['network_isolate'],'auto_action_network_enabled':True}
    finding={'classification':'confirmed','sources':['audit','suricata']}
    context={'automated':True,'target_ip':'8.8.8.8'}
    assert authorize_destructive('network_isolate',finding,cfg,context).allowed
    finding.update(sources=['audit'],multi_source_verified=True)
    assert authorize_destructive('network_isolate',finding,cfg,context).allowed
    assert not authorize_destructive('network_isolate',{'classification':'indicator','sources':['audit']},cfg,context).allowed

@pytest.mark.parametrize('nfq,rules,code',[(False,1,0),(True,0,0),(True,1,1),(True,1,0)])
def test_ips_preflight_requires_nfq_valid_rules_and_success(nfq,rules,code):
    from installer.ips_preflight import verify
    def runner(args,**kw):
        if '-V' in args:return SimpleNamespace(stdout='This is Suricata version 8.0.7 RELEASE',stderr='')
        if '--build-info' in args:return SimpleNamespace(stdout='NFQueue support: '+('yes' if nfq else 'no'))
        return SimpleNamespace(returncode=code,stdout=f'{rules} rules successfully loaded',stderr='')
    if nfq and rules and code==0:assert verify(runner)['status']=='configuration_checked'
    else:
        with pytest.raises(RuntimeError):verify(runner)


def test_network_setup_failure_installs_lockdown_and_never_clears_it(monkeypatch):
    from installer import network_setup
    calls=[]
    def broken():raise RuntimeError('unrecognized table')
    from satsuma import app_firewall
    monkeypatch.setattr(app_firewall,'policy',lambda:{'enabled':True})
    monkeypatch.setattr(app_firewall,'apply',lambda enabled:None)
    monkeypatch.setattr(network_setup,'setup',broken)
    monkeypatch.setattr(network_setup,'lockdown',lambda:calls.append('lockdown'))
    monkeypatch.setattr(network_setup,'remove_lockdown',lambda:calls.append('remove'))
    with pytest.raises(RuntimeError,match='emergency DROP remains active'):network_setup.main()
    assert calls==['lockdown']

@pytest.mark.parametrize('owner,executable',[(True,True),(False,True),(True,False)])
def test_queue_listener_requires_expected_executable_and_socket_inode(tmp_path,monkeypatch,owner,executable):
    root=tmp_path/'proc';(root/'net/netfilter').mkdir(parents=True)
    (root/'net/netfilter/nfnetlink_queue').write_text('100 777 0 0 0 0 0 0\n')
    (root/'net/netlink').write_text('header\n0000 12 777 0 0 0 0 2 0 999\n')
    process=root/'123';(process/'fd').mkdir(parents=True)
    binary=tmp_path/'suricata';binary.write_bytes(b'fixture');binary.chmod(0o755)
    other=tmp_path/'other';other.write_bytes(b'other')
    (process/'exe').symlink_to(binary if executable else other)
    (process/'fd/4').symlink_to('socket:[999]' if owner else 'socket:[888]')
    real_stat=Path.stat
    def root_stat(path,**kw):
        info=real_stat(path,**kw);parts=list(info);parts[4]=0;return os.stat_result(parts)
    monkeypatch.setattr(Path,'stat',root_stat)
    result=ips.listener_status(root,runner=lambda *a,**kw:SimpleNamespace(stdout='123'),binary=binary)
    assert result['ready']==(owner and executable)


def test_tls_transport_is_not_an_independent_threat_sensor():
    cfg={'response_enabled':True,'destructive_response_enabled':True,'destructive_allowed_actions':['network_isolate'],'auto_action_network_enabled':True}
    finding={'classification':'confirmed','sources':['otx','tls_verified'],'multi_source_verified':True}
    auth=authorize_destructive('network_isolate',finding,cfg,{'automated':True,'target_ip':'8.8.8.8'})
    assert auth.allowed and auth.sources==('otx',)

@pytest.mark.parametrize('age',[float('nan'),float('inf'),-1,'0'])
def test_otx_rejects_invalid_pulse_age(age):
    result=otx._should_block({'tls':{'verified':True},'pulse_count':11,'latest_pulse_age_days':age},{'pulse_threshold':11,'recent_pulse_days':14,'require_tls':True})
    assert result==(False,'pulse_age_invalid')


def test_ips_readiness_record_rejects_pid_reuse_and_changed_queue_peer(tmp_path,monkeypatch):
    ready=tmp_path/'ready.json';queue=tmp_path/'queue';pid=os.getpid()
    ticks=(Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19]
    status={'ready':True,'pid':pid,'start_ticks':ticks,'peer_portid':'777','writer_uid':os.geteuid(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    ready.write_text(json.dumps(status));ready.chmod(0o600);queue.write_text('100 777 0\n')
    monkeypatch.setattr(ips,'QUEUE_FILE',queue)
    original=os.fstat
    def root_owned(fd):
        parts=list(original(fd));parts[4]=0;return os.stat_result(parts)
    monkeypatch.setattr(os,'fstat',root_owned)
    runner=lambda *a,**kw:SimpleNamespace(stdout=str(pid))
    assert ips.read_ready(ready,runner)['ready']
    status['start_ticks']='0';ready.write_text(json.dumps(status))
    assert not ips.read_ready(ready,runner)['ready']
    status['start_ticks']=ticks;ready.write_text(json.dumps(status));queue.write_text('100 888 0\n')
    assert not ips.read_ready(ready,runner)['ready']


def test_no_satsuma_table_allows_dns_over_tls():
    # Field 2026-11-04: port 853 carried C2 traffic; the LAN table named it as allowed.
    from satsuma import network_modes
    for script in (network_modes.lan_script(), network_modes.dns_script(), nft.render_ruleset()):
        assert '853' not in script
