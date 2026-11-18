"""Failure-trigger, direction, concurrency and repair-budget regressions."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import time
import pytest

ROOT=Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('rescue',ROOT/'integrations/omni_sentinel_rescue.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
from satsuma import self_health as h


def test_outage_requires_two_protection_services_not_gui_or_unknown():
    states={unit:'active' for unit in r.UNITS}
    assert r.failed_units(states)==[]
    states[r.UNITS[0]]='inactive'
    assert len(r.failed_units(states))==1
    states[r.UNITS[1]]='failed'
    assert len(r.failed_units(states))==2
    states[r.UNITS[1]]='activating'
    assert len(r.failed_units(states))==1
    states[r.UNITS[1]]='unknown'
    assert len(r.failed_units(states))==1


@pytest.mark.parametrize('priority',[1,2,3])
def test_fast_exact_original_tuple_only(priority):
    line=f'[Priority: {priority}] {{TCP}} 45.33.32.10:4000 -> 192.168.1.3:443'
    flow=('tcp','45.33.32.10','192.168.1.3',4000,443)
    assert r.fast_candidates(line,{flow})==[('45.33.32.10',f'suricata_priority_{priority}')]
    assert not r.fast_candidates(line,{('tcp','192.168.1.3','45.33.32.10',443,4000)})
    assert not r.fast_candidates(line,{('tcp','45.33.32.10','192.168.1.3',4001,443)})


def test_ipv6_original_alert_and_single_ip_burst():
    line='[Priority: 2] {UDP} [2606:4700:4700::1111]:123 -> [fd00::2]:123'
    assert r.fast_candidates(line,{('udp','2606:4700:4700::1111','fd00::2',123,123)})
    flows={('tcp',f'45.33.32.{i}','192.168.1.3',4000+i,443) for i in range(1,11)}
    result=r.burst_candidates(flows)
    assert len(result)==10 and all('/' not in ip for ip,_ in result)
    assert not r.burst_candidates(set(list(flows)[:9]))


def test_flow_inventory_excludes_outgoing_originals(monkeypatch):
    def checked(args):
        if '-j' in args:return json.dumps([{'addr_info':[{'local':'192.168.1.3'}]}])
        if args[-1]=='ipv6':return ''
        return ('tcp 6 100 ESTABLISHED src=192.168.1.3 dst=45.33.32.10 sport=4000 dport=443 src=45.33.32.10 dst=192.168.1.3 sport=443 dport=4000 [ASSURED] use=1\n'
                'tcp 6 100 ESTABLISHED src=45.33.32.11 dst=192.168.1.3 sport=5000 dport=443 src=192.168.1.3 dst=45.33.32.11 sport=443 dport=5000 [ASSURED] use=1\n'
                # Audit K2: forged UDP and an unfinished handshake are not incoming flows.
                'udp 17 29 src=45.33.32.12 dst=192.168.1.3 sport=53 dport=40000 src=192.168.1.3 dst=45.33.32.12 sport=40000 dport=53 use=1\n'
                'tcp 6 118 SYN_RECV src=45.33.32.13 dst=192.168.1.3 sport=6000 dport=443 src=192.168.1.3 dst=45.33.32.13 sport=443 dport=6000 use=1\n')
    monkeypatch.setattr(r,'checked',checked)
    assert r.flow_snapshot()=={('tcp','45.33.32.11','192.168.1.3',5000,443)}


def test_k2_resolvers_are_read_from_resolv_conf(monkeypatch,tmp_path):
    conf=tmp_path/'resolv.conf';conf.write_text('# generated\nnameserver 195.175.39.39\nnameserver fe80::1%eth0\nnameserver bogus\n')
    real_open=open
    monkeypatch.setattr('builtins.open',lambda p,*a,**k:real_open(conf,*a,**k) if p=='/etc/resolv.conf' else real_open(p,*a,**k))
    assert r.resolvers()=={'195.175.39.39','fe80::1'}


def test_fast_cursor_retained_until_delivery_then_rotates(monkeypatch,tmp_path):
    path=tmp_path/'fast.log';path.write_text('[Priority: 1] {TCP} 45.33.32.10:4000 -> 192.168.1.3:443\npartial')
    monkeypatch.setattr(r,'trusted_file',lambda p:open(p,'rb'))
    lane=r.FastLane(str(path));flows={('tcp','45.33.32.10','192.168.1.3',4000,443)}
    candidates,cursor=lane.scan(flows)
    assert candidates and lane.cursor is None
    assert lane.scan(flows)[0]==candidates
    lane.commit(cursor);assert not lane.scan(flows)[0]
    path.unlink();path.write_text('[Priority: 2] {TCP} 45.33.32.10:4000 -> 192.168.1.3:443\n')
    assert lane.scan(flows)[0]


def test_otx_deny_default_redirect_key_and_pulses(monkeypatch):
    monkeypatch.setattr(r,'trusted_file',lambda *a,**k:io.BytesIO(b'key'))
    class Response(io.BytesIO):pass
    class Opener:
        def open(self,request,timeout):return Response(b'{"pulse_info":{"count":36}}')
    monkeypatch.setattr(r.urllib.request,'build_opener',lambda *a:Opener())
    lane=r.OtxLane();flows={('tcp','45.33.32.10','192.168.1.3',5000,443)}
    assert lane.scan(flows)[0]==[('45.33.32.10','otx_pulses_gt_35')]
    assert len(lane.requests)==1
    assert lane.scan(flows)[0] and len(lane.requests)==1
    with pytest.raises(ValueError):r.NoRedirect().redirect_request(None,None,None,None,None,None)


def test_rescue_launches_three_lanes_and_does_not_wait_for_otx(monkeypatch):
    import threading
    entered=threading.Event();release=threading.Event();calls=[];reports=[]
    def slow(self,flows):entered.set();release.wait(timeout=3);return [],None
    monkeypatch.setattr(r.OtxLane,'scan',slow)
    monkeypatch.setattr(r.FastLane,'scan',lambda self,flows:(calls.append('fast') or [],(1,1,0)))
    monkeypatch.setattr(r,'burst_candidates',lambda flows:(calls.append('burst') or []))
    monkeypatch.setattr(r,'service_states',lambda:{unit:('inactive' if i<2 else 'active') for i,unit in enumerate(r.UNITS)})
    monkeypatch.setattr(r,'flow_snapshot',lambda:set())
    monkeypatch.setattr(r.Nft,'setup',lambda self:None)
    monkeypatch.setattr(r,'command',lambda args,**k:subprocess.CompletedProcess(args,0,'',''))
    monkeypatch.setattr(r.signal,'signal',lambda *a:None)
    monkeypatch.setattr(r.os,'geteuid',lambda:0)
    old_read=r.Path.read_text
    monkeypatch.setattr(r.Path,'read_text',lambda self,*a,**k:'1000 0' if str(self)=='/proc/uptime' else old_read(self,*a,**k))
    real_sleep=time.sleep
    def sleep(_):real_sleep(.001)
    monkeypatch.setattr(r.time,'sleep',sleep)
    def save(report):
        reports.append(report)
        if len(reports)>5 and entered.is_set():r.STOP=True;release.set()
        if len(reports)>100:r.STOP=True;release.set()
    monkeypatch.setattr(r,'save_status',save)
    r.STOP=False
    try:r.run()
    finally:r.STOP=False;release.set()
    assert entered.is_set() and 'fast' in calls and 'burst' in calls
    assert any(report['mode']=='RESCUE_ACTIVE' for report in reports)


def test_repair_budget_and_masking_no_unbounded_restarts():
    now=time.time();unit=h.UNITS[0]
    assert h.repair_allowed(unit,'failed',{},now)
    assert not h.repair_allowed(unit,'active',{},now)
    assert not h.repair_allowed('arbitrary.service','failed',{},now)
    assert not h.repair_allowed(unit,'failed',{unit:[now-1,now-20,now-30]},now)
    assert h.repair_allowed(unit,'failed',{unit:[now-1801]},now)


def test_report_staleness_and_symlink_rejection(tmp_path):
    path=tmp_path/'status.json';path.write_text(json.dumps({'status':'RUNNING','updated_at':time.time()-901}))
    assert h.read_report(path)['status']=='STALE'
    link=tmp_path/'link';link.symlink_to(path)
    assert h.read_report(link)['status']=='UNAVAILABLE'
    assert h.read_report(tmp_path/'missing')['status']=='NOT_RUN'




def test_packaged_rescue_is_independent_and_health_timer_ten_minutes():
    unit=(ROOT/'systemd/satsuma-rescue.service').read_text()
    assert 'Requires=satsuma-image.service' in unit and 'Restart=always' in unit
    timer=(ROOT/'systemd/satsuma-self-health.timer').read_text()
    assert 'OnUnitActiveSec=10min' in timer
    spec=(ROOT/'packaging/satsuma-core.spec').read_text()
    for name in ('satsuma-rescue.service','satsuma-self-health.timer','satsuma-app-control.service'):
        assert any('systemctl enable ' in line and name in line for line in spec.splitlines())
        assert any(('systemctl start ' in line or 'systemctl restart ' in line) and name in line for line in spec.splitlines())
    # 2.2.38: the maintenance kit's timer goes first too: it may start units.
    assert ('for unit in satsuma-maintenance.timer satsuma-maintenance '
            'satsuma-self-health.timer satsuma-self-health satsuma-rescue satsuma-core') in spec


def test_self_health_reports_running_and_refuses_repairs_on_integrity_failure(monkeypatch):
    from satsuma import self_guard,store
    reports=[];commands=[]
    monkeypatch.setattr(h,'read_report',lambda:{'status':'NOT_RUN'})
    monkeypatch.setattr(h,'report',lambda value:reports.append(json.loads(json.dumps(value))))
    states={unit:{'ActiveState':'active','UnitFileState':'enabled'} for unit in h.UNITS}
    states['satsuma-core.service']={'ActiveState':'failed','UnitFileState':'enabled'}
    monkeypatch.setattr(h,'inspect_units',lambda:states)
    def fail():raise RuntimeError('application changed')
    monkeypatch.setattr(self_guard,'verify',fail)
    class FakeStore:
        db=None
        def get(self,key,default=None):return default
        def close(self):pass
    monkeypatch.setattr(store,'Store',FakeStore)
    def command(args,timeout=8):
        commands.append(args)
        if args[0]=='/usr/bin/unshare':return json.dumps({'packet_drop_verified':True})
        if args[1:3]==['show','suricata.service']:return 'LoadState=not-found\n'  # read-only check
        raise AssertionError('No repair command allowed when integrity fails')
    monkeypatch.setattr(h,'command',command)
    from satsuma.protected_storage import RootDataStore
    monkeypatch.setattr(RootDataStore,'append',lambda self,record:None)
    h.run()
    assert reports[0]['status']=='RUNNING'
    assert reports[-1]['status']=='DEGRADED'
    assert not reports[-1]['checks']['integrity']['ok']
    assert not reports[-1]['repairs']
    assert all(args[0]=='/usr/bin/unshare' or args[1]=='show' for args in commands)
