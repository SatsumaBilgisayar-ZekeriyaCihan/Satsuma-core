"""Exercise failure, restart and bounded input across real collector methods."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from satsuma.worker_kernel import WorkerKernel
from satsuma.worker_systemd_dbus import WorkerSystemdDbus
from satsuma.worker_audit_bridge import WorkerAuditBridge
from satsuma.worker_memory import WorkerMemory
from satsuma.worker_log import read_batch


class Store:
    def __init__(self): self.values={};self.records=[]
    def get(self,key,default=None): return self.values.get(key,default)
    def set(self,key,value): self.values[key]=value
    def add(self,kind,value): self.records.append((kind,value))


class Pipeline:
    def __init__(self,fail=False):self.events=[];self.fail=fail
    def ingest_host(self,event):
        if self.fail:raise RuntimeError('database unavailable')
        self.events.append(event)


def test_kernel_read_failure_is_not_healthy():
    store=Store();worker=WorkerKernel(store)
    with patch('satsuma.worker_kernel.subprocess.run',return_value=SimpleNamespace(returncode=1,stdout='',stderr='Operation not permitted')):
        result=worker.tick(Pipeline())
    assert not result['ok']
    assert store.get(worker.health_key)['status']=='DEGRADED'
    assert store.get(worker.baseline_key) is None


def test_kernel_failed_delivery_replays_and_only_then_commits():
    store=Store();store.set('worker.kernel.baseline',{'lines':['old']})
    worker=WorkerKernel(store)
    worker.collect=lambda:{'timestamp':1,'total_lines':1,'events':[{'raw':'kernel panic','types':['panic'],'timestamp':1}]}
    assert not worker.tick(Pipeline(fail=True))['ok']
    assert store.get(worker.baseline_key)=={'lines':['old']}
    assert worker._last_lines=={'old'}
    pipeline=Pipeline();assert worker.tick(pipeline)['ok']
    assert len(pipeline.events)==1
    assert store.get(worker.baseline_key)['lines']==['kernel panic']
    assert WorkerKernel(store).tick(None)['status']=='DEGRADED'


def test_systemd_command_failure_does_not_erase_baseline():
    store=Store();saved={'units':['demo.service:active'],'dbus_services':['org.demo']}
    store.set('worker.systemd_dbus.baseline',saved)
    worker=WorkerSystemdDbus(store);worker._run=lambda *a,**k:(1,'','no system bus')
    assert not worker.tick(Pipeline())['ok']
    assert store.get(worker.baseline_key)==saved


def test_systemd_delivery_failure_does_not_commit_new_unit():
    store=Store();store.set('worker.systemd_dbus.baseline',{'units':['a.service:active'],'dbus_services':[]})
    worker=WorkerSystemdDbus(store)
    worker.collect=lambda **k:dict(timestamp=1,units=[dict(name='b.service',active='active')],timers=[],dbus_services=[],dbus_messages=[])
    assert not worker.tick(Pipeline(True))['ok']
    assert store.get(worker.baseline_key)['units']==['a.service:active']
    pipe=Pipeline();assert worker.tick(pipe)['ok'];assert len(pipe.events)==1


def test_bridge_without_pipeline_retains_cursor(tmp_path):
    store=Store();worker=WorkerAuditBridge(store,{'audit_host_db_path':str(tmp_path/'missing.db')})
    assert not worker.tick()['ok']
    assert store.get(worker.cursor_key) is None
    assert worker.tick(Pipeline())['status']=='WAITING_FOR_HOST_DB'
    assert not worker.tick(Pipeline())['ok']


def opener(path,uid):return open(path,'rb')


def test_batch_keeps_backlog_and_partial_tail(tmp_path):
    path=tmp_path/'events';path.write_bytes(b'one\ntwo\npar')
    lines,cursor=read_batch(path,opener=opener,limit=1)
    assert lines==['one\n']
    lines,cursor=read_batch(path,cursor,opener=opener)
    assert lines==['two\n'];assert cursor['offset']==8
    with path.open('ab') as stream:stream.write(b'tial\n')
    lines,cursor=read_batch(path,cursor,opener=opener)
    assert lines==['partial\n']
    path.unlink();path.write_text('rotated\n')
    assert read_batch(path,cursor,opener=opener)[0]==['rotated\n']


def test_batch_rejects_oversized_line(tmp_path):
    path=tmp_path/'events';path.write_bytes(b'x'*65537+b'\n')
    with pytest.raises(ValueError,match='Oversized'):read_batch(path,opener=opener)


def test_memory_retry_does_not_suppress_rejected_indicator(tmp_path):
    proc=tmp_path/'proc';p=proc/'12345';p.mkdir(parents=True)
    (p/'exe').symlink_to('/memfd:example')
    (p/'maps').write_text('1000-2000 rwxp 0 00:00 0\n')
    (p/'stat').write_text('12345 (example) '+' '.join(['0']*22))
    worker=WorkerMemory(Store(),proc_root=proc)
    assert not worker.tick(Pipeline(True))['ok']
    assert not worker.seen
    pipe=Pipeline();worker.tick(pipe);assert len(pipe.events)==2


def test_team_exception_updates_worker_health():
    from satsuma.teams.base import BaseTeamLead
    class Broken:
        name='broken'
        def tick(self,**kwargs):raise PermissionError('denied')
    store=Store();team=BaseTeamLead(store);team.worker_instances=[Broken()]
    assert not team.run_workers()['broken']['ok']
    assert store.get('worker.broken.health')['status']=='DEGRADED'


def test_new_workers_enabled_and_started_in_package():
    spec=(Path(__file__).parents[1]/'packaging/satsuma-core.spec').read_text()
    enables=' '.join(line for line in spec.splitlines() if 'systemctl enable ' in line)
    # DNS readiness starts the queue consumers on an earlier line; every start line counts.
    starts=' '.join(line for line in spec.splitlines() if 'systemctl start ' in line)
    for name in ['satsuma-udev.service','satsuma-integrity-check.timer']:
        assert name in enables and name in starts


def test_scan_results_reach_core_and_failed_delivery_retains_cursor(tmp_path):
    import json,sqlite3,os
    from satsuma.worker_clamav import WorkerClamav
    host=tmp_path/'host.db';db=sqlite3.connect(host)
    db.execute('CREATE TABLE records(id INTEGER PRIMARY KEY,kind TEXT,body TEXT)')
    db.execute('INSERT INTO records VALUES(1,?,?)',('security_scan',json.dumps({'tool':'clamav','status':'FINDINGS','completed_at':1,'output_excerpt':'/tmp/file with spaces: Test.Signature FOUND\n'})))
    db.commit();db.close();os.chmod(host,0o600)
    store=Store();worker=WorkerClamav(store,{'audit_host_db_path':str(host)})
    assert not worker.tick(Pipeline(True))['ok']
    assert store.get(worker.cursor_key+'.scheduled') is None
    pipe=Pipeline();assert worker.tick(pipe)['ok']
    assert pipe.events[0]['file']=='/tmp/file with spaces'
    assert store.get(worker.cursor_key+'.scheduled')==1
    pipe.events.clear();worker.tick(pipe);assert not pipe.events


def test_bpf_tool_absence_is_unknown_not_fake_program_count():
    from satsuma.bpf_inventory import inventory
    with patch('satsuma.bpf_inventory.shutil.which',return_value=None):
        result=inventory()
    assert result['status']=='UNAVAILABLE'
    assert result['program_count'] is None and result['programs']==[]


def test_sql_read_failures_are_not_zero_alerts():
    import sqlite3
    from satsuma import dashboard_api as api
    db=sqlite3.connect(':memory:')
    try:
        for operation in [lambda:api._count(db,'alerts'),lambda:api._rows(db,'alerts'),lambda:api._state(db,'health')]:
            with pytest.raises(sqlite3.Error):operation()
    finally:db.close()


def test_continuous_dbus_keeps_headers_until_delivery_commit():
    import os, threading, time
    from satsuma.dbus_stream import DbusStream
    readfd,writefd=os.pipe()
    class Process:
        def __init__(self):self.stdout=os.fdopen(readfd,'rb');self.stopped=False
        def poll(self):return 0 if self.stopped else None
        def terminate(self):self.stopped=True;os.close(writefd)
        def wait(self,timeout=None):return 0
    process=Process();monitor=DbusStream(popen=lambda *a,**k:process)
    try:
        header=b'method call time=1 sender=:1.2 -> destination=org.freedesktop.systemd1 interface=org.freedesktop.systemd1.Manager; member=StartTransientUnit\n'
        os.write(writefd,header)
        deadline=time.monotonic()+2
        while not monitor.queue and time.monotonic()<deadline:time.sleep(.01)
        first=monitor.capture();assert 'StartTransientUnit' in first
        assert monitor.capture()==first
        monitor.commit();assert monitor.capture()==''
        os.write(writefd,header)
        deadline=time.monotonic()+2
        while not monitor.queue and time.monotonic()<deadline:time.sleep(.01)
        assert 'StartTransientUnit' in monitor.capture()
    finally:monitor.close()


def test_stale_heartbeat_is_not_running_in_dashboard(tmp_path):
    import sqlite3,json,time
    from satsuma import dashboard_api as api
    path=tmp_path/'core.db';db=sqlite3.connect(path)
    db.execute('CREATE TABLE state(key TEXT,body TEXT)')
    db.execute('INSERT INTO state VALUES(?,?)',('worker.memory.health',json.dumps({'status':'RUNNING','updated_at':time.time()-3600})))
    db.commit();db.close()
    with patch.object(api,'_connect',side_effect=lambda:sqlite3.connect(path)),patch.object(api,'_connect_host',side_effect=FileNotFoundError()):
        result=api.m_workers()
    assert result['memory']['status']=='DEGRADED'
    assert 'stale' in result['memory']['degraded_reason']


def test_watch_hash_does_not_read_device_nodes():
    from satsuma.watch_store import _sha256_file,WatchStore
    assert _sha256_file('/dev/zero') is None
    store=Store();store.set('watch_files',{'/tmp/a':{'path':'/tmp/a'}})
    watch=WatchStore(store)
    assert watch.match_process('/usr/bin/echo','echo /tmp/a')==[]
    assert watch.match_process('/tmp/abc','/tmp/abc')==[]
    assert watch.match_process('/usr/bin/bash','bash /tmp/a')


def test_automatic_response_preserves_outbound_or_unknown_direction():
    from satsuma.response import ResponseWorker
    from satsuma import incoming_response
    store=Store();calls=[]
    worker=ResponseWorker(store,{'response_enabled':True},runner=lambda args:calls.append(args))
    with patch.object(incoming_response,'incoming_peer',return_value=False):
        result=worker.block_ip('45.33.32.10','automatic alert')
    assert result['status']=='outbound_or_direction_unverified'
    assert result['executed'] is False and calls==[]


def test_incoming_peer_uses_first_original_tuple_not_reply():
    from satsuma.incoming_response import incoming_peer
    import integrations.satsuma_guard as module
    outgoing='tcp 6 100 ESTABLISHED src=192.168.1.10 dst=45.33.32.10 sport=50000 dport=443 src=45.33.32.10 dst=192.168.1.10 sport=443 dport=50000'
    incoming='tcp 6 100 ESTABLISHED src=45.33.32.10 dst=192.168.1.10 sport=443 dport=50000 src=192.168.1.10 dst=45.33.32.10 sport=50000 dport=443'
    with patch.object(module,'local_ips',return_value={'192.168.1.10'}):
        with patch.object(module,'command',return_value=SimpleNamespace(returncode=0,stdout=outgoing)):
            assert not incoming_peer('45.33.32.10')
        with patch.object(module,'command',return_value=SimpleNamespace(returncode=0,stdout=incoming)):
            assert incoming_peer('45.33.32.10')


def test_scanner_output_is_bounded_and_child_is_reaped(tmp_path):
    import sys
    from satsuma import security_scan
    with (tmp_path/'output').open('wb') as output,patch.object(security_scan,'MAX_OUTPUT_BYTES',1024):
        with pytest.raises(RuntimeError,match='capacity'):
            security_scan.bounded_run([sys.executable,'-c','print("x"*100000)'],stdout=output,timeout=3)
        assert output.tell()<=1024


def test_components_without_their_own_heartbeat_are_shown_active(tmp_path):
    import sqlite3
    from satsuma import dashboard_api as api
    path=tmp_path/'core.db';db=sqlite3.connect(path)
    db.execute('CREATE TABLE state(key TEXT,body TEXT)');db.commit();db.close()
    with patch.object(api,'_connect',side_effect=lambda:sqlite3.connect(path)),patch.object(api,'_connect_host',side_effect=FileNotFoundError()):
        result=api.m_workers()
    for name in ('dns_monitor','evidence','response'):
        if name in result:
            assert result[name]['status']=='ACTIVE' and 'Veri alınamadı' not in result[name]['status_tr']
            assert result[name]['degraded_reason'] is None
    assert 'response' in result
