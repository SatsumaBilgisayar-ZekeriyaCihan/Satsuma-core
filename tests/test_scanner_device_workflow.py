"""Scanner UI, device queue and explicit file quarantine contracts."""
import json
import os
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from satsuma import scan_quarantine as q, network_discovery as nd, dashboard_api
from satsuma.store import Store
from satsuma.host_store import HostStore


@pytest.fixture
def store(tmp_path):
    value=Store(tmp_path/'core',test=True)
    yield value
    value.close()


def test_new_device_is_queued_once_without_claiming_remote_scan(store,monkeypatch):
    snapshot={'updated_at':100,'status':'RUNNING','neighbors':[{'ip':'192.168.1.20','mac':'02:00:00:00:00:20','interface':'eth0'}],'errors':{}}
    monkeypatch.setattr(nd,'discover',lambda:snapshot)
    worker=nd.WorkerNetworkDiscovery(store)
    worker.tick();worker.tick()
    rows=store.recent('network_device_alerts')
    assert len(rows)==1
    device=next(iter(store.get('network_devices').values()))
    assert device['scan_status']=='AGENT_REQUIRED' and device['decision']=='pending'
    assert all(v=='REMOTE_AGENT_REQUIRED' for v in device['scanners'].values())
    assert device['rule_evaluation']=='AWAITING_SCAN_EVIDENCE'


def test_unresolved_neighbor_is_not_registered_as_a_device(store,monkeypatch):
    monkeypatch.setattr(nd,'discover',lambda:{'updated_at':100,'status':'RUNNING','neighbors':[{'ip':'192.168.1.20','interface':'eth0'}],'errors':{}})
    nd.WorkerNetworkDiscovery(store).tick()
    assert store.get('network_devices')=={}


def test_scanner_reader_returns_real_history_and_missing_engines(tmp_path,monkeypatch):
    from satsuma import security_scan
    host=HostStore(tmp_path/'host',test=True)
    host.add('security_scan',{'tool':'clamav','status':'FINDINGS','findings':1,'exit_code':1})
    host.close()
    monkeypatch.setattr(dashboard_api,'HOST_DB_PATH',str(tmp_path/'host'/'host.db'))
    monkeypatch.setattr(security_scan,'commands',lambda:[('clamav',['clamscan']),('rkhunter',None),('chkrootkit',None)])
    result=dashboard_api.m_security_scanners()
    assert result['engines']['clamav']['last_result']['status']=='FINDINGS'
    assert result['engines']['rkhunter']['installed'] is False
    assert result['data_state']=='OK' and len(result['items'])==1


def test_quarantine_requires_same_file_and_preserves_bytes(tmp_path,monkeypatch):
    source=tmp_path/'sample.bin';source.write_bytes(b'harmless scanner fixture')
    monkeypatch.setattr(q,'ALLOWED_ROOTS',(tmp_path,))
    # Production storage rejects world-writable ancestors such as /tmp.
    # This fixture supplies an already-open temporary storage parent instead.
    monkeypatch.setattr('satsuma.protected_storage.open_directory',lambda p:os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
    target=q.inspect_target(source);audit=[]
    result=q.quarantine_target(target,audit.append,directory=tmp_path/'quarantine')
    assert result['status']=='quarantined' and not source.exists()
    moved=tmp_path/'quarantine'/result['quarantine_id']
    assert moved.read_bytes()==b'harmless scanner fixture'
    assert moved.stat().st_mode&0o777==0o600
    assert audit[0]['status']=='REQUESTED' and audit[-1]['status']=='quarantined'
    assert result['permanently_deleted'] is False


def test_changed_file_cannot_be_quarantined(tmp_path,monkeypatch):
    source=tmp_path/'sample';source.write_bytes(b'first')
    monkeypatch.setattr(q,'ALLOWED_ROOTS',(tmp_path,))
    target=q.inspect_target(source);source.write_bytes(b'changed')
    with pytest.raises(ValueError,match='changed'):
        q.quarantine_target(target,lambda r:None,directory=tmp_path/'quarantine')
    assert source.read_bytes()==b'changed'


def test_symlink_and_hardlink_targets_are_rejected(tmp_path):
    source=tmp_path/'sample';source.write_bytes(b'fixture')
    link=tmp_path/'link';link.symlink_to(source)
    with pytest.raises(OSError):q.inspect_target(link)
    os.link(source,tmp_path/'hardlink')
    with pytest.raises(ValueError):q.inspect_target(source)


def test_system_paths_are_never_quarantined():
    with pytest.raises(PermissionError):q.quarantine_target({'path':'/etc/passwd'},lambda r:None)
    with pytest.raises(PermissionError):q.quarantine_target({'path':'/opt/satsuma-core/main.py'},lambda r:None)


def test_scanner_job_is_fixed_command_without_arbitrary_arguments(store):
    from satsuma.maintenance_jobs import MaintenanceJobs
    calls=[]
    def popen(command,**kw):
        calls.append(command);return NS(poll=lambda:None)
    jobs=MaintenanceJobs(store,popen=popen)
    try:
        assert jobs.start('security_scan')['accepted']
        assert calls==[['/usr/bin/systemctl','start','--wait','satsuma-core-security-scan-now.service']]
    finally:jobs.log.close()


def test_new_panels_are_registered_and_reachable():
    from PyQt6.QtWidgets import QApplication
    from satsuma.dashboard_qt.backend import ReaderUpdates
    from satsuma.dashboard_qt.windows.main_window import MainWindow
    app=QApplication.instance() or QApplication([])
    class Backend:
        updates=ReaderUpdates();client=None;db_path='fixture'
        def version(self):return 'test'
        def is_connected(self):return False
        def system_health(self):return {}
        def overview(self):return {}
        def call(self,*a,**kw):return {'items':[],'devices':[]}
        def close(self):pass
    window=MainWindow(Backend())
    try:
        window.nav.select('scanners');assert window.current_panel().PANEL_ID=='scanners'
        panel=window.current_panel()
        assert set(panel.cards)=={'clamav','rkhunter','chkrootkit'} and panel.table.minimumHeight()>=200
        window.nav.select('network_devices');assert window.current_panel().PANEL_ID=='network_devices'
        panel=window.current_panel();panel.decide('allow')
        assert 'Önce bir cihaz' in panel.status.text()
    finally:window.close()


def test_clamav_result_keeps_file_identity_and_rootkit_warning_does_not(tmp_path):
    from satsuma.security_scan import _result
    source=tmp_path/'test file';source.write_bytes(b'harmless fixture')
    def clam(command,stdout,**kw):
        stdout.write((str(source)+': Test.Signature FOUND\nInfected files: 1\n').encode())
        return NS(returncode=1)
    result=_result('clamav',['fixture-clamscan'],runner=clam,archive=tmp_path/'outputs')
    assert result['status']=='FINDINGS' and result['files'][0]['path']==str(source)
    assert result['files'][0]['sha256']==q.inspect_target(source)['sha256']
    def rootkit(command,stdout,**kw):
        stdout.write(b'Warning: suspicious configuration\n');return NS(returncode=0)
    result=_result('rkhunter',['fixture-rkhunter'],runner=rootkit,archive=tmp_path/'outputs')
    assert result['status']=='FINDINGS' and result['files']==[]


def test_device_decision_authentication_freshness_and_firewall_readback(store,monkeypatch):
    import time
    from satsuma.operator_service import OperatorController
    from network_fixture import table_json
    device={'device_id':'fixture','ip':'192.168.1.20','mac':'02:00:00:00:00:20','interface':'eth0',
            'last_seen':time.time(),'decision':'pending'}
    store.set('network_devices',{'fixture':device})
    store.set('network_discovery',{'neighbors':[device]})
    class Auth:
        def login(self,*a,**kw):return {'ok':True,'token':'session'}
        def validate_session(self,t):return t=='session'
    commands=[]
    def run(args,**kw):
        commands.append(args)
        return NS(returncode=0,stdout=table_json() if '-j' in args else '',stderr='')
    controller=OperatorController(store,auth=Auth(),runner=run,boot_provider=lambda:{'response_unlocked':True})
    with pytest.raises(PermissionError):controller.dispatch(1000,'device_decision',{'device_id':'fixture','decision':'block'})
    controller.dispatch(1000,'login',{})
    result=controller.dispatch(1000,'device_decision',{'token':'session','device_id':'fixture','decision':'block'})
    assert result['ok'] and store.get('network_devices')['fixture']['decision']=='block'
    assert any(cmd[1:3]==['get','element'] for cmd in commands)
    device['last_seen']=time.time()-100
    store.set('network_devices',{'fixture':device})
    with pytest.raises(ValueError,match='güncel'):
        controller.dispatch(1000,'device_decision',{'token':'session','device_id':'fixture','decision':'allow'})


def test_rule_inventory_reports_actual_zero_direct_prevention():
    result=dashboard_api.m_rules()
    assert result['active_total']==231  # RAM-106/107 retired
    assert result['direct_stop_total']==0 and result['without_direct_stop_total']==231
    assert result['native_prevention_verified_total'] is None
    assert all(not row['direct_stop_actions'] for row in result['rules'])


def test_missing_optional_chkrootkit_does_not_stop_other_engines(tmp_path,monkeypatch):
    from satsuma import security_scan
    host=HostStore(tmp_path/'optional-motor',test=True)
    calls=[]
    def which(name):return None if name=='chkrootkit' else '/usr/bin/'+name
    def result(tool,command,**kw):
        calls.append(tool)
        return {'timestamp':1,'completed_at':2,'tool':tool,'status':'COMPLETED','exit_code':0,'findings':0}
    monkeypatch.setattr(security_scan,'_result',result)
    try:
        rows=security_scan.run_once(store=host,which=which,binary_audit=lambda *a,**k:{},ssh_audit=lambda *a,**k:{},python_audit=lambda *a,**k:{},media_audit=lambda *a,**k:{},systemd_audit=lambda *a,**k:{},boot_correlator=lambda *a,**k:{},mitm_watch=lambda *a,**k:{},unhide=lambda:None)
        assert calls==['clamav','rkhunter']
        assert [row['status'] for row in rows]==['COMPLETED','COMPLETED','UNAVAILABLE']
        assert host.get('security_scan_health')['tools']=={'clamav':'COMPLETED','rkhunter':'COMPLETED','chkrootkit':'UNAVAILABLE'}
    finally:host.close()


def test_clamav_scans_are_readable_on_the_antivirus_page():
    """2.2.47 field report: ClamAV scans were not visible (seven buttons squeezed the table)."""
    import os
    os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
    import pytest
    pytest.importorskip('PyQt6.QtWidgets')
    from PyQt6.QtWidgets import QApplication
    from satsuma.dashboard_qt.panels.scanners import ScannersPanel
    app=QApplication.instance() or QApplication([])
    excerpt='/home/u/eicar.com: Win.Test.EICAR_HDB-1 FOUND\n----------- SCAN SUMMARY -----------\nScanned directories: 120\nScanned files: 184512\nInfected files: 1\nData scanned: 9876.43 MiB\nTime: 1532.118 sec (25 m 32 s)\n'
    clam={'_id':7,'timestamp':1763490000,'completed_at':1763491532,'tool':'clamav','status':'FINDINGS','findings':1,'exit_code':1,
          'output_excerpt':excerpt,'files':[{'path':'/home/u/eicar.com','signature':'Win.Test.EICAR_HDB-1','sha256':'a'*64}]}
    rk={'_id':8,'timestamp':1763491600,'tool':'rkhunter','status':'WARNING','findings':2,'exit_code':1}
    class Backend:
        def call(self,method,**kw):
            return {'items':[rk,clam],'engines':{'clamav':{'installed':True,'last_result':clam},'rkhunter':{'installed':True,'last_result':rk},
                    'chkrootkit':{'installed':False}},'data_state':'OK','scope':'yerel'}
    panel=ScannersPanel(Backend())
    try:
        panel.refresh()
        card=panel.cards['clamav'].text()
        assert '184.512 dosya' in card and '9876.43 MiB' in card and 'Bulunan: 1 dosya' in card
        assert 'rpm-ostree install chkrootkit' in panel.cards['chkrootkit'].text()
        assert panel.table.rowCount()==2
        panel.tool.setCurrentIndex(1)
        assert panel.table.rowCount()==1 and panel.table.item(0,3).text()=='184.512 dosya · 9876.43 MiB'
        panel.table.selectRow(0)
        assert 'eicar.com · Win.Test.EICAR_HDB-1' in panel.detail_view.text()
    finally:panel.close()
