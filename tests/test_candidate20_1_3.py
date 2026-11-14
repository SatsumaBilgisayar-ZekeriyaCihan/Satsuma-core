"""Source-level evidence and offscreen UI regression tests; no Fedora claims."""
import json
import os
import sqlite3
import time
from pathlib import Path
import pytest
from satsuma.status_view import health_summary,label,timestamp
from satsuma.audit_host import event
from satsuma.presentation import action_view


def test_health_separates_file_config_and_functional_results():
    result=health_summary({'status':'POLICY_INVALID','checked_at':100,'checks':{'application':{'ok':True},'configuration':{'ok':False}}},{},{'status':'PASSED','updated_at':100},now=110)
    assert result['files']=='Sağlıklı' and result['configuration']=='Sorun var'
    assert result['overall']=='Sorun var' and result['inconsistent']
    assert 'doğrulanmadı' in result['host_scope']


def test_stale_or_missing_evidence_never_becomes_healthy():
    assert health_summary({}, {}, {}, now=1000)['overall']=='Durum alınamıyor'
    assert health_summary({'status':'HEALTHY','checked_at':100},{},{'status':'PASSED','updated_at':100},now=1001)['overall']=='Durum alınamıyor'
    assert health_summary({'status':'HEALTHY','checked_at':100},{},{'status':'PASSED','updated_at':100},now=110)['overall']=='Sağlıklı'


def test_audit_user_start_nested_fields_and_absent_success():
    line="type=USER_START msg=audit(100.123:80): pid=42 uid=1000 auid=1000 msg='op=PAM:session_open acct=\"alice\" exe=\"/usr/bin/login\" terminal=tty1 res=success'"
    parsed=event([line],True)
    assert parsed['pid']=='42' and parsed['uid']=='1000'
    assert parsed['exe']=='/usr/bin/login' and parsed['acct']=='alice' and parsed['success']=='yes'
    unknown=event(['type=USER_START msg=audit(100.124:81): pid=43 uid=1001'],True)
    assert 'success' not in unknown


def test_internal_records_and_requests_are_not_block_proof():
    assert action_view({'action':'record'})['internal']
    assert action_view({'status':'REQUESTED'})['outcome']=='Onay bekliyor'
    assert 'Engellendi' not in action_view({'status':'completed'})['outcome']
    assert 'doğrulandı' in action_view({'traffic_drop_verified':True})['outcome']
    assert action_view({'_record_created':123,'ip':'1.2.3.4'})['timestamp']==123


def test_journal_temp_failure_publishes_degraded_health(monkeypatch):
    from satsuma.worker_journal import WorkerJournal
    class Store:
        health=None
        def set(self,key,value):self.health=value
    store=Store()
    def denied():raise PermissionError('No usable temporary directory')
    monkeypatch.setattr('satsuma.worker_journal.tempfile.TemporaryFile',denied)
    result=WorkerJournal(store).tick(object())
    assert result['status']=='DEGRADED' and store.health==result
    assert 'temporary' in result['error']


def test_gateway_last_check_is_valid_heartbeat(tmp_path,monkeypatch):
    import satsuma.dashboard_api as api
    core=tmp_path/'core.db';host=tmp_path/'host.db'
    for path in (core,host):
        with sqlite3.connect(path) as db:db.execute('CREATE TABLE state(key TEXT PRIMARY KEY,body TEXT)')
    with sqlite3.connect(core) as db:db.execute('INSERT INTO state VALUES(?,?)',('gateway_health',json.dumps({'status':'running','last_check':time.time(),'events':0})))
    monkeypatch.setattr(api,'_connect',lambda:sqlite3.connect(core));monkeypatch.setattr(api,'_connect_host',lambda:sqlite3.connect(host))
    item=api.m_workers()['gateway']
    assert item['status']=='RUNNING' and item['last_successful_event'] is None and item['error_count'] is None


os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
@pytest.fixture
def qt():
    widgets=pytest.importorskip('PyQt6.QtWidgets')
    app=widgets.QApplication.instance() or widgets.QApplication([])
    yield app


def test_choices_preserve_selection_and_do_not_retarget_removed_request(qt):
    from satsuma.dashboard_qt.stable_widgets import StableComboBox,update_choices
    widget=StableComboBox()
    update_choices(widget,[('One','a'),('Two','b')]);assert widget.currentIndex()==-1
    widget.setCurrentIndex(1)
    update_choices(widget,[('Three','c'),('Two (2 connections)','b')]);assert widget.currentData()=='b'
    update_choices(widget,[('Three','c')]);assert widget.currentIndex()==-1


def test_admin_pages_keep_text_focus_scroll_and_selection(qt):
    from satsuma.dashboard_qt.panels.admin import AdminPanel
    panel=AdminPanel(object());panel.resize(1000,600);panel.show()
    titles=[panel.sections.item(i).text() for i in range(panel.sections.count())]
    assert titles==['Genel durum','Uygulama izinleri','Ağ koruması','İnternet trafiği','DNS ve tehdit listeleri','Servisler','Yönetici erişimi ve doğrulama','VPN / Proxy']
    panel.sections.setCurrentRow(4);panel.dns_upstream.setText('192.0.2.53');panel.dns_upstream.setFocus();qt.processEvents()
    scroll=panel.pages.currentWidget().verticalScrollBar();scroll.setValue(50);before=scroll.value()
    result={'app_control':{'pending':[{'id':'a','application':{'executable':'/bin/brave','uid':1000},'destination':'1.1.1.1:443'}]}}
    panel._done('status',result);panel.app_requests.setCurrentIndex(0)
    panel._done('status',result)
    assert panel.dns_upstream.text()=='192.0.2.53' and panel.dns_upstream.hasFocus()
    assert scroll.value()==before and panel.app_requests.currentData()=='a'
    assert panel.sections.currentRow()==4
    panel.close()


def test_permission_window_freezes_application_and_waits_for_applied(qt):
    from satsuma.dashboard_qt.app_notifications import AppNotifications
    class Backend:
        data={'status':'ACTIVE','pending':[{'id':'a','application':{'executable':'/bin/brave'},'destination':'1.1.1.1:443'}]}
        def call(self,*a,**k):return self.data
    class Window:backend=Backend()
    widget=AppNotifications(Window());widget.timer.stop();widget.poll()
    assert widget.parent() is None and widget.active['id']=='a'
    Window.backend.data={'status':'ACTIVE','pending':[{'id':'b','application':{'executable':'/bin/other'},'destination':'2.2.2.2:443'}]}
    widget.poll();assert widget.active['id']=='a' and 'brave' in widget.message.text()
    widget.done_request({'application_control':{'status':'REQUESTED','command_id':'cmd'}})
    assert widget.command_id=='cmd' and 'uygulandı' not in widget.result.text()
    Window.backend.data['last_command']={'id':'other','status':'APPLIED'};widget.poll();assert widget.command_id=='cmd'
    Window.backend.data['last_command']={'id':'cmd','status':'FAILED','error':'Request expired'};widget.poll()
    assert widget.command_id is None and 'uygulanamadı' in widget.result.text()
    widget.close()


def test_table_preserves_selected_record_when_new_rows_arrive(qt):
    from satsuma.dashboard_qt.panels.auto_actions import AutoActionsPanel
    class Backend:
        data=[{'_id':1,'timestamp':100,'action':'block','ip':'192.0.2.1'}, {'_id':2,'timestamp':101,'action':'block','ip':'192.0.2.2'}]
        def call(self,*a,**k):return self.data
    backend=Backend();panel=AutoActionsPanel(backend);panel.refresh();panel.table.selectRow(1)
    backend.data=[{'_id':3,'timestamp':102,'action':'block','ip':'192.0.2.3'},*backend.data]
    panel.refresh();assert panel._rows[panel.table.currentRow()]['_id']==2
    panel.close()


def test_numeric_timestamp_and_missing_labels():
    assert '1970' in timestamp(100)
    assert label('RUNNING')=='Çalışıyor' and label('STALE')=='Durum bildirimi gecikti'
    assert label(None)=='Kayıtta belirtilmemiş'


def test_runtime_integrity_is_not_hidden_by_missing_legacy_state(tmp_path,monkeypatch):
    import satsuma.dashboard_api as api
    path=tmp_path/'core.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE state(key TEXT PRIMARY KEY,body TEXT)')
        db.execute('CREATE TABLE records(id INTEGER,created REAL,kind TEXT,body TEXT)')
        db.execute('INSERT INTO state VALUES(?,?)',('integrity_runtime',json.dumps({'status':'HEALTHY','checked_at':time.time()})))
    monkeypatch.setattr(api,'_connect',lambda:sqlite3.connect(path))
    result=api.m_integrity()
    assert result['status']=='HEALTHY' and result['data_state']=='OK'
    assert result['summary']['files']=='Sağlıklı' and result['summary']['protection']=='Durum alınamıyor'


def test_memory_scanner_processes_safe_fixture_and_zero_is_not_healthy(tmp_path):
    from satsuma.worker_memory import WorkerMemory
    class Store:
        data={}
        def get(self,key,default=None):return self.data.get(key,default)
        def set(self,key,value):self.data[key]=value
        def add(self,*args):pass
    class Pipeline:
        events=[]
        def ingest_host(self,event):self.events.append(event)
    store=Store();pipeline=Pipeline();pid=tmp_path/'42';pid.mkdir()
    # stat starttime is offset 19 in the fields after the closing parenthesis.
    (pid/'stat').write_text('42 (fixture) '+' '.join(['0']*19+['100']))
    (pid/'exe').symlink_to('/usr/bin/safe-fixture')
    (pid/'maps').write_text('1000-2000 r-xp 0 00:00 0 /usr/bin/safe-fixture\n')
    WorkerMemory(store,proc_root=tmp_path).tick(pipeline)
    assert store.data['worker.memory.health']['inspected']==1 and not pipeline.events
    empty=tmp_path/'empty';empty.mkdir()
    WorkerMemory(store,proc_root=empty).tick(pipeline)
    assert store.data['worker.memory.health']['inspected']==0 and store.data['worker.memory.health']['status']=='DEGRADED'


def test_action_filter_refreshes_when_backend_data_is_unchanged(qt):
    from satsuma.dashboard_qt.panels.auto_actions import AutoActionsPanel
    class Backend:
        def call(self,*a,**k):return [{'action':'record'},{'action':'network.block','ip':'192.0.2.1'}]
    panel=AutoActionsPanel(Backend());panel.refresh();assert len(panel._rows)==1
    panel._filter_widgets['search'].setText('no match');panel.refresh();assert len(panel._rows)==0
    panel._filter_widgets['search'].clear();panel._filter_widgets['kind'].setCurrentIndex(2);panel.refresh()
    assert len(panel._rows)==1 and panel._rows[0]['internal']
    panel.close()


def test_old_status_reply_cannot_unlock_or_overwrite_active_mutation(qt):
    from satsuma.dashboard_qt.panels.admin import AdminPanel
    panel=AdminPanel(object());panel.token='session';panel._busy=True;panel._reading_status=True
    panel.status.setText('Karar uygulanıyor');panel._mutation_serial=2
    panel._done('status',{'_ui_generation':1,'app_control':{}})
    assert panel._busy and panel.status.text()=='Karar uygulanıyor' and not panel._reading_status
    panel._busy=False
    panel._done('status',{'_ui_generation':1,'app_control':{}})
    assert panel.status.text()=='Karar uygulanıyor'
    panel.close()
