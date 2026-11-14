"""Offscreen Qt integration; no host service or privileged operation is called."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
pytest.importorskip('PyQt6.QtWidgets')
from PyQt6.QtWidgets import QApplication
from satsuma.dashboard_qt.backend import ReaderUpdates
from satsuma.dashboard_qt.windows.main_window import MainWindow


def test_security_home_opens_and_application_management_controls_are_real_widgets():
    app = QApplication.instance() or QApplication([])
    class Backend:
        updates = ReaderUpdates()
        client = None
        db_path = 'test-reader'
        def version(self): return 'test'
        def is_connected(self): return False
        def system_health(self): return {}
        def overview(self): return {}
        def close(self): pass
    window = MainWindow(Backend())
    try:
        assert window.nav.current() == 'overview'
        assert window.stack.currentWidget().PANEL_ID == 'overview'
        assert not hasattr(window.stack.currentWidget(), '_panel_class')
        window.nav.select('admin')
        panel = window.stack.currentWidget()
        assert panel.PANEL_ID == 'admin'
        assert panel.app_requests.count() == 0
        assert panel.app_rules.count() == 0
        assert panel.app_duration.count() == 3
        assert all(not button.isEnabled() for button in panel._controls)
        panel._done('application_control', {'ok': True, 'application_control': {'enabled': False}})
        assert 'False' in panel.status.text()
    finally:
        window.close()


def test_health_check_banner_running_and_degraded():
    app=QApplication.instance() or QApplication([])
    class Backend:
        updates=ReaderUpdates();client=None;db_path='test'
        state='RUNNING'
        def call(self,*a,**k):return {'status':self.state}
        def version(self):return '19.1'
        def is_connected(self):return False
        def system_health(self):return {}
        def overview(self):return {}
        def close(self):pass
    backend=Backend();window=MainWindow(backend)
    try:
        window._refresh_self_health()
        assert 'Sağlık kontrol ediliyor' in window.health_notice.text()
        assert not window.health_notice.isHidden()
        backend.state='DEGRADED';window._refresh_self_health()
        assert 'sorun buldu' in window.health_notice.text()
        backend.state='PASSED';window._refresh_self_health()
        assert window.health_notice.isHidden()
    finally:window.close()


def test_welcome_setup_shows_plan_before_yes_and_detailed_has_no_preselection():
    app=QApplication.instance() or QApplication([])
    from satsuma.dashboard_qt.modem_setup import ModemSetup
    widget=ModemSetup()
    candidate={'id':'candidate','gateway':'192.168.1.1','gateway_mac':'02:00:00:00:00:02','interface':'eth0','table':'254'}
    plan={'ready_for_automatic':True,'candidate':candidate,'route_fingerprint':'a'*64,
          'summary':['Modem adayı: 192.168.1.1','Bu cihaz tek referans kaydedilecek.'],
          'inventory':{'tables':['254','255'],'routes':[],'rules':[],'candidates':[candidate]}}
    try:
        assert not widget.yes.isEnabled() and widget.plan is None
        widget.done('preview',plan)
        assert 'ayarlarınız şöyle' in widget.summary.text()
        assert '192.168.1.1' in widget.summary.text()
        assert widget.yes.isEnabled()
        widget.apply() # No password: no worker thread or privileged request.
        assert not widget.busy and 'parolanızı' in widget.summary.text()
        widget.detailed=True;widget.done('preview',plan)
        assert widget.choices.currentIndex()==-1
        assert '254' in widget.tables.toPlainText()
        widget.done('apply',{'error':'Network changed since preview'})
        assert widget.plan is None and not widget.yes.isEnabled()
    finally:widget.close()


def test_custom_malware_feed_field_is_connected_to_management_widgets():
    app=QApplication.instance() or QApplication([])
    class Backend:
        updates=ReaderUpdates();client=None;db_path='test'
        def version(self):return 'test'
        def is_connected(self):return False
        def system_health(self):return {}
        def overview(self):return {}
        def close(self):pass
    window=MainWindow(Backend())
    try:
        window.nav.select('admin');panel=window.stack.currentWidget()
        assert 'https://' in panel.custom_list_url.placeholderText()
        panel._done('custom_list_update',{'ok':True,'active':False,'custom_lists':{'sources':[{'url':'https://feed.example/hosts','count':12}]}})
        assert '12' in panel.custom_list_status.text() and 'aktif değil' in panel.custom_list_status.text()
        panel._done('custom_list_update',{'ok':True,'active':True,'custom_lists':{'sources':[{'url':'https://feed.example/hosts','count':12}]}})
        assert 'uygulandı' in panel.custom_list_status.text()
    finally:window.close()
