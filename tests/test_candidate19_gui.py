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
        # 2.2.47: the panel opens on "Durum"; application control is its own section.
        assert window.nav.current() == 'home'
        assert window.current_panel().PANEL_ID == 'home'
        window.nav.select('apps')
        panel = window.current_panel()
        assert panel.PANEL_ID == 'apps' and window.nav._buttons['apps'].isChecked()
        assert panel.duration.count() == 3 and panel.duration.currentData() == 'application'
        assert panel.switch.switch.known is False      # no reader: state unknown, not "off"
    finally:
        window.close()


def test_attention_strip_follows_what_waits_for_the_user_outside_home():
    """2.2.45: the strip under the top bar names what waits; it hides on Durum and when nothing waits."""
    app=QApplication.instance() or QApplication([])
    class Backend:
        updates=ReaderUpdates();client=None;db_path='test'
        items=[{'tone':'warning','title':'DNS filtresi çalışmıyor','actions':[]}]
        def call(self,method,**k):return {'attention':self.items} if method=='home' else {}
        def version(self):return '19.1'
        def is_connected(self):return False
        def close(self):pass
    backend=Backend();window=MainWindow(backend)
    try:
        window.nav.select('settings');window._refresh_attention()
        assert 'DNS filtresi çalışmıyor' in window.health_notice.text()
        assert not window.health_notice.isHidden()
        assert window.topbar.attention.text().strip()=='1'
        window.nav.select('home');window._refresh_attention()
        assert window.health_notice.isHidden()
        backend.items=[];window.nav.select('settings');window._refresh_attention()
        assert window.health_notice.isHidden() and window.topbar.attention.text()==''
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


def test_custom_malware_feed_field_is_on_the_protection_page():
    """2.2.47: user lists are added on Güvenlik duvarı → Ayarlar → DNS filtresi, through the shared lock."""
    import sys
    from pathlib import Path
    app=QApplication.instance() or QApplication([])
    sys.path.insert(0,str(Path(__file__).parents[1]/'tools'))
    from dashboard_fixture import FakeBackend
    window=MainWindow(FakeBackend())
    try:
        window.nav.select('firewall_settings');panel=window.current_panel();panel.reload()
        assert 'https://' in panel.list_url.placeholderText()
        texts=[panel.lists_box.itemAt(i).layout().itemAt(0).widget().text() for i in range(panel.lists_box.count()) if panel.lists_box.itemAt(i).layout()]
        assert 'https://lists.example.org/malware.txt' in texts
        acted=[];panel.act=lambda action,refresh=True:acted.append(action)
        panel.list_url.setText('https://feed.example/hosts');panel._add_list()
        assert acted==[{'method':'custom_list_update','params':{'url':'https://feed.example/hosts'}}]
    finally:window.close()
