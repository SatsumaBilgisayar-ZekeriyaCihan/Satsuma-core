"""Native Qt redesign contracts: truthful status, navigation and usable controls."""
import os,time
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
import pytest
pytest.importorskip('PyQt6.QtWidgets')
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from satsuma.dashboard_qt.backend import ReaderUpdates
from satsuma.dashboard_qt.windows.main_window import MainWindow
from satsuma.dashboard_qt.panels.overview import protection_view

@pytest.fixture(scope="module")
def app():
    value=QApplication.instance() or QApplication([])
    value.setStyle('Fusion')
    yield value

class Backend:
    client=None;db_path='fixture'
    def __init__(self):self.updates=ReaderUpdates();self.data={}
    def version(self):return 'test'
    def is_connected(self):return False
    def overview(self):return self.data
    def system_health(self):return {}
    def call(self,*args,**kwargs):return {}
    def close(self):pass

@pytest.fixture
def window(app):
    backend=Backend();backend.data={};value=MainWindow(backend)
    for timer in value._timers.values():timer.stop()
    value.app_notifications.timer.stop()
    yield value
    value.close()


def test_healthy_artwork_requires_all_three_successful_checks():
    assert protection_view({})[0]=='unknown'
    assert protection_view({'health_summary':{'overall':'Sağlıklı'}})[0]=='unknown'
    healthy={'overall':'Sağlıklı','files':'Sağlıklı','configuration':'Sağlıklı','protection':'Sağlıklı'}
    assert protection_view({'health_summary':healthy})[0]=='healthy'
    assert protection_view({'health_summary':{**healthy,'inconsistent':True}})[0]=='warning'
    assert protection_view({'health_summary':healthy,'system':{'critical_integrity':{'status':'CRITICAL'}}})[0]=='critical'


def test_sidebar_reaches_every_registered_panel_without_rebuilding_on_refresh(window):
    assert window.nav.current()=='overview'
    from satsuma.dashboard_qt import panels
    reachable={c.PANEL_ID for group in window.nav._groups for c in group}
    assert set(panels.all_ids())-{'tickets'}<=reachable
    window.nav.select('otx');item=window.nav.tools.item(0)
    # 'Ağ güvenliği' is the fourth section since 'Kayıtlar' (2.2.30).
    assert window.nav._buttons[3].isChecked()
    window.nav.select('network_response')
    assert window.nav.tools.item(0) is item
    assert window.stack.currentWidget().PANEL_ID=='network_response'


def test_home_shows_no_zero_counts_or_success_when_reader_has_no_data(window):
    home=window.stack.currentWidget();home.refresh()
    assert home.art.tone=='unknown' and 'doğrulanıyor' in home.status.text()
    assert home.cards['Son 24 saat bulgu'].text()=='—'
    assert home.cards['Aktif kurallar'].text()=='—'
    assert all(card.state.text()=='Doğrulanmadı' for card in home.security_cards.values())


def test_home_shortcuts_open_real_authenticated_application_settings(window):
    home=window.stack.currentWidget();home._open_apps()
    panel=window.stack.currentWidget()
    assert panel.PANEL_ID=='admin' and panel.sections.currentRow()==1
    assert not panel.token and all(not button.isEnabled() for button in panel._controls)


def test_desktop_is_native_dark_qt_with_bounded_sidebar_at_small_size(window,app):
    window.resize(1000,680);window.show();app.processEvents()
    assert window.nav.width()==236 and window.stack.width()<window.width()
    # Black-and-orange theme (2.2.30): the window background is Colors.BG_DEEP.
    assert '#050505' in window.styleSheet() and window.stack.currentWidget().scroll.widgetResizable()
    assert window.stack.currentWidget().inspect_button.isVisible()
    assert window.stack.currentWidget().scroll.horizontalScrollBar().maximum()==0


def test_activity_selection_survives_status_only_refresh(window):
    rows=[{'finding_id':'a','title':'First','timestamp':time.time(),'severity':'info'},{'finding_id':'b','title':'Second','timestamp':time.time(),'severity':'high'}]
    backend=window.backend;backend.data={'last_findings':rows};home=window.stack.currentWidget();home.refresh();home.table.selectRow(1)
    backend.data={**backend.data,'health_summary':{'overall':'Sorun var'}};home.refresh()
    assert home.table.currentRow()==1 and home.art.tone=='warning'


def test_failed_panel_construction_keeps_previous_screen(window):
    original = window.stack.currentWidget()
    placeholder = window._panels['findings']
    class Broken:
        def __init__(self, backend):
            raise RuntimeError('fixture construction failure')
    placeholder._panel_class = Broken
    window.nav.select('findings')
    assert window.stack.currentWidget() is original
    assert window.nav.current() == 'overview'


def test_failed_panel_activation_keeps_previous_screen(window):
    original = window.stack.currentWidget()
    from PyQt6.QtWidgets import QWidget
    class Broken(QWidget):
        def __init__(self, backend):
            super().__init__()
        def on_activate(self):
            raise RuntimeError('fixture activation failure')
    window._panels['findings']._panel_class = Broken
    window.nav.select('findings')
    assert window.stack.currentWidget() is original


def test_navigation_reports_initial_and_subsequent_timings(window):
    window.nav.select('findings')
    panel = window.stack.currentWidget()
    window.nav.select('overview')
    window.nav.select('findings')
    assert window.stack.currentWidget() is panel
    assert window._panel_timings[('findings', 'initial')] >= 0
    assert window._panel_timings[('findings', 'subsequent')] >= 0


def test_finding_selection_uses_record_identity_and_survives_loading(app):
    from satsuma.dashboard_qt.panels.findings import FindingsPanel
    backend = Backend()
    data = {'items': [{'finding_id': 'one', 'record_key': 'core:1', 'rule_id': 'same'},
                      {'finding_id': 'two', 'record_key': 'core:2', 'rule_id': 'same'}],
            'data_state': 'OK', 'total_count': 2, 'filtered_count': 2, 'has_more': True}
    backend.call = lambda *a, **k: data
    panel = FindingsPanel(backend)
    try:
        panel.refresh(); panel.table.selectRow(1)
        data = {**data, 'items': list(reversed(data['items']))}
        panel.refresh()
        assert panel._rows[panel.table.currentRow()]['finding_id'] == 'two'
        backend.call = lambda *a, **k: (_ for _ in ()).throw(ConnectionError('Veri arka planda yükleniyor'))
        panel.refresh()
        assert panel.table.rowCount() == 2
        assert panel._rows[panel.table.currentRow()]['finding_id'] == 'two'
        assert 'Toplam: 2' not in panel.status.text()  # pending state is explicit
    finally:
        panel.close()


def test_finding_paging_and_filter_changes_reset_offset(app):
    from satsuma.dashboard_qt.panels.findings import FindingsPanel
    backend = Backend(); calls = []
    def read(method, **params):
        calls.append(params)
        return {'items': [], 'data_state': 'OK', 'has_more': True}
    backend.call = read
    panel = FindingsPanel(backend)
    try:
        panel.refresh(); panel.next_page.click()
        assert calls[-1]['offset'] == 250
        panel._filter_widgets['rule_id'].setText('OLD')
        panel.refresh()
        assert calls[-1]['offset'] == 0 and calls[-1]['rule_id'] == 'OLD'
    finally:
        panel.close()
