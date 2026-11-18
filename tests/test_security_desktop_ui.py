"""Native Qt redesign contracts: truthful status, navigation and usable controls."""
import os,time
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
import pytest
pytest.importorskip('PyQt6.QtWidgets')
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from satsuma.dashboard_qt.backend import ReaderUpdates
from satsuma.dashboard_qt.windows.main_window import MainWindow

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


def test_sidebar_has_six_sections_and_every_page_is_a_tab(window):
    """2.2.47: no expert view; antivirus, firewall, application control and logs are sections of their own."""
    assert window.nav.current()=='home'
    from satsuma.dashboard_qt import panels
    from satsuma.dashboard_qt.windows.nav import PRIMARY, SECTION_OF
    assert [s for s,_,_ in PRIMARY]==['home','activity','antivirus','firewall','apps','protection','health','logs','settings']
    assert set(panels.all_ids())-{'tickets'}==set(SECTION_OF)
    assert not hasattr(window.nav,'tools') and not hasattr(window.nav,'set_expert')
    window.nav.select('otx')
    assert window.nav._buttons['firewall'].isChecked() and window.current_panel().PANEL_ID=='otx'
    assert window.sections['firewall'].buttons['otx'].isChecked()
    window.nav.select('scanners')
    assert window.nav._buttons['antivirus'].isChecked()
    window.nav.select('logs')
    assert window.current_panel().PANEL_ID=='logbook'
    window.nav.select('host_provenance')
    assert window.nav._buttons['health'].isChecked() and 'TPM' in window.topbar.title.text()
    window.nav.select('network')                      # section id of earlier builds
    assert window.current_panel().PANEL_ID=='firewall_settings'


def test_old_pages_are_gone():
    from pathlib import Path
    root=Path(__file__).parents[1]/'satsuma'/'dashboard_qt'/'panels'
    assert not (root/'admin.py').exists() and not (root/'overview.py').exists()


def test_home_shows_no_zero_counts_or_success_when_reader_has_no_data(window):
    home=window.current_panel();home.reload()
    assert home.art.tone=='unknown' and home.verdict.text()=='Durum alınamıyor'
    assert all(metric.value.text()=='—' for metric in home.metrics.values())


def test_links_open_the_page_that_resolves_them(window):
    window.open_target('expert:admin',{'section':'apps'})      # a link from before 2.2.47 goes nowhere harmful
    assert window.current_panel().PANEL_ID=='home'
    window.open_target('apps')
    assert window.current_panel().PANEL_ID=='apps' and window.nav._buttons['apps'].isChecked()
    window.open_target('protection:dns')                # the DNS card moved to the firewall settings
    assert window.current_panel().PANEL_ID=='firewall_settings'
    window.open_target('protection:process')
    assert window.current_panel().PANEL_ID=='protection'


def test_desktop_is_native_dark_qt_with_bounded_sidebar_at_small_size(window,app):
    window.resize(1060,700);window.show();app.processEvents()
    assert window.nav.width()==236 and window.stack.width()<window.width()
    assert '#050505' in window.styleSheet()
    page=window.current_panel().page
    assert page.scroll.widgetResizable() and page.scroll.horizontalScrollBar().maximum()==0


def test_activity_selection_survives_refresh_and_reordering(window):
    from satsuma import home_view
    now=time.time()
    findings=[(now,{'finding_id':'a','rule_id':'R1','event':{'exe':'/a'},'timestamp':now}),
              (now-5,{'finding_id':'b','rule_id':'R2','event':{'exe':'/b'},'timestamp':now-5})]
    rows=home_view.group_activity(findings,[])
    backend=window.backend
    backend.call=lambda method,**k:{'items':rows,'counts':{}} if method=='activity' else {}
    window.nav.select('activity');page=window.current_panel();page.reload()
    page.list.setCurrentRow(1);chosen=page.rows[1]['id']
    rows=list(reversed(rows));page.reload()
    assert page.rows[page.list.currentRow()]['id']==chosen


def test_failed_panel_construction_keeps_previous_screen(window,monkeypatch):
    from satsuma.dashboard_qt import panels
    original = window.current_panel()
    class Broken:
        def __init__(self, backend):
            raise RuntimeError('fixture construction failure')
    real=panels.get_panel
    monkeypatch.setattr(panels,'get_panel',lambda pid: Broken if pid=='findings' else real(pid))
    window.nav.select('findings')
    assert window.current_panel() is original
    assert window.nav.current() == 'home' and window.nav._buttons['home'].isChecked()
    assert 'fixture construction failure' in window.feedback.text.text()


def test_failed_panel_activation_keeps_previous_screen(window,monkeypatch):
    from satsuma.dashboard_qt import panels
    from PyQt6.QtWidgets import QWidget
    original = window.current_panel()
    class Broken(QWidget):
        def __init__(self, backend):
            super().__init__()
        def on_activate(self):
            raise RuntimeError('fixture activation failure')
    real=panels.get_panel
    monkeypatch.setattr(panels,'get_panel',lambda pid: Broken if pid=='findings' else real(pid))
    window.nav.select('findings')
    assert window.current_panel() is original


def test_navigation_reports_initial_and_subsequent_timings(window):
    window.nav.select('findings')
    panel = window.current_panel()
    window.nav.select('home')
    window.nav.select('findings')
    assert window.current_panel() is panel
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
