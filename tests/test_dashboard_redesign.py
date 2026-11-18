"""2.2.45 panel redesign, offscreen: lock, switches, actions and pages with fixture data.

Yeni panel ekransız sınanır: kilit, anahtarlar, eylemler ve sayfalar örnek veriyle.
"""
import os
import sys
import time
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import pytest
pytest.importorskip('PyQt6.QtWidgets')
from PyQt6.QtWidgets import QApplication

sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
from dashboard_fixture import FakeBackend, FakeOperator  # noqa: E402
from satsuma.dashboard_qt.session import OperatorSession  # noqa: E402
from satsuma.dashboard_qt.windows.main_window import MainWindow  # noqa: E402


@pytest.fixture(scope='module')
def app():
    value = QApplication.instance() or QApplication([])
    value.setStyle('Fusion')
    yield value


def wait(app, predicate, seconds=3.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


class Session(OperatorSession):
    def __init__(self, operator, passwords):
        super().__init__(client_factory=lambda: operator)
        self.passwords = list(passwords)
        self.asked = []

    def ask_password(self, parent, title, explanation, confirm):
        self.asked.append(title)
        return self.passwords.pop(0) if self.passwords else None


@pytest.fixture
def make(app):
    windows = []

    def build(healthy=False, passwords=()):
        operator = FakeOperator()
        session = Session(operator, passwords)
        window = MainWindow(FakeBackend(healthy), session=session)
        for timer in window._timers.values():
            timer.stop()
        windows.append(window)
        app.processEvents()
        return window, session, operator
    yield build
    for window in windows:
        window.close()


def test_opens_on_status_with_verdict_waiting_items_and_layers(make):
    window, _, _ = make()
    page = window.current_panel()
    page.reload()
    assert page.PANEL_ID == 'home'
    assert page.verdict.text().endswith('sizi bekliyor')
    titles = [page.attention_box.itemAt(i).widget().item['title'] for i in range(page.attention_box.count())]
    assert '2 sağlık kontrolü başarısız' in titles and 'firefox internete çıkmak istiyor' in titles
    assert titles[-1] == 'Tehdit istihbaratı için OTX anahtarı ekleyin'   # suggestions last
    assert page.layers_grid.count() == 6
    assert page.metrics['stopped'].value.text() == '1'


def test_healthy_machine_says_protected(make):
    window, _, _ = make(healthy=True)
    page = window.current_panel()
    page.reload()
    assert page.verdict.text() == 'Korunuyorsunuz' and page.art.tone == 'healthy'


def test_repair_button_unlocks_then_runs_the_maintenance_kit(make, app):
    window, session, operator = make(passwords=['dogru'])
    page = window.current_panel()
    page.reload()
    row = next(page.attention_box.itemAt(i).widget() for i in range(page.attention_box.count())
               if page.attention_box.itemAt(i).widget().item['id'] == 'health')
    page.act(row.item['actions'][0])
    assert wait(app, lambda: ('repair', {}) in operator.calls)
    assert session.asked == ['Yönetici kilidini aç'] and session.unlocked()
    assert wait(app, lambda: 'Bakım kiti' in window.feedback.text.text())
    assert window.topbar.lock.text().strip() == 'Kilit açık'


def test_wrong_password_keeps_the_lock_closed(make, app):
    window, session, operator = make(passwords=['yanlis'])
    session.unlock(window)
    assert wait(app, lambda: 'Parola yanlış' in window.feedback.text.text())
    assert not session.unlocked() and [c[0] for c in operator.calls] == ['login']


def test_turning_protection_down_asks_the_password_again(make, app):
    window, session, operator = make(passwords=['dogru', 'dogru'])
    window.nav.select('protection')
    page = window.current_panel()
    page.reload()
    row = page.switches['enforcement']
    assert row.switch.known and row.switch.isChecked()
    row.switch.click()                      # off: lowers protection
    assert wait(app, lambda: any(c[0] == 'enforcement' for c in operator.calls))
    assert session.asked == ['Yönetici kilidini aç', 'Korumayı azaltan işlem']
    assert ('enforcement', {'enabled': False}) in operator.calls


def test_switch_shows_unknown_until_the_state_is_read(app):
    from satsuma.dashboard_qt.ui import SettingRow
    row = SettingRow('Deneme', 'açıklama')
    row.set(None)
    assert not row.switch.known and row.state.text() == 'Bilinmiyor'
    row.set(False)
    assert row.switch.known and not row.switch.isChecked() and row.state.text() == 'Kapalı'


def test_activity_folds_repeats_and_offers_actions(make, app):
    window, session, operator = make(passwords=['dogru', 'dogru'])
    window.nav.select('activity')
    page = window.current_panel()
    page.reload()
    fileless = next(r for r in page.rows if r['rule_id'] == 'SATSUMA-FILELESS-002')
    assert fileless['count'] == 11 and fileless['outcome'] == 'reported'
    blocked = next(i for i, r in enumerate(page.rows) if r['outcome'] == 'blocked')
    page.list.setCurrentRow(blocked)
    unblock = next(a for a in page.rows[blocked]['actions'] if a.get('method') == 'unblock')
    page.act(unblock)
    assert wait(app, lambda: ('unblock', {'ip': '203.0.113.77'}) in operator.calls)
    assert session.asked[-1] == 'Korumayı azaltan işlem'


def test_search_in_the_top_bar_filters_the_activity(make, app):
    window, _, _ = make()
    window.topbar.search.setText('mount_')
    window.topbar.search.returnPressed.emit()
    page = window.current_panel()
    assert page.PANEL_ID == 'activity'
    assert page.rows and all('mount_' in r['subject'] for r in page.rows)


def test_every_user_page_and_expert_page_opens(make, app):
    window, _, _ = make()
    for panel_id in ('home', 'activity', 'protection', 'health', 'settings', 'findings', 'admin', 'records', 'system_health'):
        window.nav.select(panel_id)
        app.processEvents()
        assert window.current_panel().PANEL_ID == panel_id, panel_id


def test_expert_view_can_be_hidden_and_comes_back_when_asked_for(make, app):
    window, _, _ = make()
    window.nav.set_expert(False)
    assert window.nav.tools.isHidden()
    window.open_target('expert:suricata')
    assert window.nav.expert_visible() and window.current_panel().PANEL_ID == 'suricata'


def test_advanced_management_page_shares_the_lock(make, app):
    window, session, operator = make(passwords=['dogru'])
    session.unlock(window)
    assert wait(app, session.unlocked)
    window.nav.select('admin')
    assert window.current_panel().token == session.token
    session.lock()
    assert window.current_panel().token is None
