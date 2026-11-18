#!/usr/bin/env python3
"""Save a PNG of every page of the Qt panel, using fixture data (CI: QT_QPA_PLATFORM=offscreen).

Usage: python3 tools/dashboard_screenshots.py OUTPUT_DIR
Qt panelinin her sayfasının görüntüsünü örnek veriyle kaydeder.
"""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))


def main(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    from satsuma.dashboard_qt.qt import QApplication, QTimer
    from satsuma.dashboard_qt.style.theme import GLOBAL_QSS
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setStyleSheet(GLOBAL_QSS)
    from dashboard_fixture import FakeBackend, FakeOperator
    from satsuma.dashboard_qt.session import OperatorSession
    from satsuma.dashboard_qt.windows.main_window import MainWindow

    def pump(seconds=0.4):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            app.processEvents()
            time.sleep(0.02)

    failures = []
    for state in ('sorunlu', 'saglikli'):
        operator = FakeOperator()
        session = OperatorSession(client_factory=lambda: operator)
        window = MainWindow(FakeBackend(healthy=state == 'saglikli'), session=session)
        window.resize(1400, 900)
        window.show()
        pump(0.8)
        from satsuma.dashboard_qt.windows.nav import SECTIONS
        # 2.2.47: every tab of every section (problem state); the healthy state shows Durum only.
        pages = [tab for _, _, _, tabs in SECTIONS for tab, _ in tabs] if state == 'sorunlu' else ['home']
        for index, page in enumerate(pages):
            try:
                window.nav.select(page)
                pump(0.5)
                window._refresh_all()
                pump(0.5)
                if window.current_panel() is None or window.current_panel().PANEL_ID != page:
                    raise RuntimeError('page did not open: ' + window.feedback.text.text())
                window.grab().save(str(out / f'{state}-{index:02d}-{page}.png'))
                panel = window.current_panel()
                body = panel.page.scroll.widget() if hasattr(panel, 'page') else None
                if body is not None and body.height() > panel.height():
                    body.grab().save(str(out / f'{state}-{index:02d}-{page}-tam.png'))
                print('saved', state, page, 'ok')
            except Exception as exc:
                import traceback
                traceback.print_exc()
                failures.append((state, page, repr(exc)))
        if state == 'sorunlu':
            # The antivirus page with the ClamAV scan selected, and the log with a record chosen.
            for page in ('scanners', 'logbook'):
                window.nav.select(page)
                pump(0.4)
                panel = window.current_panel()
                if panel.table.rowCount():
                    panel.table.selectRow(2 if page == 'scanners' else 0)
                pump(0.3)
                window.grab().save(str(out / f'secili-{page}.png'))
            # The activity page with a row chosen and the lock open.
            session.token = 't' * 32
            session.changed.emit(True)
            window.open_target('activity')
            pump(0.6)
            window.grab().save(str(out / 'sorunlu-activity-kilit-acik.png'))
            from satsuma.dashboard_qt.session import PasswordDialog
            dialog = PasswordDialog('Yönetici kilidini aç', 'Ayarları değiştirmek için yönetici parolanızı girin. Kilit 30 dakika açık kalır.', window)
            dialog.show()
            pump(0.3)
            dialog.grab().save(str(out / 'parola-penceresi.png'))
            dialog.close()
        window.close()
        pump(0.3)
    print('failures:', failures)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else 'shots'))
