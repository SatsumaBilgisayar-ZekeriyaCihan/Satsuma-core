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
        pages = ['home', 'activity', 'protection', 'health', 'settings'] if state == 'sorunlu' else ['home']
        for page in pages:
            try:
                window.nav.select(page)
                pump(0.6)
                window._refresh_all()
                pump(0.6)
                window.grab().save(str(out / f'{state}-{page}.png'))
                panel = window.current_panel()
                body = panel.page.scroll.widget() if hasattr(panel, 'page') else None
                if body is not None and body.height() > panel.height():
                    body.grab().save(str(out / f'{state}-{page}-tam.png'))
                print('saved', state, page, 'ok')
            except Exception as exc:
                import traceback
                traceback.print_exc()
                failures.append((state, page, repr(exc)))
        if state == 'sorunlu':
            for expert in ('findings', 'admin', 'records'):
                try:
                    window.nav.select(expert)
                    pump(0.6)
                    window.grab().save(str(out / f'uzman-{expert}.png'))
                    print('saved expert', expert)
                except Exception as exc:
                    failures.append(('expert', expert, repr(exc)))
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
