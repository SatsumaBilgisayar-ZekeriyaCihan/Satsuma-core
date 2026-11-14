"""Read-only Qt dashboard; management auth lives in the operator service."""
import sys
try:
    from PyQt6.QtWidgets import QApplication
except ImportError:
    from PyQt5.QtWidgets import QApplication
from .style.theme import GLOBAL_QSS
from .windows.main_window import MainWindow
from .backend import Backend


def run():
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName('Satsuma Internet Security')
    app.setOrganizationName('SatsumaBilgisayar')
    app.setStyle('Fusion')
    app.setStyleSheet(GLOBAL_QSS)
    backend = Backend()
    win = MainWindow(backend)
    win.show()
    return app.exec()


if __name__ == '__main__':
    sys.exit(run())
