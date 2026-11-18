import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import pytest
pytest.importorskip('PyQt6')
from PyQt6.QtWidgets import QApplication
from satsuma.dashboard_qt.panels.events import EventsPanel
from satsuma.dashboard_qt.panels.findings import FindingsPanel


def test_desktop_tables_show_priority_date_process_and_pid():
    app = QApplication.instance() or QApplication([])
    rows = [{'action': 'execve', 'severity': 'low', 'timestamp': 300, 'comm': 'lowproc', 'pid': 7},
            {'action': 'execve', 'severity': 'critical', 'classification': 'confirmed', 'timestamp': 100, 'comm': 'criticalproc', 'pid': 42}]
    class Backend:
        def rows(self, *a, **k): return rows
        def call(self, *a, **k): return {'items': rows, 'data_state': 'OK'}
    events = EventsPanel(Backend()); findings = FindingsPanel(Backend())
    try:
        events.refresh(); findings.refresh()
        for panel in (events, findings):
            assert panel.table.rowCount() == 2
            assert panel.table.item(0, 0).text() == 'Kritik'
            assert panel.table.item(0, 1).text() == 'Doğrulanmış'
            assert '1970' in panel.table.item(0, 2).text()
            assert panel.table.item(0, 3).text() == 'criticalproc'
            assert panel.table.item(0, 4).text() == '42'
    finally:
        events.close(); findings.close()
