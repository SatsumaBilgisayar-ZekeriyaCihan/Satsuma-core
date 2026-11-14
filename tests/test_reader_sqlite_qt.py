"""Real SQLite -> socket -> async backend -> native Qt findings panel."""
import time
import threading

import pytest
pytest.importorskip('PyQt6.QtWidgets')

from PyQt6.QtWidgets import QApplication
from satsuma import dashboard_api as api
from satsuma.dashboard_api_client import ReaderClient
from satsuma.dashboard_qt.async_reader import AsyncReader
from satsuma.dashboard_qt.backend import Backend
from satsuma.dashboard_qt.panels.findings import FindingsPanel
from test_reader_findings_pagination import databases


def test_historical_findings_reach_qt_without_blocking_gui(databases, tmp_path):
    app = QApplication.instance() or QApplication([])
    socket_path = str(tmp_path / 'reader.sock')
    server = api.Server(socket_path, api.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    backend = Backend()
    backend.close()
    backend.client = AsyncReader(ReaderClient(socket_path), backend.updates.updated.emit, ttl=60)
    panel = FindingsPanel(backend)
    backend.updates.updated.connect(panel.refresh)
    try:
        panel._filter_widgets['rule_id'].setText('OLD')
        start = time.perf_counter()
        panel.refresh()
        assert time.perf_counter() - start < 0.2
        deadline = time.monotonic() + 10
        while panel.table.rowCount() != 3 and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        assert {item['finding_id'] for item in panel._rows} == {'host-00000', 'core-0', 'old-core-event'}
        assert 'Toplam: 15004' in panel.status.text()
        assert 'Filtrelenen: 3' in panel.status.text()
        assert not panel.next_page.isEnabled()
    finally:
        backend.updates.updated.disconnect(panel.refresh)
        panel.close()
        backend.close()
        backend.client._thread.join(timeout=4)
        server.shutdown();server.server_close();thread.join(timeout=2)
