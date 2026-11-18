"""Qt6 regression of the shipped unbound-summary path; no host mutations.

Yayımlanan tanımsız summary yolunun Qt6 regresyonu; ana sistem değişmez.
"""
from types import SimpleNamespace
import pytest
from PyQt6.QtWidgets import QApplication
from satsuma.dashboard_qt.panels.integrity import IntegrityPanel


@pytest.fixture
def panel():
    app=QApplication.instance() or QApplication([])
    view=IntegrityPanel(SimpleNamespace(call=lambda *a,**k:{'summary':{'overall':'Sağlıklı'}}))
    yield view
    view.close()


def test_valid_dictionary_renders_summary_in_real_qt(panel):
    panel.refresh()
    assert any(row.get('value')=='Sağlıklı' for row in panel._rows)
    assert panel.table.rowCount()==9


@pytest.mark.parametrize('data',[None,[],False,'invalid',{}, {'summary':None}, {'summary':[]}, {'summary':'invalid'}])
def test_missing_or_malformed_data_never_crashes_or_claims_health(panel,data):
    rows=panel._rows_from(data)
    assert rows
    assert not any(row.get('value')=='Sağlıklı' for row in rows)


def test_failed_data_cannot_reuse_healthy_summary(panel):
    rows=panel._rows_from({'data_state':'UNKNOWN','error':'reader unavailable','summary':{'overall':'Sağlıklı'}})
    assert not any(row.get('value')=='Sağlıklı' for row in rows)
    assert any(row.get('value')=='reader unavailable' for row in rows)


def test_detail_failure_is_reported_until_a_successful_refresh(panel):
    panel.backend.call=lambda *a,**k:(_ for _ in ()).throw(RuntimeError('reader unavailable'))
    panel.refresh()
    assert 'integrity' in panel.backend.presentation_errors
    panel.backend.call=lambda *a,**k:{'summary':{'overall':'Sağlıklı'},'data_state':'OK'}
    panel.refresh()
    assert panel.backend.presentation_errors=={}


def test_repeated_render_error_cannot_be_cleared_by_render_cache(panel,monkeypatch):
    def fail(data):raise RuntimeError('synthetic render error')
    monkeypatch.setattr(panel,'_rows_from',fail)
    for _ in range(2):
        with pytest.raises(RuntimeError,match='synthetic render error'):panel.refresh()
        assert panel._last_render is None
        assert 'integrity' in panel.backend.presentation_errors
