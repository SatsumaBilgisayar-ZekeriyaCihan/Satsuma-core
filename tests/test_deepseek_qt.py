"""Real Qt widgets, background requests and existing authenticated controller."""
import json
import threading
import time
import uuid
from unittest.mock import Mock
import pytest
pytest.importorskip('PyQt6.QtWidgets')
from PyQt6.QtWidgets import QApplication,QMessageBox
from satsuma.dashboard_qt.panels import deepseek as ui
from test_deepseek_secure_workflow import proposal,store


@pytest.fixture(scope='module')
def app():
    value=QApplication.instance() or QApplication([])
    yield value


@pytest.fixture
def panel(app):
    value=ui.DeepSeekPanel(Mock())
    value._token=lambda:'fixture-session'
    value.refresh()
    value.editor.setPlainText(json.dumps(proposal()));value.rule_id.setText(proposal()['rule_id'])
    value.reason.setText('isolated review decision');value.signature.setPlainText('-----BEGIN PGP SIGNATURE-----\nfixture')
    yield value
    value.close()


def wait(app,panel):
    end=time.monotonic()+5
    while panel._busy and time.monotonic()<end:
        app.processEvents();time.sleep(.005)
    assert not panel._busy


def test_every_deepseek_button_routes_to_existing_operator_channel(panel,app,monkeypatch):
    seen=[]
    class Client:
        def __init__(self,path,timeout):assert path==ui.SOCKET_PATH
        def call(self,method,**params):seen.append((method,params));return {'ok':True}
    monkeypatch.setattr(ui,'ReaderClient',Client)
    monkeypatch.setattr(ui.QMessageBox,'question',lambda *a:QMessageBox.StandardButton.Yes)
    for method,button in panel._buttons.items():
        panel.consent.setChecked(True);button.click();wait(app,panel)
        assert seen[-1][0]==method
        assert seen[-1][1]['token']=='fixture-session'
    assert len(seen)==len(panel._buttons)
    assert {'deepseek_approve','deepseek_activate','deepseek_verify_signature'}<=set(panel._buttons)


def test_request_wait_is_nonblocking_and_duplicate_click_coalesced(panel,app,monkeypatch):
    entered=threading.Event();release=threading.Event();calls=[]
    class Client:
        def __init__(self,*a,**k):pass
        def call(self,method,**params):
            calls.append(method);entered.set();release.wait(3);return {'ok':True}
    monkeypatch.setattr(ui,'ReaderClient',Client)
    start=time.perf_counter();panel._send('deepseek_status')
    assert time.perf_counter()-start<.2
    assert entered.wait(1)
    panel._send('deepseek_status');assert panel._busy
    assert all(not button.isEnabled() for button in panel._buttons.values())
    # Deactivation does not rebuild the panel or discard a pending operation.
    panel.on_deactivate();panel.on_activate();assert panel._busy
    release.set();wait(app,panel)
    assert calls==['deepseek_status']


def test_no_network_without_consent_and_no_fabricated_success(panel,app,monkeypatch):
    client=Mock();monkeypatch.setattr(ui,'ReaderClient',client)
    panel._send('deepseek_generate');client.assert_not_called()
    assert 'onay' in panel.status.text()
    panel._done('deepseek_activate',{'ok':False,'activated':False,'error':'signature_invalid'})
    assert 'tamamlanamadı' in panel.status.text() and not panel._payload


def test_authentication_required_and_private_key_input_rejected(panel,app,monkeypatch):
    panel._token=lambda:None;panel.refresh()
    assert all(not button.isEnabled() for button in panel._buttons.values())
    panel._send('deepseek_status');assert 'oturumu' in panel.status.text()
    panel._token=lambda:'fixture-session';panel.refresh()
    panel.signature.setPlainText('-----BEGIN PGP PRIVATE KEY BLOCK-----')
    panel._send('deepseek_verify_signature');assert not panel._busy
    assert 'Özel anahtar' in panel.status.text()


def test_qt_preview_submit_queue_and_approval_use_actual_backend(panel,app,monkeypatch,store):
    from satsuma.operator_service import OperatorController
    from satsuma import deepseek_client
    # SQLite Store is thread-bound: create a backend connection inside its
    # worker, just as the real Operator process owns its own connection.
    directory=store.directory
    auth=Mock();auth.validate_session.return_value=True
    package=proposal()
    monkeypatch.setattr(deepseek_client,'generate_rule',lambda *a,**k:package)
    class Client:
        def __init__(self,*a,**k):pass
        def call(self,method,**params):
            from satsuma.store import Store
            backend=Store(directory,test=True)
            try:
                controller=OperatorController(backend,auth=auth,config={'deepseek_enabled':True,'rule_adapter_enabled':True})
                controller.owners['fixture-session']=1000
                return controller.dispatch(1000,method,params)
            finally:backend.close()
    monkeypatch.setattr(ui,'ReaderClient',Client)
    panel.consent.setChecked(True);panel._send('deepseek_generate');wait(app,panel)
    assert json.loads(panel.editor.toPlainText())==package
    panel._send('deepseek_test_rule');wait(app,panel)
    assert json.loads(panel.result.toPlainText())['test_report']['passed']
    panel._send('deepseek_submit');wait(app,panel)
    panel._send('deepseek_list');wait(app,panel)
    assert panel.queue.item(0,1).text()=='pending_review'
    panel._send('deepseek_approve');wait(app,panel)
    assert json.loads(panel.signing.toPlainText())['package']==package
    panel._send('deepseek_list');wait(app,panel)
    assert panel.queue.item(0,1).text()=='approved_for_signing'
    assert 'Henüz aktive' in panel.queue.item(0,3).text()
