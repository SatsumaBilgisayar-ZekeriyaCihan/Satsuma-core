"""Audit K7: lowering protection needs the password again and is recorded as critical.

Denetim K7: korumayı azaltmak parolanın yeniden girilmesini ister ve kritik
olarak kaydedilir.
"""
import json
import time
from types import SimpleNamespace as NS

import pytest

from satsuma.operator_service import OperatorController, weakens
from satsuma.store import Store

PASSWORD = 'dogru-parola'


class Auth:
    def __init__(self):
        self.sessions = set()

    def login(self, password, client='local'):
        if password != PASSWORD:
            return {'ok': False, 'error': 'invalid_credentials'}
        token = 'session-%d' % len(self.sessions)
        self.sessions.add(token)
        return {'ok': True, 'token': token}

    def validate_session(self, token):
        return token in self.sessions

    def logout(self, token):
        self.sessions.discard(token)


@pytest.fixture
def controller(tmp_path):
    store = Store(tmp_path / 'data', test=True)
    c = OperatorController(store, auth=Auth(), runner=lambda *a, **k: NS(returncode=0, stdout='', stderr=''),
                           boot_provider=lambda: {'response_unlocked': True})
    token = c.dispatch(1000, 'login', {'password': PASSWORD})['token']
    yield c, store, token
    store.close()


def changes(store):
    return [json.loads(b) for (b,) in store.db.execute("SELECT body FROM records WHERE kind='protection_changes'").fetchall()]


@pytest.mark.parametrize('method,params', [
    ('integrity_rebaseline', {}), ('allow_ip', {'ip': '198.51.100.7'}),
    ('allow_domain', {'domain': 'example.com'}), ('subnet_protection', {'enabled': False}),
    ('auto_network', {'enabled': False}), ('service', {'name': 'satsuma-core.service', 'action': 'stop'}),
])
def test_session_alone_cannot_lower_protection(controller, method, params):
    c, store, token = controller
    with pytest.raises(PermissionError, match='K7'):
        c.dispatch(1000, method, {**params, 'token': token})
    with pytest.raises(PermissionError, match='K7'):
        c.dispatch(1000, method, {**params, 'token': token, 'password': 'yanlis'})
    assert [x['status'] for x in changes(store)] == ['refused_password', 'refused_password']
    assert all(x['severity'] == 'critical' for x in changes(store))


def test_with_the_password_it_is_applied_and_recorded_without_the_password(controller):
    c, store, token = controller
    c.dispatch(1000, 'subnet_protection', {'enabled': False, 'token': token, 'password': PASSWORD})
    record = changes(store)[-1]
    assert record['status'] == 'applied' and record['method'] == 'subnet_protection' and record['severity'] == 'critical'
    assert 'password' not in record['params'] and 'token' not in record['params']
    assert PASSWORD not in json.dumps(store.db.execute('SELECT body FROM records').fetchall())
    # The re-check opened no lasting extra session.
    assert c.auth.sessions == {token}


def test_raising_protection_still_needs_only_the_session(controller):
    c, store, token = controller
    c.dispatch(1000, 'remove_allow_ip', {'ip': '198.51.100.7', 'token': token})
    assert changes(store) == []


@pytest.mark.parametrize('method,params,expected', [
    ('lan_access', {'enabled': True}, True), ('dns_filter', {'enabled': False}, True),
    ('dns_filter', {'enabled': True}, False), ('otx_blocker', {'enabled': False}, True),
    ('hagezi_enabled', {'enabled': False}, True), ('service', {'action': 'restart'}, False),
    ('application_control', {'action': 'disable'}, True), ('unblock', {}, True),
    ('remove_allow_domain', {}, False), ('status', {}, False),
])
def test_weakens_table(method, params, expected):
    assert weakens(method, params) is expected


def test_gui_asks_for_the_password_and_cancelling_sends_nothing(monkeypatch):
    """2.2.47: the shared lock asks again before lowering protection; cancelling sends nothing."""
    from PyQt6.QtWidgets import QApplication
    from satsuma.dashboard_qt.session import OperatorSession
    app = QApplication.instance() or QApplication([])
    sent = []

    class Client:
        def call(self, method, **params):
            sent.append((method, params))
            return {'ok': True}
    session = OperatorSession(client_factory=Client)
    session.token = 'session'
    answers = ['']
    session.ask_password = lambda *a: answers.pop(0) if answers else None
    messages = []
    session.message.connect(lambda tone, text: messages.append(text))
    session.run('lan_access', {'enabled': True})
    time.sleep(0.2); app.processEvents()
    assert sent == [] and any('iptal' in m for m in messages)
    session.ask_password = lambda *a: PASSWORD
    session.run('lan_access', {'enabled': True})
    for _ in range(50):
        app.processEvents(); time.sleep(0.02)
        if sent:
            break
    assert sent and sent[0][1]['password'] == PASSWORD and sent[0][1]['token'] == 'session'


def test_pausing_does_not_exist(controller):
    """A security product has no pause switch (2.2.16).

    Güvenlik ürününde duraklatma anahtarı yoktur (2.2.16).
    """
    c, store, token = controller
    with pytest.raises(ValueError, match='Desteklenmeyen'):
        c.dispatch(1000, 'pause', {'enabled': True, 'token': token, 'password': PASSWORD})
    assert store.get('operator_pause', False) is False
