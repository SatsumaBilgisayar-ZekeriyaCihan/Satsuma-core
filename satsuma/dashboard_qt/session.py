"""One administrator lock for the whole panel (2.2.45).

Until 2.2.44 every management button lived on one "Yönetim" page with its own
login. Now any page may change a setting: when the lock is closed the password
is asked right there, and an action that lowers protection asks for it again
(audit K7, satsuma.operator_service.weakens). Socket IO never runs in the GUI
thread; answers come back through a Qt signal.

Panelin tamamı için tek yönetici kilidi. Kilit kapalıyken parola o anda sorulur;
korumayı azaltan işlem parolayı yeniden ister. Soket işlemi arayüz iş
parçacığında çalışmaz.
"""
import threading
import uuid

from .qt import (QObject, pyqtSignal, QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
                 PASSWORD, ACCEPTED)
from ..operator_messages import describe, session_lost


def _client():
    from ..dashboard_api_client import ReaderClient
    from ..operator_service import SOCKET_PATH
    return ReaderClient(SOCKET_PATH, timeout=180)


class PasswordDialog(QDialog):
    """Asks the administrator password; the caller decides what it is for."""

    def __init__(self, title, explanation, parent=None, confirm='Kilidi aç'):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setObjectName('passwordDialog')
        self.setModal(True)
        self.setMinimumWidth(420)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(12)
        heading = QLabel(title)
        heading.setObjectName('dialogTitle')
        layout.addWidget(heading)
        text = QLabel(explanation)
        text.setWordWrap(True)
        text.setObjectName('secondary')
        layout.addWidget(text)
        self.password = QLineEdit()
        self.password.setEchoMode(PASSWORD)
        self.password.setPlaceholderText('Yönetici parolası')
        self.password.setAccessibleName('Yönetici parolası')
        layout.addWidget(self.password)
        self.error = QLabel('')
        self.error.setObjectName('errorText')
        self.error.setWordWrap(True)
        self.error.hide()
        layout.addWidget(self.error)
        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton('Vazgeç')
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        self.ok = QPushButton(confirm)
        self.ok.setObjectName('primary')
        self.ok.setDefault(True)
        self.ok.clicked.connect(self._accept)
        buttons.addWidget(self.ok)
        layout.addLayout(buttons)
        self.password.returnPressed.connect(self._accept)

    def _accept(self):
        if not self.password.text():
            self.error.setText('Parolayı yazın.')
            self.error.show()
            return
        self.accept()

    def value(self):
        text = self.password.text()
        self.password.clear()
        return text


class OperatorSession(QObject):
    changed = pyqtSignal(bool)
    finished = pyqtSignal(str, object, object, str)
    message = pyqtSignal(str, str)          # tone, sentence

    def __init__(self, client_factory=_client, parent=None):
        super().__init__(parent)
        self.client_factory = client_factory
        self.token = None
        self.busy = set()
        self._callbacks = {}
        self.finished.connect(self._deliver)

    # -- state
    def unlocked(self):
        return bool(self.token)

    def adopt(self, token):
        """A token obtained elsewhere (the advanced management page) becomes the shared lock."""
        if token != self.token:
            self.token = token or None
            self.changed.emit(self.unlocked())

    def lock(self):
        token, self.token = self.token, None
        if token:
            self._call('logout', {'token': token}, None)
        self.changed.emit(False)

    # -- dialogs (overridable in tests)
    def ask_password(self, parent, title, explanation, confirm):
        dialog = PasswordDialog(title, explanation, parent, confirm)
        return dialog.value() if dialog.exec() == ACCEPTED else None

    def unlock(self, parent=None, then=None):
        """Ask the password and log in; ``then`` runs once the lock is open."""
        password = self.ask_password(parent, 'Yönetici kilidini aç',
                                     'Ayarları değiştirmek için yönetici parolanızı girin. Kilit 30 dakika açık kalır.',
                                     'Kilidi aç')
        if not password:
            return False

        def done(method, params, result):
            if isinstance(result, dict) and result.get('ok') and result.get('token'):
                self.token = result['token']
                self.changed.emit(True)
                self.message.emit('ok', describe('login', {}, result)[1])
                if then:
                    then()
            else:
                self.message.emit('error', describe('login', {}, result)[1])
        self._call('login', {'password': password}, done)
        return True

    def run(self, method, params=None, parent=None, then=None):
        """Send one operator request; unlock first if needed; ask again when it lowers protection."""
        params = dict(params or {})
        if not self.token:
            return self.unlock(parent, lambda: self.run(method, params, parent, then))
        from ..operator_service import weakens
        try:
            lowers = weakens(method, params)
        except ValueError as exc:
            self.message.emit('error', 'İşlem uygulanamadı: ' + str(exc))
            return False
        if lowers:
            password = self.ask_password(parent, 'Korumayı azaltan işlem',
                                         'Bu işlem korumayı azaltır ve kritik olarak kaydedilir. Onaylamak için yönetici parolanızı yeniden girin.',
                                         'Onayla')
            if not password:
                self.message.emit('warn', 'İşlem iptal edildi.')
                return False
            params['password'] = password
        params['token'] = self.token
        self._call(method, params, then)
        return True

    # -- transport
    def _call(self, method, params, callback):
        key = uuid.uuid4().hex
        self._callbacks[key] = (callback, {k: v for k, v in params.items() if k not in ('password', 'token')})
        self.busy.add(method)

        def task():
            try:
                result = self.client_factory().call(method, **params)
            except Exception as exc:
                result = {'ok': False, 'error': str(exc)[:300]}
            try:
                self.finished.emit(method, result, None, key)
            except RuntimeError:
                pass
        threading.Thread(target=task, daemon=True, name='satsuma-operator').start()

    def _deliver(self, method, result, _unused, key):
        self.busy.discard(method)
        callback, params = self._callbacks.pop(key, (None, {}))
        if isinstance(result, dict) and session_lost(result.get('error')):
            self.token = None
            self.changed.emit(False)
        if method not in ('login', 'logout', 'status'):
            tone, text = describe(method, params, result)
            self.message.emit(tone, text)
        if callback:
            callback(method, params, result)
