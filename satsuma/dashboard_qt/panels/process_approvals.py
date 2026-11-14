"""Interactive test-mode approval UI: authenticated Operator IPC only.

No direct kill, memory access, SQL DB access, or password persistence here.
"""
import json
import threading

try:
    from PyQt6.QtWidgets import QLabel, QPushButton, QLineEdit, QListWidget, QHBoxLayout, QPlainTextEdit, QApplication
    from PyQt6.QtCore import pyqtSignal
except ImportError:
    from PyQt5.QtWidgets import QLabel, QPushButton, QLineEdit, QListWidget, QHBoxLayout, QPlainTextEdit, QApplication
    from PyQt5.QtCore import pyqtSignal

from . import register
from .base import BasePanel
from ...dashboard_api_client import ReaderClient
from ...operator_service import SOCKET_PATH


@register
class ProcessApprovalsPanel(BasePanel):
    PANEL_ID = 'process_approvals'
    PANEL_TITLE = 'Test Modu — Süreç ve Kural İnceleme'
    PANEL_ORDER = 4
    PANEL_GROUP = 'security'
    PANEL_SUBTITLE = 'Süreç müdahalesi onayları ve derin kural doğruluk etiketleri; derin kural etiketi sistem müdahalesi yapmaz.'
    REFRESH_MS = 0  # Authentication is explicit; no periodic password prompt.
    completed = pyqtSignal(object)

    def _build(self):
        self._layout.addWidget(self.make_title(self.PANEL_TITLE))
        self._layout.addWidget(QLabel('Yönetici parolası gerekli. Derin kural denemelerinde Uygula yalnız tespit etiketini kabul eder; süreci sonlandırmaz.'))
        self.password = QLineEdit()
        self.password.setPlaceholderText('Yönetici parolası')
        self.password.setEchoMode(QLineEdit.EchoMode.Password if hasattr(QLineEdit, 'EchoMode') else QLineEdit.Password)
        self._layout.addWidget(self.password)
        row = QHBoxLayout()
        for title, callback in (
            ('Test modunu aç', lambda: self._request('mode', enabled=True)),
            ('Test modunu kapat', lambda: self._request('mode', enabled=False)),
            ('Bekleyenleri yenile', self.refresh),
        ):
            button = QPushButton(title)
            button.clicked.connect(callback)
            row.addWidget(button)
        self._layout.addLayout(row)
        self.status = QLabel('Test modu varsayılan kapalı. Önce yetkili olarak açın.')
        self.status.setWordWrap(True)
        self._layout.addWidget(self.status)
        self.requests = QListWidget()
        self._layout.addWidget(self.requests, 1)
        row2 = QHBoxLayout()
        self.action_buttons = {}
        for title, action in (('İşlemi uygula', 'apply'), ('İşlemi reddet', 'reject'), ('Log çıktısını paylaş (kopyala)', 'copy')):
            button = QPushButton(title)
            button.clicked.connect(lambda checked=False, a=action: self._act(a))
            self.action_buttons[action] = button
            row2.addWidget(button)
        self._layout.addLayout(row2)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(180)
        self._layout.addWidget(self.details)
        self.requests.currentRowChanged.connect(self._show_selected)
        self._pending = []
        self._busy = False
        self.completed.connect(self._completed)

    def _selected(self):
        i = self.requests.currentRow()
        return self._pending[i] if 0 <= i < len(self._pending) else None

    def _show_selected(self, *_):
        item = self._selected()
        is_review = bool(item and item.get('kind') == 'deep_rule_review')
        labels = ({'apply': 'Tespiti doğru işaretle', 'reject': 'Tespiti yanlış işaretle',
                   'copy': 'Kanıt özetini kopyala'} if is_review else
                  {'apply': 'Süreç müdahalesini onayla', 'reject': 'Süreç müdahalesini reddet',
                   'copy': 'Log çıktısını paylaş (kopyala)'})
        for action, button in self.action_buttons.items():
            button.setText(labels[action])
        self.details.setPlainText(json.dumps(item or {}, ensure_ascii=False, indent=2))

    def _act(self, action):
        item = self._selected()
        if item is None:
            self.status.setText('Önce bir istek seçin.')
            return
        if action == 'copy':
            # Explicit user action: no automatic network export and no secrets.
            QApplication.clipboard().setText(json.dumps(item, ensure_ascii=False, indent=2))
            self.status.setText('Seçili isteğin hassas olmayan kanıt özeti panoya kopyalandı; otomatik gönderilmedi.')
            return
        self._request('lab_decision' if item.get('kind') == 'deep_rule_review' else 'decision', request_id=item['id'], decision=action)

    def refresh(self, *_):
        # Status requires an authorized operator session. Never expose raw
        # evidence through the unauthenticated reader API.
        self._request('status')

    def _request(self, action, **fields):
        if self._busy:
            return
        password = self.password.text()
        self.password.clear()
        if not password:
            self.status.setText('Yönetici parolasını girin. Parola depolanmaz.')
            return
        self._busy = True
        self.status.setText('Yetkili kanalın yanıtı bekleniyor…')

        def task():
            try:
                client = ReaderClient(SOCKET_PATH, timeout=20)
                login = client.call('login', password=password)
                token = login.get('token')
                if not login.get('ok') or not token:
                    raise PermissionError('Yönetici kimliği doğrulanamadı')
                if action == 'status':
                    result = client.call('status', token=token)
                elif action == 'mode':
                    result = client.call('interactive_process_test_mode', token=token,
                                         password=password, **fields)
                elif action == 'lab_decision':
                    result = client.call('deep_rule_review_decide', token=token, password=password, **fields)
                else:
                    result = client.call('process_approval_decide', token=token,
                                         password=password, **fields)
                # Prevent session token/password from reaching the Qt signal.
                result.pop('token', None)
                try:
                    client.call('logout', token=token)
                except Exception:
                    pass
                self.completed.emit({'action': action, 'result': result})
            except Exception as exc:
                self.completed.emit({'error': type(exc).__name__ + ': ' + str(exc)[:180]})
        threading.Thread(target=task, daemon=True).start()

    def _completed(self, response):
        self._busy = False
        if 'error' in response:
            self.status.setText('İşlem doğrulanamadı: ' + response['error'])
            return
        action = response['action']
        result = response['result']
        if action == 'status':
            self._pending = result.get('process_approval_pending', []) + result.get('deep_rule_review_pending', [])
            self.requests.clear()
            for item in self._pending:
                self.requests.addItem((('DERİN KURAL · yalnız tespit etiketi · ' + str(item.get('rule_id'))) if item.get('kind') == 'deep_rule_review' else (str(item.get('engine', '?')) + ' · PID ' + str(item.get('pid', '?')) + ' · ' + str(item.get('rule_id', '?')))) + ' · ' + str(item.get('id', ''))[:8])
            self.status.setText(('AÇIK' if result.get('interactive_process_test_mode') is True else 'KAPALI') +
                                f' · Bekleyen süreç istekleri: {len(self._pending)}')
        else:
            self.status.setText('Operatör sonucu: ' + str(result.get('status') or result.get('enabled') or 'tamamlandı') +
                                '. Bir sinyalin gönderilmesi sürecin çıktığını tek başına kanıtlamaz.')
            self._pending = []
            self.requests.clear()
