"""Optional desktop notice for lab-mode process approvals.

The reader channel exposes only a pending count.  A separate authenticated
Operator connection is required to retrieve details or decide.  No GUI dialog
can send a signal directly; the existing privileged process responder owns all
live identity, enforcement, and memory-revalidation checks.
"""
import json
import threading

try:
    from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                                 QPushButton, QLineEdit, QListWidget, QApplication)
    from PyQt6.QtCore import QTimer, pyqtSignal
except ImportError:
    from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                                 QPushButton, QLineEdit, QListWidget, QApplication)
    from PyQt5.QtCore import QTimer, pyqtSignal

from ..dashboard_api_client import ReaderClient, SOCKET_PATH as READER_SOCKET
from ..operator_service import SOCKET_PATH as OPERATOR_SOCKET


class ProcessApprovalNotifications(QDialog):
    """Independent window: minimizing the dashboard does not hide the alert."""
    notice_ready = pyqtSignal(object)
    operation_ready = pyqtSignal(object)

    def __init__(self, owner):
        super().__init__(None)
        self.owner = owner
        self._polling = False
        self._busy = False
        self._notice_signature = None
        self._pending = []
        self.setWindowTitle('Satsuma — Test modu müdahale onayı')
        self.setMinimumWidth(510)
        layout = QVBoxLayout(self)
        self.message = QLabel('Bekleyen süreç müdahalesi tespit edildi. Karar için yönetici doğrulaması gerekir.')
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        self.password = QLineEdit()
        self.password.setPlaceholderText('Yönetici parolası (kaydedilmez)')
        self.password.setEchoMode(QLineEdit.EchoMode.Password if hasattr(QLineEdit, 'EchoMode') else QLineEdit.Password)
        layout.addWidget(self.password)
        load = QPushButton('Kimliği doğrula ve istekleri göster')
        load.clicked.connect(lambda: self._operator_call('status'))
        layout.addWidget(load)
        self.requests = QListWidget()
        layout.addWidget(self.requests)
        row = QHBoxLayout()
        for title, action in (('İşlemi uygula', 'apply'), ('İşlemi reddet', 'reject'),
                              ('Logu paylaş (kopyala)', 'copy')):
            button = QPushButton(title)
            button.clicked.connect(lambda checked=False, a=action: self._act(a))
            row.addWidget(button)
        layout.addLayout(row)
        dismiss = QPushButton('Karar vermeden kapat')
        dismiss.clicked.connect(self.hide)
        layout.addWidget(dismiss)
        self.notice_ready.connect(self._update_notice)
        self.operation_ready.connect(self._finish_operation)
        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self.poll)
        self.timer.start()
        self.hide()

    def poll(self):
        if self._polling or self._busy:
            return
        self._polling = True

        def task():
            try:
                result = ReaderClient(READER_SOCKET, timeout=2).call('process_approval_notice')
                self.notice_ready.emit(result if isinstance(result, dict) else {'status': 'UNAVAILABLE'})
            except Exception:
                self.notice_ready.emit({'status': 'UNAVAILABLE'})
        threading.Thread(target=task, daemon=True).start()

    def _update_notice(self, notice):
        self._polling = False
        if notice.get('status') != 'OK':
            self._notice_signature = None
            return
        count = notice.get('pending_count')
        if type(count) is not int or count <= 0:
            self._notice_signature = None
            return
        # One notice for a given pending count until dismissed; details require
        # a fresh authenticated read, not the unprivileged reader channel.
        if self._notice_signature == count:
            return
        self._notice_signature = count
        self._pending = []
        self.requests.clear()
        self.message.setText(f'{count} süreç müdahalesi kullanıcı kararı bekliyor. '
                             'İşlem yapılmazsa istek kendiliğinden sona erer.')
        self.show()
        self.raise_()

    def _act(self, action):
        row = self.requests.currentRow()
        if not (0 <= row < len(self._pending)):
            self.message.setText('Önce yönetici parolasıyla isteği görüntüleyip seçin.')
            return
        item = self._pending[row]
        if action == 'copy':
            # Only public_pending fields; no raw finding, passwords or tokens.
            QApplication.clipboard().setText(json.dumps(item, ensure_ascii=False, indent=2))
            self.message.setText('Kanıt özeti panoya kopyalandı; dışarıya gönderilmedi.')
            return
        self._operator_call('decision', request_id=item['id'], decision=action)

    def _operator_call(self, action, **fields):
        if self._busy:
            return
        password = self.password.text()
        self.password.clear()
        if not password:
            self.message.setText('Bu işlem için yönetici parolasını yeniden girin.')
            return
        self._busy = True
        self.message.setText('Yetkili Operator kanalından yanıt bekleniyor…')

        def task():
            token = None
            client = ReaderClient(OPERATOR_SOCKET, timeout=15)
            try:
                login = client.call('login', password=password)
                token = login.get('token')
                if not login.get('ok') or not token:
                    raise PermissionError('Yönetici kimliği doğrulanamadı')
                if action == 'status':
                    result = client.call('status', token=token)
                else:
                    result = client.call('process_approval_decide', token=token,
                                         password=password, **fields)
                result.pop('token', None)
                self.operation_ready.emit({'action': action, 'result': result})
            except Exception as exc:
                self.operation_ready.emit({'error': type(exc).__name__})
            finally:
                if token:
                    try:
                        client.call('logout', token=token)
                    except Exception:
                        pass
        threading.Thread(target=task, daemon=True).start()

    def _finish_operation(self, output):
        self._busy = False
        if 'error' in output:
            self.message.setText('Kimlik doğrulama veya işlem başarısız: ' + output['error'])
            return
        result = output['result']
        if output['action'] == 'status':
            if result.get('interactive_process_test_mode') is not True:
                self._pending = []
                self.requests.clear()
                self.message.setText('Test modu etkin değil; müdahale onayı alınamaz.')
                return
            self._pending = list(result.get('process_approval_pending', []))[:64]
            self.requests.clear()
            for item in self._pending:
                self.requests.addItem(f"PID {item.get('pid', '?')} · {item.get('rule_id', '?')} · {item.get('id', '')[:8]}")
            self.message.setText(f'{len(self._pending)} geçerli istek bulundu. Seçim ve karar için yeniden parola girin.')
        else:
            self._pending = []
            self.requests.clear()
            self.message.setText('Operatör kararı: ' + str(result.get('status', 'UNKNOWN')) +
                                 '. Süreç çıkışı ayrıca doğrulanmalıdır.')
