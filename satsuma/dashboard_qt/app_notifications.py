"""Independent application decision window; mutations use authenticated operator IPC."""
import copy
import os
import threading
import time
try:
    from PyQt6.QtWidgets import QDialog,QVBoxLayout,QLabel,QPushButton,QCheckBox,QLineEdit,QHBoxLayout,QPlainTextEdit
    from PyQt6.QtCore import QTimer,pyqtSignal
except ImportError:
    from PyQt5.QtWidgets import QDialog,QVBoxLayout,QLabel,QPushButton,QCheckBox,QLineEdit,QHBoxLayout,QPlainTextEdit
    from PyQt5.QtCore import QTimer,pyqtSignal
from ..dashboard_api_client import ReaderClient
from .style.theme import GLOBAL_QSS
from .security_widgets import icon
from ..operator_service import SOCKET_PATH


class AppNotifications(QDialog):
    completed=pyqtSignal(object)
    def __init__(self,window):
        # No Qt parent: minimizing the main window must not minimize this dialog.
        super().__init__(None)
        self.window_owner=window;self.active=None;self.seen=set();self.busy=False
        self.token=None;self.command_id=None;self.deadline=None
        self.setWindowTitle('Satsuma — Uygulama ağ izni');self.setMinimumWidth(500)
        self.setWindowIcon(icon('shield'));self.setStyleSheet(GLOBAL_QSS)
        layout=QVBoxLayout(self);layout.setContentsMargins(26,24,26,24);layout.setSpacing(14)
        self.message=QLabel();self.message.setWordWrap(True);self.message.setMinimumHeight(110)
        self.message.setStyleSheet('font-size:24px;font-weight:700;');layout.addWidget(self.message)
        self.details_button=QPushButton('Bağlantı ayrıntılarını göster');self.details_button.setObjectName('quiet');layout.addWidget(self.details_button)
        self.details=QPlainTextEdit();self.details.setReadOnly(True);self.details.setMaximumHeight(150);self.details.hide();layout.addWidget(self.details)
        self.details_button.clicked.connect(lambda:self.details.setVisible(self.details.isHidden()))
        self.remember=QCheckBox('Bu uygulama için hatırla (dosya kimliği ve kullanıcı; alt süreçler dahil)');layout.addWidget(self.remember)
        layout.addWidget(QLabel('İşlem için yönetici parolası (geçerli oturum varsa tekrar gerekmez)'))
        self.password=QLineEdit();self.password.setEchoMode(QLineEdit.EchoMode.Password if hasattr(QLineEdit,'EchoMode') else QLineEdit.Password);layout.addWidget(self.password)
        self.result=QLabel('Bir kez: yalnız gösterilen bağlantı için en fazla 5 dakika.');self.result.setWordWrap(True);self.result.setMinimumHeight(64);layout.addWidget(self.result)
        row=QHBoxLayout();self.allow=QPushButton('İzin ver');self.allow.setObjectName('primary');self.deny=QPushButton('Engelle');self.deny.setObjectName('danger')
        for b,decision in ((self.allow,'allow'),(self.deny,'deny')):
            b.setMinimumHeight(48);b.clicked.connect(lambda checked,d=decision:self.decide(d));row.addWidget(b)
        layout.addLayout(row)
        self.dismiss=QPushButton('Karar vermeden kapat');self.dismiss.clicked.connect(self.dismiss_request);layout.addWidget(self.dismiss)
        self.completed.connect(self.done_request)
        self.timer=QTimer(self);self.timer.timeout.connect(self.poll);self.timer.start(2000)
        self.hide()

    def dismiss_request(self):
        if self.busy or self.command_id:return
        self.active=None;self.hide()

    def closeEvent(self,event):
        if self.busy or self.command_id:event.ignore();return
        self.active=None;super().closeEvent(event)

    def poll(self):
        try:status=self.window_owner.backend.call('app_control') or {}
        except Exception:
            if self.active:self.result.setText('Durum alınamadı; kararın uygulandığı doğrulanmadı.')
            return
        command=status.get('last_command') or {}
        if self.command_id:
            if command.get('id')==self.command_id and command.get('status') in ('APPLIED','FAILED'):
                self.result.setText('Teyit Edildi: uygulama ağ izni kararı uygulandı (program çalıştırma izni değildir). Gerçek paket engelleme bu bildirimle ölçülmez.' if command['status']=='APPLIED' else 'Karar uygulanamadı: '+str(command.get('error') or 'Nedeni alınamadı'))
                self.command_id=None;self.dismiss.setText('Kapat');self.dismiss.setEnabled(True)
            elif time.monotonic()>self.deadline:
                self.result.setText('Sonuç bekleme süresi doldu; kararın uygulandığı doğrulanmadı. İzinleri yönet bölümünden kontrol edin.')
                self.command_id=None;self.dismiss.setEnabled(True)
            return
        # Freeze the displayed application, request ID and controls until dismissed.
        if self.active:return
        if status.get('status')!='ACTIVE':return
        pending=status.get('pending') or []
        current={x['id'] for x in pending};self.seen.intersection_update(current)
        item=next((x for x in pending if x['id'] not in self.seen),None)
        if not item:return
        self.active=copy.deepcopy(item);self.seen.add(item['id'])
        proc=item.get('application') or {};flow=item.get('flow') or []
        self.message.setText((os.path.basename(proc.get('executable') or '') or 'Uygulama adı alınamadı')+'\nAğ erişimine izin verilsin mi?')
        self.details.setPlainText('Python girişi: '+(str((proc.get('python_entry') or {}).get('path')) if (proc.get('python_entry') or {}).get('status')=='verified' else 'doğrulanamadı' if proc.get('python_entry') else 'Python değil')+'\nDosya: '+str(proc.get('executable') or 'Kayıtta belirtilmemiş')+'\nHedef: '+str(item.get('destination') or 'Kayıtta belirtilmemiş')+'\nProtokol: '+str(flow[1] if len(flow)>1 else 'Kayıtta belirtilmemiş')+'\nBirleştirilen bağlantı: '+str(item.get('connection_count',1)))
        self.result.setText('Onay verilene kadar bağlantı engellenir. Bir kez: gösterilen bağlantı, en fazla 5 dakika.')
        self.remember.setChecked(False);self.remember.setEnabled(not proc.get('python_entry') or proc['python_entry'].get('status')=='verified');self.allow.setEnabled(True);self.deny.setEnabled(True);self.dismiss.setEnabled(True);self.dismiss.setText('Karar vermeden kapat')
        self.adjustSize();screen=self.screen()
        if screen:
            area=screen.availableGeometry();self.move(max(area.left(),area.right()-self.width()-24),area.top()+60)
        self.show();self.raise_()

    def decide(self,decision):
        if not self.active or self.busy or self.command_id:return
        request_id=self.active['id'];duration='application' if self.remember.isChecked() else 'once'
        password=self.password.text();self.password.clear();token=self.token
        self.busy=True;self.allow.setEnabled(False);self.deny.setEnabled(False);self.dismiss.setEnabled(False)
        self.result.setText('Yetkilendirme ve karar sonucu bekleniyor…')
        def task():
            try:
                client=ReaderClient(SOCKET_PATH,timeout=15)
                active_token=token
                if not active_token:
                    login=client.call('login',password=password)
                    active_token=login.get('token')
                    if not login.get('ok') or not active_token:raise PermissionError(login.get('error') or 'Yönetici girişi doğrulanamadı')
                result=client.call('application_control',token=active_token,action='decision',decision=decision,duration=duration,request_id=request_id)
                result={**result,'session_token':active_token}
            except Exception as exc:result={'error':str(exc)}
            try:self.completed.emit(result)
            except RuntimeError:pass
        threading.Thread(target=task,daemon=True).start()

    def done_request(self,result):
        self.busy=False
        if result.get('error'):
            self.token=None;self.result.setText('Karar uygulanamadı / oturum süresi dolmuş olabilir: '+str(result['error']))
            self.allow.setEnabled(True);self.deny.setEnabled(True);self.dismiss.setEnabled(True);return
        self.token=result.get('session_token')
        command=result.get('application_control') or {}
        if command.get('status')=='REQUESTED' and command.get('command_id'):
            self.command_id=command['command_id'];self.deadline=time.monotonic()+20
            self.result.setText('İstek alındı; kararın uygulanması doğrulanıyor…')
        else:
            self.result.setText('Kararın uygulandığı doğrulanamadı. İzinleri yönet bölümünden kontrol edin.');self.dismiss.setEnabled(True)
