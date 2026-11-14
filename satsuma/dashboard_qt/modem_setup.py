"""End-user network setup: review first, explicit yes, authenticated apply."""
import json
import threading
try:
    from PyQt6.QtCore import pyqtSignal
    from PyQt6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,QComboBox,QPlainTextEdit,QLineEdit
except ImportError:
    from PyQt5.QtCore import pyqtSignal
    from PyQt5.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,QComboBox,QPlainTextEdit,QLineEdit
from ..dashboard_api_client import ReaderClient
from ..operator_service import SOCKET_PATH
from .detail_sanitizer import detail_lines


class ModemSetup(QWidget):
    completed=pyqtSignal(str,object)
    def __init__(self,parent=None):
        super().__init__(parent)
        self.plan=None;self.busy=False;self.detailed=False
        layout=QVBoxLayout(self)
        intro=QLabel('Ağınızı nasıl hazırlamak istersiniz? Önce yapılacak ayarları inceleyin; onayınız olmadan modem referansı kaydedilmez.')
        intro.setWordWrap(True);layout.addWidget(intro)
        row=QHBoxLayout()
        self.auto=QPushButton('Otomatik yapılandırma')
        self.detail=QPushButton('Detaylı yapılandırma')
        self.auto.clicked.connect(lambda:self.choose(False))
        self.detail.clicked.connect(lambda:self.choose(True))
        row.addWidget(self.auto);row.addWidget(self.detail);layout.addLayout(row)
        self.summary=QLabel('Otomatik seçenekte önerilen ayarlar, detaylı seçenekte tüm ağ tabloları gösterilir.')
        self.summary.setWordWrap(True);layout.addWidget(self.summary)
        self.tables=QPlainTextEdit();self.tables.setReadOnly(True);self.tables.setMaximumHeight(200);self.tables.hide();layout.addWidget(self.tables)
        self.choices=QComboBox();self.choices.hide();layout.addWidget(self.choices)
        self.password=QLineEdit();self.password.setEchoMode(QLineEdit.EchoMode.Password if hasattr(QLineEdit,'EchoMode') else QLineEdit.Password)
        self.password.setPlaceholderText('Uygulamak için Satsuma yönetici parolanız');layout.addWidget(self.password)
        self.yes=QPushButton('Evet, gösterilen ayarları uygula');self.yes.setEnabled(False)
        self.yes.clicked.connect(self.apply);layout.addWidget(self.yes)
        self.completed.connect(self.done)
    def choose(self,detailed):
        if self.busy:return
        self.detailed=detailed;self.plan=None;self.yes.setEnabled(False)
        self.tables.setVisible(detailed);self.choices.setVisible(detailed)
        self.busy=True;self.summary.setText('Modem adayları ve ağ tabloları okunuyor…')
        def work():
            try:result=ReaderClient(timeout=45).call('modem_setup_preview')
            except Exception as exc:result={'error':str(exc)}
            try:self.completed.emit('preview',result)
            except RuntimeError:pass
        threading.Thread(target=work,daemon=True).start()
    def apply(self):
        if self.busy or not self.plan:return
        candidate_id=self.choices.currentData() if self.detailed else (self.plan.get('candidate') or {}).get('id')
        if not candidate_id:self.summary.setText('Önce kendi modeminizi seçin.');return
        password=self.password.text();self.password.clear()
        if not password:self.summary.setText('Gösterilen ayarları uygulamak için yönetici parolanızı girin.');return
        self.busy=True;self.yes.setEnabled(False)
        fingerprint=self.plan['route_fingerprint']
        self.summary.setText('Onayladığınız modem referansı kaydediliyor…')
        def work():
            client=ReaderClient(SOCKET_PATH,timeout=45);token=None
            try:
                session=client.call('login',password=password)
                if not session.get('ok'):raise PermissionError('Yönetici parolası doğrulanmadı.')
                token=session['token']
                result=client.call('modem_approve',token=token,candidate_id=candidate_id,confirmed=True,route_fingerprint=fingerprint)
            except Exception as exc:result={'error':str(exc)}
            finally:
                if token:
                    try:client.call('logout',token=token)
                    except Exception:pass
            try:self.completed.emit('apply',result)
            except RuntimeError:pass
        threading.Thread(target=work,daemon=True).start()
    def done(self,kind,result):
        self.busy=False
        if result.get('error'):
            self.plan=None;self.yes.setEnabled(False)
            self.summary.setText('Ayar uygulanmadı: '+str(result['error'])+'\nAyarları yeniden görüntüleyip onaylayın.');return
        if kind=='preview':
            self.plan=result;data=result.get('inventory') or {}
            self.summary.setText('Otomatik yapılandırmada ayarlarınız şöyle yapılacaktır:\n'+'\n'.join(result.get('summary',[])) if not self.detailed else 'Tüm tablolar aşağıdadır. Kendi modeminizi seçin; yalnız bu cihaz referans kaydedilecektir.')
            self.choices.clear()
            for item in data.get('candidates',[]):
                self.choices.addItem(f"{item['gateway']} · {item['interface']} · MAC {item['gateway_mac']} · tablo {item['table']}",item['id'])
            self.choices.setCurrentIndex(-1)
            self.tables.setPlainText(detail_lines({'tables':data.get('tables',[]),'routes':data.get('routes',[]),'rules':data.get('rules',[])}))
            self.yes.setEnabled(bool(data.get('candidates')) if self.detailed else bool(result.get('ready_for_automatic')))
        else:
            self.plan=None;self.yes.setEnabled(False)
            self.summary.setText('Seçtiğiniz modem referansı kaydedildi. Güncel sağlık kontrolünün sonucunu Sistem Sağlığı bölümünden izleyebilirsiniz.')
