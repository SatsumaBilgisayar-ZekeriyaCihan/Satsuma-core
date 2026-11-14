"""Native research workspace using the existing authenticated Operator socket.

No key access, signing key import, local SQLite or response execution exists here.
"""
import json
import threading
import uuid
from pathlib import Path
try:
    from PyQt6.QtWidgets import (QWidget,QLabel,QPushButton,QLineEdit,QComboBox,QPlainTextEdit,
        QCheckBox,QHBoxLayout,QVBoxLayout,QGridLayout,QTabWidget,QTableWidget,QTableWidgetItem,
        QHeaderView,QFileDialog,QMessageBox,QSplitter,QFrame,QScrollArea)
    from PyQt6.QtCore import pyqtSignal,Qt
except ImportError:
    from PyQt5.QtWidgets import (QWidget,QLabel,QPushButton,QLineEdit,QComboBox,QPlainTextEdit,
        QCheckBox,QHBoxLayout,QVBoxLayout,QGridLayout,QTabWidget,QTableWidget,QTableWidgetItem,
        QHeaderView,QFileDialog,QMessageBox,QSplitter,QFrame,QScrollArea)
    from PyQt5.QtCore import pyqtSignal,Qt
from .base import BasePanel
from . import register
from ...dashboard_api_client import ReaderClient
from ...operator_service import SOCKET_PATH

# Backend codes in plain Turkish; the code itself is still shown for support.
# Arka uç kodlarının Türkçe karşılığı; destek için kod da gösterilir.
MESSAGES = {
    'key_file_missing': 'Anahtar dosyası yok: /etc/satsuma-core/deepseek.key oluşturun.',
    'key_mode_must_be_0600': 'Anahtar dosyasının izni 0600 olmalı: sudo chmod 600 /etc/satsuma-core/deepseek.key',
    'key_owner_must_be_root_root': 'Anahtar dosyasının sahibi root:root olmalı: sudo chown root:root /etc/satsuma-core/deepseek.key',
    'key_not_regular_file': 'Anahtar normal bir dosya olmalı; kısayol (symlink) kabul edilmez.',
    'key_has_extra_hard_link': 'Anahtar dosyasının ikinci bir bağlantısı var; dosyayı yeniden oluşturun.',
    'key_size_invalid': 'Anahtar dosyası boş ya da 4096 bayttan büyük.',
    'key_content_invalid': 'Anahtar dosyasında yalnızca boşluksuz tek satır anahtar olmalı.',
    'key_unavailable_root_0600_required': 'Anahtar okunamadı: dosya root:root ve 0600 izinli olmalı.',
    'backend_not_root': 'Yetkili arka uç root olarak çalışmıyor; satsuma-operator servisini kontrol edin.',
    'deepseek_disabled': 'DeepSeek ayarlarda kapalı (deepseek_enabled).',
    'explicit_network_consent_required': 'Bu API isteği için onay kutusunu işaretleyin.',
    'api_rate_limit_reached': 'Saatlik istek sınırı doldu ya da iki istek arasında 3 saniye geçmedi; biraz bekleyin. Sınır ayarlardan (deepseek_requests_per_hour) değiştirilebilir.',
    'request_timeout': 'DeepSeek zamanında yanıt vermedi; ağ bağlantısını kontrol edin.',
    'network_or_response_error': 'DeepSeek sunucusuna ulaşılamadı ya da yanıt hatalı (ağ, DNS ya da anahtar).',
    'invalid_mitre_technique': 'MITRE tekniği T1059 ya da T1059.004 biçiminde olmalı.',
    'unsupported_attack_type': 'Seçilen saldırı türü desteklenmiyor.',
    'prompt_too_large': 'İstek çok büyük.',
    'response_too_large': 'DeepSeek yanıtı izin verilen boyutu aşıyor.',
    'unsafe_or_unexpected_response': 'DeepSeek yanıtı güvenlik kontrolünden geçmedi; kural oluşturulmadı.',
    'approval_required': 'Bu işlem için önce kural onaylanmalı.',
    'operation_preconditions_failed': 'İşlemin ön koşulları sağlanmadı.',
    'identical_rule_already_present': 'Bu kuralın aynısı zaten kuyrukta ya da etkin; yeni bir şey eklenmedi.',
    'rejection_reason_required': 'Reddetmek için "Ret gerekçesi" kutusuna kısa bir açıklama yazın.',
    'duplicate_rule_id_history_preserved': 'Bu kural kimliği kuyrukta zaten var. Önce mevcut kuralı reddedin; reddedilen kural aynı kimlikle yeniden gönderilebilir.',
    'active_rule_id_collision': 'Bu kimlikte etkin bir kural var; DeepSeek\'ten farklı kimlikli bir kural isteyin.',
    'invalid_state_transition': 'Kural bu işlem için uygun durumda değil (önce gönderin ya da onaylayın).',
    'signed_state_required': 'Etkinleştirmeden önce kuralı onaylayın.',
    'functional_tests_failed': 'Kural kendi testlerini geçmedi; 02 sekmesinde test edin.',
    'rule_not_found': 'Bu kimlikte kural bulunamadı; listeyi yenileyin.',
    'activation_target_exists': 'Bu kural zaten etkin.',
}


def explain(error):
    """Turkish text for a backend error code or message."""
    text = str(error or '')
    return MESSAGES.get(text, text or 'Bilinmeyen hata')


CASE_NAMES = {'positive': 'olumlu', 'negative': 'olumsuz', 'wrong_source': 'yanlış kaynak',
              'repeat_determinism': 'tekrar'}


def failed_cases(result):
    """Turkish summary of isolated-test cases that did not behave as expected."""
    report = result.get('test_report') if isinstance(result.get('test_report'), dict) else result
    cases = report.get('cases') if isinstance(report, dict) else None
    if not isinstance(cases, list):
        return ''
    parts = []
    for case in cases:
        if isinstance(case, dict) and case.get('passed') is False:
            kind = CASE_NAMES.get(case.get('case'), str(case.get('case')))
            what = 'yakalanmadı' if case.get('case') == 'positive' else 'yanlışlıkla yakalandı'
            parts.append(f"{kind} örnek {int(case.get('index', 0)) + 1} {what}")
    return ', '.join(parts)


def session_expired(error):
    text = str(error or '').casefold()
    return 'oturum' in text and ('gerekli' in text or 'süresi' in text)


@register
class DeepSeekPanel(BasePanel):
    PANEL_ID='deepseek'
    PANEL_TITLE='Tehdit araştırması'
    PANEL_ORDER=9
    PANEL_GROUP='main'
    REFRESH_MS=3000
    completed=pyqtSignal(str,object)

    def _token(self):
        panels=getattr(self.window(),'_panels',{})
        return getattr(panels.get('admin'),'token',None)

    def _build(self):
        self._busy=False;self._stage='Henüz öneri yok';self._payload=None;self._buttons={}
        title=QHBoxLayout()
        heading=QVBoxLayout();eyebrow=QLabel('ARAŞTIRMA ÇALIŞMA ALANI');eyebrow.setObjectName('eyebrow');heading.addWidget(eyebrow)
        name=QLabel('DeepSeek ile araştır. Satsuma ile doğrula.');name.setObjectName('pageTitle');name.setWordWrap(True);heading.addWidget(name)
        title.addLayout(heading,1)
        access=QPushButton('Yönetici oturumu');access.setObjectName('quiet');access.clicked.connect(lambda:self.window().nav.select('admin'));title.addWidget(access)
        self._layout.addLayout(title)
        note=QLabel('Öneri → doğrulama → izole test → onay (Satsuma mühürler) → aktivasyon. GPG imzası isteğe bağlıdır. Müdahale yetkisi Satsuma’da kalır.')
        note.setWordWrap(True);note.setObjectName('secondary');self._layout.addWidget(note)
        self.tabs=QTabWidget();self._layout.addWidget(self.tabs,1)
        research=QWidget();form=QVBoxLayout(research);form.setSpacing(14)
        fields=QHBoxLayout();self.technique=QLineEdit();self.technique.setPlaceholderText('MITRE tekniği · T1059.004')
        self.attack=QComboBox()
        for key,label in (('reverse_shell','Ters kabuk'),('privilege_escalation','Yetki yükseltme'),
                ('credential_access','Kimlik bilgilerine erişim'),('persistence','Kalıcılık'),
                ('defense_evasion','Savunmadan kaçınma'),('network_reconnaissance','Ağ keşfi'),('malware','Zararlı yazılım'),
                ('memory_code_integrity','Bellek kod bütünlüğü'),('anonymous_executable','Anonim yürütülebilir bellek'),('memfd_execution','memfd yürütme')):
            self.attack.addItem(label,key)
        fields.addWidget(self.technique,1);fields.addWidget(self.attack,1);form.addLayout(fields)
        self.consent=QCheckBox('Bu işlem için DeepSeek API kullanımını ve şema gönderimini onaylıyorum.')
        self.consent.setToolTip('Yerel olaylar, komutlar, IP adresleri ve özel anahtar gönderilmez. Her istek ayrı onay gerektirir.')
        form.addWidget(self.consent)
        grid=QGridLayout();form.addLayout(grid)
        for index,(label,method) in enumerate((('DeepSeek durumunu kontrol et','deepseek_status'),
            ('Bağlantıyı test et','deepseek_test_connection'),('Tehdit araştır','deepseek_research'),('Kural oluştur','deepseek_generate'))):
            self._button(grid,index//2,index%2,label,method)
        self.research_summary=QPlainTextEdit();self.research_summary.setReadOnly(True)
        self.research_summary.setPlaceholderText('Yanıt burada gösterilir. İstek olmadan ağ bağlantısı kurulmaz.');self.research_summary.setMinimumHeight(140);form.addWidget(self.research_summary,1)
        self.tabs.addTab(self._scrolling(research),'01  Araştırma')
        package=QWidget();layout=QVBoxLayout(package)
        self.editor=QPlainTextEdit();self.editor.setPlaceholderText('DeepSeek’ten alınan gerçek tespit + müdahale önerisi paketi (JSON).')
        self.editor.setMinimumHeight(220);layout.addWidget(self.editor,1)
        checks=QGridLayout();layout.addLayout(checks)
        for index,(label,method) in enumerate((('Tespit şemasını doğrula','deepseek_validate_detection'),
            ('Müdahale şemasını doğrula','deepseek_validate_response'),('Ortak kimliği doğrula','deepseek_validate_identity'),
            ('Kuralı izole ortamda test et','deepseek_test_rule'),('Müdahale politikasını değerlendir','deepseek_evaluate_response'),
            ('İnceleme kuyruğuna gönder','deepseek_submit'))):
            self._button(checks,index//2,index%2,label,method)
        self.tabs.addTab(self._scrolling(package),'02  Doğrulama ve test')
        review=QWidget();layout=QVBoxLayout(review)
        self.queue=QTableWidget(0,4);self.queue.setHorizontalHeaderLabels(['Kural','Durum','İmza','Aktivasyon'])
        self.queue.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers if hasattr(QTableWidget,'EditTrigger') else QTableWidget.NoEditTriggers)
        self.queue.horizontalHeader().setStretchLastSection(True);self.queue.verticalHeader().hide();self.queue.setMaximumHeight(180)
        self.queue.cellClicked.connect(self._pick_rule);layout.addWidget(self.queue)
        identity=QHBoxLayout();self.rule_id=QLineEdit();self.rule_id.setPlaceholderText('İncelenecek kural kimliği')
        self.reason=QLineEdit();self.reason.setPlaceholderText('Ret gerekçesi');identity.addWidget(self.rule_id);identity.addWidget(self.reason);layout.addLayout(identity)
        actions=QGridLayout();layout.addLayout(actions)
        for index,(label,method) in enumerate((('Bekleyen / incelenen kuralları göster','deepseek_list'),
            ('Kuralı onayla · aktive etmez','deepseek_approve'),('Kuralı gerekçeyle reddet','deepseek_reject'),
            ('İmzalanacak paketi getir','deepseek_export'),('İmzayı doğrula','deepseek_verify_signature'),
            ('İmzalı kuralı aktifleştir','deepseek_activate'),('Aktivasyon durumunu gör','deepseek_activation_status'))):
            self._button(actions,index//2,index%2,label,method)
        self.signing=QPlainTextEdit();self.signing.setReadOnly(True);self.signing.setPlaceholderText('Onaydan sonra sizin imzalayacağınız değişmez paket. Özel GPG anahtarı burada istenmez.')
        self.signing.setMinimumHeight(110);layout.addWidget(self.signing,1)
        row=QHBoxLayout();save=QPushButton('Paketi dosyaya kaydet');save.clicked.connect(self._save_payload)
        load=QPushButton('İsteğe bağlı: açık GPG imzasını yükle (.asc)');load.clicked.connect(self._load_signature)
        row.addWidget(save);row.addWidget(load);layout.addLayout(row)
        self.signature=QPlainTextEdit();self.signature.setMaximumHeight(76);self.signature.setPlaceholderText('-----BEGIN PGP SIGNATURE-----');layout.addWidget(self.signature)
        self.tabs.addTab(self._scrolling(review),'03  İnceleme, imza ve aktivasyon')
        self.status=QLabel('İşlem yapmak için mevcut yönetici oturumunu açın.');self.status.setWordWrap(True);self.status.setObjectName('workflowStatus');self._layout.addWidget(self.status)
        self.result=QPlainTextEdit();self.result.setReadOnly(True);self.result.setMaximumHeight(130);self.result.setPlaceholderText('Doğrulama, test ve müdahale sonuçları ayrı gösterilir.');self._layout.addWidget(self.result)
        self.completed.connect(self._done);self.refresh()

    @staticmethod
    def _scrolling(page):
        """A tab page that scrolls instead of squeezing buttons on top of each other on short windows."""
        page.setMinimumHeight(page.sizeHint().height())
        area=QScrollArea();area.setWidgetResizable(True);area.setFrameShape(QFrame.Shape.NoFrame if hasattr(QFrame,'Shape') else QFrame.NoFrame)
        area.setWidget(page)
        return area

    def _button(self,grid,row,column,label,method):
        button=QPushButton(label);button.setMinimumHeight(38)
        if method in ('deepseek_generate','deepseek_submit'):button.setObjectName('primary')
        if method=='deepseek_activate':button.setObjectName('danger')
        button.clicked.connect(lambda checked=False,m=method:self._send(m));grid.addWidget(button,row,column);self._buttons[method]=button

    def refresh(self):
        enabled=bool(self._token()) and not self._busy
        for button in self._buttons.values():button.setEnabled(enabled)

    def _send(self,method):
        if self._busy:return
        token=self._token()
        if not token:
            self.status.setText('Yönetici oturumu gerekli.');return
        params={'token':token,'request_id':uuid.uuid4().hex}
        if method in ('deepseek_test_connection','deepseek_research','deepseek_generate'):
            if not self.consent.isChecked():
                self.status.setText('Bu API isteği için açık onay kutusunu işaretleyin.');return
            params.update(confirmed=True,technique=self.technique.text().strip() or None,attack_type=self.attack.currentData())
            self.consent.setChecked(False)
        if method in ('deepseek_validate_detection','deepseek_validate_response','deepseek_validate_identity',
                      'deepseek_test_rule','deepseek_evaluate_response','deepseek_submit'):
            try:
                if len(self.editor.toPlainText().encode())>32768:raise ValueError()
                params['package']=json.loads(self.editor.toPlainText())
            except (ValueError,TypeError):
                self.status.setText('Geçerli ve en fazla 32 KiB büyüklüğünde JSON paketini girin.');return
        if method in ('deepseek_approve','deepseek_reject','deepseek_verify_signature','deepseek_activate','deepseek_activation_status','deepseek_export'):
            params['rule_id']=self.rule_id.text().strip()
            if not params['rule_id']:
                self.status.setText('Bir kural seçin.');return
        if method=='deepseek_reject':params['reason']=self.reason.text().strip()
        if method=='deepseek_verify_signature':
            signature=self.signature.toPlainText().strip()
            if not signature.startswith('-----BEGIN PGP SIGNATURE-----') or len(signature.encode())>16384:
                self.status.setText('Yalnız açık, ayrık GPG imzasını yükleyin. Özel anahtar yüklemeyin.');return
            params['signature']=signature
        if method=='deepseek_activate':
            answer=QMessageBox.question(self,'İmzalı kural aktivasyonu',
                'İmzalı tespit kuralı, doğrulamadan sonra motora sunulacak. Bu işlem önerilen müdahaleyi çalıştırmaz. Devam edilsin mi?')
            yes=QMessageBox.StandardButton.Yes if hasattr(QMessageBox,'StandardButton') else QMessageBox.Yes
            if answer!=yes:return
            params['confirmed']=True
        self._busy=True;self.status.setText('İşlem sürüyor… Ekranı değiştirebilirsiniz.');self.refresh()
        def task():
            try:result=ReaderClient(SOCKET_PATH,timeout=60).call(method,**params)
            except Exception as exc:
                # Show the real reason (session, socket, rate limit) instead of one generic sentence.
                result={'ok':False,'error':str(exc)[:300] or type(exc).__name__}
            try:self.completed.emit(method,result)
            except RuntimeError:pass
        threading.Thread(target=task,name='satsuma-deepseek-ui',daemon=True).start()

    def _done(self,method,result):
        self._busy=False;self.refresh()
        success=result.get('ok') is True
        error=result.get('error') or result.get('errors')
        if not success and session_expired(error):
            admin=getattr(self.window(),'_panels',{}).get('admin')
            if admin is not None:
                admin.token=None
                if hasattr(admin,'refresh'):admin.refresh()
            self.refresh()
            self.status.setText('Yönetici oturumu sona erdi. Sağ üstteki "Yönetici erişimi" ile yeniden giriş yapın.')
        elif success and method=='deepseek_status':
            problem=result.get('key_problem')
            key='Anahtar hazır' if result.get('key_available') else 'Anahtar kullanılamıyor: '+explain(problem)
            self.status.setText(key+' · Bu saat kalan istek: '+str(result.get('network_requests_left_this_hour','?'))+'/'+str(result.get('network_requests_per_hour','?')))
        elif success and method=='deepseek_approve' and result.get('sealed'):
            self.status.setText('Onaylandı ve Satsuma tarafından mühürlendi. GPG imzası gerekmez; şimdi etkinleştirebilirsiniz.')
        elif success and str(result.get('renamed','')).startswith('renamed_from:'):
            self.status.setText('Kimlik çakıştığı için kurala yeni kimlik verildi: '+str(result.get('rule_id'))+' (eski: '+str(result['renamed']).split(':',1)[1]+').')
        elif success:
            self.status.setText('İşlem tamamlandı · '+method.removeprefix('deepseek_'))
        elif failed_cases(result):
            self.status.setText('Kural kendi testini geçmedi: '+failed_cases(result)+
                                '. base_match içindeki koşulların hepsi birlikte (VE) sağlanmalı.')
        else:
            code=str(error or 'Doğrulama sonucu başarısız')
            self.status.setText('İşlem tamamlanamadı · '+explain(code)+('' if explain(code)==code else ' ('+code+')'))
        self.result.setPlainText(json.dumps(result,ensure_ascii=False,indent=2))
        if 'package' in result:
            self.editor.setPlainText(json.dumps(result['package'],ensure_ascii=False,indent=2));self.tabs.setCurrentIndex(1)
            self.research_summary.setPlainText(json.dumps(result,ensure_ascii=False,indent=2))
        if result.get('signing_payload'):
            self._payload=result['signing_payload'];self.signing.setPlainText(self._payload)
        if method=='deepseek_list':
            rows=result.get('items') or [];self._queue_rows=rows;self.queue.setRowCount(len(rows))
            for row,item in enumerate(rows):
                values=(item.get('rule_id'),item.get('status'),'Doğrulandı' if item.get('signature_fingerprint') else 'Bekleniyor',item.get('activation') or 'Henüz aktive edilmedi')
                for col,value in enumerate(values):self.queue.setItem(row,col,QTableWidgetItem(str(value)))

    def _pick_rule(self,row,column):
        if 0<=row<len(getattr(self,'_queue_rows',[])):self.rule_id.setText(self._queue_rows[row]['rule_id'])

    def _save_payload(self):
        if not self._payload:
            self.status.setText('Önce onaylanan imza paketini getirin.');return
        path,_=QFileDialog.getSaveFileName(self,'İmzalanacak paketi kaydet','satsuma-approved-package.json','JSON (*.json)')
        if path:
            try:Path(path).write_bytes(self._payload.encode('utf-8'))
            except OSError:self.status.setText('Paket dosyası kaydedilemedi.')

    def _load_signature(self):
        path,_=QFileDialog.getOpenFileName(self,'Yalnız ayrık açık GPG imzasını seçin','','GPG imzası (*.asc)')
        if path:
            try:
                with open(path,'rb') as stream:data=stream.read(16385)
                text=data.decode('ascii')
                if len(data)>16384 or not text.startswith('-----BEGIN PGP SIGNATURE-----'):raise ValueError()
                self.signature.setPlainText(text)
            except (OSError,ValueError,UnicodeError):self.status.setText('Geçerli bir açık GPG imzası seçilmedi. Özel anahtar kabul edilmez.')
