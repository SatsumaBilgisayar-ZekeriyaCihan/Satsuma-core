"""Actual management operations through the authenticated operator socket.

Kimliği doğrulanmış operatör soketi üzerinden gerçek yönetim işlemleri.

Lowering protection asks for the admin password again before the request
is sent (audit K7). Korumayı azaltan işlemler, istek gönderilmeden önce
yönetici parolasını yeniden sorar (denetim K7).

The VPN / Proxy page imports WireGuard profiles from a .conf file and
connects or disconnects them; Satsuma opens the server port while a
profile is active. VPN / Proxy sayfası WireGuard profillerini .conf
dosyasından içe aktarır, bağlar ve keser; profil etkinken sunucu portunu
Satsuma açar.
"""
import threading
try:
    from PyQt6.QtWidgets import QLabel, QLineEdit, QPushButton, QHBoxLayout, QComboBox, QScrollArea, QWidget, QVBoxLayout, QCheckBox, QPlainTextEdit, QListWidget, QStackedWidget, QInputDialog, QFileDialog
    from PyQt6.QtCore import pyqtSignal, Qt
except ImportError:
    from PyQt5.QtWidgets import QLabel, QLineEdit, QPushButton, QHBoxLayout, QComboBox, QScrollArea, QWidget, QVBoxLayout, QCheckBox, QPlainTextEdit, QListWidget, QStackedWidget, QInputDialog, QFileDialog
    from PyQt5.QtCore import pyqtSignal, Qt
from .base import BasePanel
from . import register
from ...dashboard_api_client import ReaderClient
from ...operator_service import SOCKET_PATH, SERVICES, weakens
from ..stable_widgets import StableComboBox as QComboBox, update_choices
from ...status_view import label, timestamp
from ..detail_sanitizer import detail_lines
from ...verification_view import job_text, decision_text



def otx_dns_text(info):
    """OTX's share of the DNS filter: blocked names, checked names, last error."""
    if not isinstance(info, dict):
        return ''
    text = ' · OTX: ' + str(info.get('blocked', 0)) + ' alan adı engelli (' + str(info.get('checked', 0)) + ' denetlendi)'
    if info.get('status') == 'disabled':
        text += ', sorgular kapalı'
    elif info.get('status') == 'key_missing':
        text += ', API anahtarı yok'
    elif info.get('status') == 'error' and info.get('error'):
        text += ', hata: ' + str(info['error'])[:160]
    return text


@register
class AdminPanel(BasePanel):
    PANEL_ID = 'admin'
    PANEL_TITLE = 'Yönetim'
    PANEL_ORDER = 15
    REFRESH_MS = 5000
    completed = pyqtSignal(object, object)

    def _build(self):
        outer = self._layout
        self._outer = outer
        body = QHBoxLayout()
        self.sections = QListWidget()
        self.sections.setFixedWidth(235)
        self.pages = QStackedWidget()
        body.addWidget(self.sections)
        body.addWidget(self.pages, 1)
        outer.addLayout(body, 1)
        self.sections.currentRowChanged.connect(self.pages.setCurrentIndex)
        self._page('Genel durum')
        self.token = None
        self._busy = False
        self._reading_status = False
        self._mutation_serial = 0
        intro=QLabel('Koruma ayarları ve izinler. Değişiklik yapmak için yönetici oturumu açın.')
        intro.setWordWrap(True);intro.setObjectName('secondary');self._layout.addWidget(intro)
        self.status = QLabel('Yönetim servisine giriş yapın.')
        self.status.setWordWrap(True)
        self._layout.addWidget(self.status)
        scan=QPushButton('ClamAV, rkhunter ve chkrootkit ile yerel tarama')
        scan.clicked.connect(lambda:self._send('security_scan',{}))
        self._layout.addWidget(scan)
        self._page('Yönetici erişimi ve doğrulama')
        row = QHBoxLayout()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password if hasattr(QLineEdit, 'EchoMode') else QLineEdit.Password)
        self._layout.addWidget(QLabel('Yönetici parolası'))
        self.password.setPlaceholderText('Yönetici parolası')
        row.addWidget(self.password)
        button = QPushButton('Yönetim oturumu aç')
        button.clicked.connect(self._login)
        row.addWidget(button)
        self._layout.addLayout(row)
        self._controls = [scan]
        self._toggles = {}
        self._layout = self.pages.widget(0).widget().layout()
        self._add_buttons([('Durumu oku', 'status', {}), ('Oturumu kapat', 'logout', {})])
        self._page('Uygulama izinleri')
        app_notice = QLabel('Satsuma App Control: uygulama, kullanıcı ve dosya hash’i temelinde ağ izni. Bekleyen bağlantılar onaylanana kadar engellenir.')
        app_notice.setWordWrap(True)
        self._layout.addWidget(app_notice)
        self.opensnitch_state=QLabel('OpenSnitch: durum bekleniyor')
        self.opensnitch_state.setWordWrap(True);self._layout.addWidget(self.opensnitch_state)
        self._page('Ağ koruması')
        self.modem_tables = QPlainTextEdit()
        self.modem_tables.setReadOnly(True)
        self.modem_tables.setMaximumHeight(160)
        self.modem_tables.setPlaceholderText('Tüm yönlendirme tablolarını ve modem adaylarını listeleyin.')
        self.modem_tables.hide()
        modem_details=QPushButton('Teknik ayrıntılar: modem tabloları')
        modem_details.clicked.connect(lambda:self.modem_tables.setVisible(self.modem_tables.isHidden()))
        self._layout.addWidget(modem_details)
        self._layout.addWidget(self.modem_tables)
        self.modem_choices = QComboBox()
        self._layout.addWidget(self.modem_choices)
        self.modem_confirm = QCheckBox('Seçtiğim cihazın kendi modemim olduğunu doğruladım; bu tek referansı onaylıyorum.')
        self._layout.addWidget(self.modem_confirm)
        self._add_buttons([('Tüm tabloları / modemleri listele', 'modem_inventory', {}),
                           ('Seçtiğim modemi onayla', 'modem_approve', {})])
        self.modem_mac = QLineEdit()
        self.modem_mac.setPlaceholderText('Modemin MAC adresini elle yazın (ör. a8:9a:93:12:34:56)')
        self._layout.addWidget(self.modem_mac)
        self._add_buttons([('Elle yazdığım MAC ile onayla', 'modem_manual', {})])
        self._layout = self.pages.widget(2).widget().layout()
        self._layout.addWidget(QLabel('Karar bekleyen uygulama (seçim yapın)'))
        self.app_requests = QComboBox()
        self._layout.addWidget(self.app_requests)
        self._layout.addWidget(QLabel('Kararın geçerlilik kapsamı'))
        self.app_duration = QComboBox()
        self.app_duration.addItem('Bu bağlantı / en fazla 5 dakika', 'once')
        self.app_duration.addItem('Bu dosya, kullanıcı ve uygulama oturumu için kalıcı', 'always')
        self.app_duration.addItem('Bu dosya ve kullanıcı; alt süreç oturumları dahil kalıcı', 'application')
        self.app_duration.setCurrentIndex(self.app_duration.findData('application'))
        self._layout.addWidget(self.app_duration)
        self._add_buttons([('İzin ver', 'application_control', {'action':'decision','decision':'allow'}),
                           ('Engelle', 'application_control', {'action':'decision','decision':'deny'})])
        self._layout.addWidget(QLabel('Kayıtlı uygulama kuralı'))
        self.app_rules = QComboBox()
        self._layout.addWidget(self.app_rules)
        self._add_buttons([('Kuralı izin ver yap', 'application_control', {'action':'rule','decision':'allow'}),
                           ('Kuralı engelle yap', 'application_control', {'action':'rule','decision':'deny'}),
                           ('Yeniden sor', 'application_control', {'action':'rule','decision':'ask'})])
        self._add_buttons([('App Control aç', 'application_control', {'action':'enable'}),
                           ('App Control kapat', 'application_control', {'action':'disable'})])
        self._layout = self.pages.widget(3).widget().layout()
        self._add_buttons([('Otomatik engellemeyi aç', 'enforcement', {'enabled': True}), ('Otomatik engellemeyi kapat', 'enforcement', {'enabled': False})])
        enforcement_note = QLabel('Otomatik engelleme: şüpheli, muhtemel ve kesin saldırı kuralları (her önem düzeyinde) eşleşince o programı durdurur. '
            'Satsuma, TeamViewer, AnyDesk, masaüstü ve paket yöneticisi asla durdurulmaz. Durdurulan her program bulgularda görünür.')
        enforcement_note.setWordWrap(True);enforcement_note.setObjectName('secondary')
        self._layout.addWidget(enforcement_note)
        self._add_buttons([('Otomatik ağ engelini aç', 'auto_network', {'enabled': True}), ('Otomatik ağ engelini kapat', 'auto_network', {'enabled': False})])
        notice = QLabel('Otomatik engel: taze ve doğrulanmış bulgu, en az iki bağımsız kaynak, genel IP. İzinli IP’ler korunur.')
        notice.setWordWrap(True)
        self._layout.addWidget(notice)
        self._add_buttons([('Yerel ağa izin ver', 'lan_access', {'enabled': True}), ('Yerel ağı kapat; internet/DNS açık', 'lan_access', {'enabled': False})])
        self._add_buttons([('Aynı subnet içinde 10 farklı IP engelini aç', 'subnet_protection', {'enabled': True}), ('Subnet korumasını kapat', 'subnet_protection', {'enabled': False})])
        self._page('DNS ve tehdit listeleri')
        self._add_buttons([('OTX sorgularını aç', 'otx_enabled', {'enabled': True}), ('OTX sorgularını kapat', 'otx_enabled', {'enabled': False})])
        self._add_buttons([('OTX eşik engelini aç', 'otx_blocker', {'enabled': True}), ('OTX eşik engelini kapat', 'otx_blocker', {'enabled': False})])
        self._layout.addWidget(QLabel('DNS sunucusu IP adresi (loopback kullanmayın)'))
        self.dns_upstream = QLineEdit()
        self.dns_upstream.setPlaceholderText('Mevcut DNS sunucunuzun IP adresi (loopback değil)')
        self._layout.addWidget(self.dns_upstream)
        self._add_buttons([('dnsmasq alan adı filtresini aç', 'dns_filter', {'enabled': True}), ('Alan adı filtresini kapat', 'dns_filter', {'enabled': False})])
        self._add_buttons([('HaGeZi Ultimate listesini güncelle', 'hagezi_update', {}), ('Ultimate listesini kullan', 'hagezi_enabled', {'enabled': True}), ('Ultimate listesini kapat', 'hagezi_enabled', {'enabled': False})])
        self._layout.addWidget(QLabel('Ek tehdit listesi HTTPS adresi'))
        self.custom_list_url = QLineEdit()
        self.custom_list_url.setPlaceholderText('Ek malware listesi: https://… (alan adı / hosts / adblock)')
        self._layout.addWidget(self.custom_list_url)
        self._add_buttons([('Listeyi ekle/güncelle', 'custom_list_update', {}), ('Listeyi kaldır', 'custom_list_remove', {}), ('Ek listelerin durumunu gör', 'custom_lists_status', {})])
        self.custom_list_status = QLabel('Liste kullanımı için DNS filtresini yapılandırıp açın. IP/CIDR ve tam URL listeleri bu alanda kullanılmaz.')
        self.custom_list_status.setWordWrap(True)
        self._layout.addWidget(self.custom_list_status)
        self._layout.addWidget(QLabel('İzin verilecek alan adı (örnek: ornek.com)'))
        self.domain = QLineEdit()
        self.domain.setPlaceholderText('Yanlış engellenen alan adı; örnek: ornek.com')
        self._layout.addWidget(self.domain)
        self._add_buttons([('Alan adına izin ver', 'allow_domain', {}), ('Alan adı iznini kaldır', 'remove_allow_domain', {})])
        dns_notice = QLabel('Normal DNS açık kalır. Ultimate veya OTX listesine giren adlar dnsmasq ile engellenir. OTX anahtarı: sudo satsuma-admin set-otx-key; kaydetme sorgulamayı ve eşik engelini açar. Yerel ağ kapalıyken internet, DNS ve ağ yapılandırma trafiği korunur.')
        dns_notice.setWordWrap(True)
        self._layout.addWidget(dns_notice)
        self._layout = self.pages.widget(3).widget().layout()
        self._layout.addWidget(QLabel('İzin verilecek veya engeli kaldırılacak IP adresi'))
        self.ip = QLineEdit()
        self.ip.setPlaceholderText('IPv4 / IPv6 adresi')
        self._layout.addWidget(self.ip)
        self._add_buttons([('İzinli listeye ekle', 'allow_ip', None), ('İzinli listeden çıkar', 'remove_allow_ip', None), ('Engeli kaldır', 'unblock', None)])
        self._page('Servisler')
        self._layout.addWidget(QLabel('İşlem yapılacak servis'))
        self.service = QComboBox()
        self.service.addItems(SERVICES)
        self._layout.addWidget(self.service)
        self._add_buttons([('Seçili servisi başlat', 'service', {'action': 'start'}), ('Seçili servisi durdur', 'service', {'action': 'stop'}), ('Seçili servisi yeniden başlat', 'service', {'action': 'restart'}), ('Servis durumu', 'service', {'action': 'status'})])
        self._layout = self.pages.widget(1).widget().layout()
        self.integrity_label = QLabel('Uygulama doğrulaması açılışta ve periyodik olarak otomatik yapılır.')
        self.integrity_label.setWordWrap(True)
        self._layout.addWidget(self.integrity_label)
        self.verification_job_label = QLabel('Bekleyen kontrol yok')
        self.verification_job_label.setWordWrap(True)
        self._layout.addWidget(self.verification_job_label)
        self._add_buttons([('Doğrulamayı şimdi çalıştır', 'boot_check', {})])
        self._add_buttons([('systemd güvenlik denetimi', 'systemd_security', {}), ('/dev aygıt envanteri', 'device_inventory', {})])
        self._layout.addStretch()
        self._page('VPN / Proxy')
        note=QLabel('Göstergeler saldırı kanıtı değildir. Seçilen VPN bağlantısı veya süreç yalnız onayınızla kapatılır. Kalıcı engelleme yapılmaz; servis yeniden başlatabilir.')
        note.setWordWrap(True);self._layout.addWidget(note)
        self.vpn_targets=QComboBox();self._layout.addWidget(self.vpn_targets)
        self.vpn_confirm=QCheckBox('Seçtiğim bağlantının kesilmesini onaylıyorum; ağ erişimim kesilebilir.')
        self._layout.addWidget(self.vpn_confirm)
        self._add_buttons([('Durumu yenile','status',{}),('Seçileni kapat','vpn_proxy_disconnect',{})])
        self._layout.addWidget(self.make_title('WireGuard VPN'))
        wg_note=QLabel('WireGuard profilini .conf dosyasından içe aktarın. Profil etkinken Satsuma sunucunun UDP portunu kendisi açar, kapanınca kapatır; dışarıdan gelen bağlantı açılmaz. Dosyadaki DNS satırı uygulanmaz, Satsuma DNS filtresi sabit kalır. PreUp/PostUp gibi komut satırları olan dosyalar reddedilir.')
        wg_note.setWordWrap(True);self._layout.addWidget(wg_note)
        self._layout.addWidget(QLabel('Yeni profilin adı (küçük harf, rakam, -; en fazla 15 karakter)'))
        self.wg_name=QLineEdit();self.wg_name.setPlaceholderText('ör. ev-vpn');self._layout.addWidget(self.wg_name)
        self._add_buttons([('Dosyadan içe aktar…','wireguard',{'action':'import'})])
        self.wg_profiles=QComboBox();self._layout.addWidget(self.wg_profiles)
        self._add_buttons([('Bağlan','wireguard',{'action':'up'}),('Bağlantıyı kes','wireguard',{'action':'down'}),('Profili sil','wireguard',{'action':'remove'})])
        self.wg_state=QLabel('WireGuard: durum bekleniyor');self.wg_state.setWordWrap(True);self._layout.addWidget(self.wg_state)
        self._page('İnternet trafiği')
        question=QLabel('İnternet trafiğini nasıl ayarlayalım? Seçtikleriniz yalnızca bu bilgisayardan dışarıya giden bağlantıları açar; dışarıdan gelen bağlantılar her seçenekte kapalı kalır. DNS sunucunuz değişmez.')
        question.setWordWrap(True);self._layout.addWidget(question)
        self._layout.addWidget(QLabel('Her zaman açık: DNS (TCP/UDP 53) ve HTTPS (TCP 443).'))
        from ...egress_profiles import ADDONS
        self.egress_addons={}
        for key,item in ADDONS.items():
            box=QCheckBox(item['title']+'\n'+item['explain'])
            self.egress_addons[key]=box;self._layout.addWidget(box)
        self._layout.addWidget(QLabel('Özel TCP portları (virgülle; örnek: 8443, 9000)'))
        self.egress_tcp=QLineEdit();self.egress_tcp.setPlaceholderText('Boş bırakılabilir');self._layout.addWidget(self.egress_tcp)
        self._layout.addWidget(QLabel('Özel UDP portları (virgülle)'))
        self.egress_udp=QLineEdit();self.egress_udp.setPlaceholderText('Boş bırakılabilir');self._layout.addWidget(self.egress_udp)
        self._add_buttons([('Seçimi uygula','egress_profile',{'action':'set'})])
        self.egress_state=QLabel('Etkin profil: durum bekleniyor')
        self.egress_state.setWordWrap(True);self._layout.addWidget(self.egress_state)
        self._egress_loaded=False
        # Consistent navigation order, independent scroll area for each page.
        page_order=[0,2,3,7,4,5,1,6]
        page_widgets=[self.pages.widget(i) for i in page_order]
        titles=[self.sections.item(i).text() for i in page_order]
        self.sections.clear()
        for widget in page_widgets:self.pages.removeWidget(widget)
        for title,widget in zip(titles,page_widgets):
            self.sections.addItem(title);self.pages.addWidget(widget)
        self.sections.setCurrentRow(0)
        self.status.setMinimumHeight(90)
        self.status.setMaximumHeight(90)
        self.status.setToolTip('İşlem tamamlanması sistemin sağlıklı olduğunu göstermez.')
        # Put operation feedback above the fixed navigation, always visible.
        feedback=QHBoxLayout();feedback.addWidget(self.status,1)
        access=QPushButton('Yönetici oturumu aç');access.setObjectName('primary')
        access.clicked.connect(lambda:self.sections.setCurrentRow(page_order.index(1)));feedback.addWidget(access)
        self._outer.insertLayout(0,feedback)
        self.completed.connect(self._done)
        self._set_enabled()

    def _page(self, title):
        scroll=QScrollArea();scroll.setWidgetResizable(True)
        form=QWidget();form.setObjectName('settingsPage')
        self._layout=QVBoxLayout(form);self._layout.setSpacing(14);self._layout.setContentsMargins(22,22,22,22)
        self._layout.setAlignment(Qt.AlignmentFlag.AlignTop if hasattr(Qt,'AlignmentFlag') else Qt.AlignTop)
        self._layout.addWidget(self.make_title(title))
        scroll.setWidget(form);self.pages.addWidget(scroll);self.sections.addItem(title)

    def _add_buttons(self, items):
        names={'enforcement':'Otomatik engelleme (programı durdurur)','auto_network':'Otomatik ağ engeli','lan_access':'Yerel ağ erişimi',
               'subnet_protection':'Subnet koruması','otx_enabled':'OTX sorguları','otx_blocker':'OTX eşik engeli',
               'dns_filter':'DNS alan adı filtresi','hagezi_enabled':'HaGeZi Ultimate listesi'}
        if len(items)==2 and items[0][1]==items[1][1] and items[0][1] in names and all(isinstance(p,dict) and set(p)=={'enabled'} and type(p.get('enabled')) is bool for _,_,p in items):
            method=items[0][1];toggle=QCheckBox(names[method]+' — durum bekleniyor')
            toggle._state_known=False;self._toggles[method]=toggle;self._controls.append(toggle)
            toggle.clicked.connect(lambda checked,m=method:self._send(m,{'enabled':checked}))
            self._layout.addWidget(toggle);return
        row = QVBoxLayout() if all(method=='service' for _,method,_ in items) else QHBoxLayout()
        for title, method, params in items:
            button = QPushButton(title)
            button.clicked.connect(lambda checked, m=method, p=params: self._send(m, p))
            if method=='service':
                button.setText(title+' · '+self.service.currentText())
                self.service.currentTextChanged.connect(lambda name,b=button,t=title:b.setText(t+' · '+name))
            row.addWidget(button)
            self._controls.append(button)
        self._layout.addLayout(row)

    def _set_enabled(self):
        for button in self._controls:
            button.setEnabled(bool(self.token) and not self._busy and getattr(button,'_state_known',True))

    def _login(self):
        password = self.password.text()
        self.password.clear()
        self._send('login', {'password': password})

    def ask_password(self, method):
        mode = QLineEdit.EchoMode.Password if hasattr(QLineEdit, 'EchoMode') else QLineEdit.Password
        text, ok = QInputDialog.getText(self, 'Korumayı azaltan işlem',
            'Bu işlem korumayı azaltır ve kritik olarak kaydedilir.\nYönetici parolasını yeniden girin:', mode)
        return text if ok else ''

    def _send(self, method, params):
        if self._busy or (method=='status' and self._reading_status):
            return
        params = dict(params or {})
        if method != 'login':
            params['token'] = self.token
        if method in ('allow_ip', 'remove_allow_ip', 'unblock'):
            params['ip'] = self.ip.text().strip()
        if method in ('dns_filter', 'hagezi_enabled') and params.get('enabled'):
            params['upstream'] = self.dns_upstream.text().strip()
        if method in ('allow_domain', 'remove_allow_domain'):
            params['domain'] = self.domain.text().strip()
        if method in ('custom_list_update','custom_list_remove'):
            params['url'] = self.custom_list_url.text().strip()
        if method == 'modem_approve':
            params['candidate_id'] = self.modem_choices.currentData()
            params['confirmed'] = self.modem_confirm.isChecked()
            params['route_fingerprint'] = getattr(self,'_modem_fingerprint',None)
        if method == 'modem_manual':
            params['mac'] = self.modem_mac.text().strip()
            params['confirmed'] = self.modem_confirm.isChecked()
            if not params['mac'] or not params['confirmed']:
                self.status.setText('MAC adresini yazın ve kendi modeminiz olduğunu onay kutusuyla doğrulayın.');return
        if method == 'vpn_proxy_disconnect':
            params['target_id']=self.vpn_targets.currentData()
            params['confirmed']=self.vpn_confirm.isChecked()
            if not params['target_id'] or not params['confirmed']:
                self.status.setText('Bir hedef seçin ve bağlantının kesilmesini açıkça onaylayın.');return
            self.vpn_confirm.setChecked(False)
        if method == 'wireguard':
            action=params.get('action');self._wg_action=action
            if action == 'import':
                name=self.wg_name.text().strip()
                if not name:
                    self.status.setText('Önce yeni profil için bir ad yazın.');return
                path,_=QFileDialog.getOpenFileName(self,'WireGuard yapılandırması seç','','WireGuard (*.conf);;Tüm dosyalar (*)')
                if not path:return
                try:
                    with open(path,'rb') as handle:data=handle.read(16*1024+1)
                    if len(data)>16*1024:raise ValueError('Dosya 16 KB’den büyük')
                    params['text']=data.decode('utf-8')
                except (OSError,ValueError,UnicodeDecodeError) as exc:
                    self.status.setText('Dosya okunamadı: '+str(exc));return
                params['name']=name
            else:
                params['name']=self.wg_profiles.currentData()
                if not params['name']:
                    self.status.setText('Önce bir WireGuard profili seçin.');return
        if method == 'service':
            params['name'] = self.service.currentText()
        if method == 'application_control':
            if params.get('action') == 'decision':
                params['request_id'] = self.app_requests.currentData()
                params['duration'] = self.app_duration.currentData()
                if not params['request_id']:
                    self.status.setText('Karar verilecek uygulamayı seçin; eski istek kaybolduysa bağlantıyı yeniden deneyin.')
                    return
            elif params.get('action') == 'rule':
                rule = self.app_rules.currentData() or {}
                params['key'] = rule.get('key')
                params['scope'] = rule.get('scope', 'session')
        if method == 'egress_profile' and params.get('action') == 'set':
            try:
                custom={proto:[int(x) for x in field.text().replace(' ','').split(',') if x]
                        for proto,field in (('tcp',self.egress_tcp),('udp',self.egress_udp))}
            except ValueError:
                self.status.setText('Özel portlar yalnızca virgülle ayrılmış sayılar olmalı (1–65535).');return
            params['selection']={'addons':[k for k,box in self.egress_addons.items() if box.isChecked()],'custom':custom}
        try:
            lowered=weakens(method, params)
        except ValueError as exc:
            self.status.setText('İşlem uygulanamadı: '+str(exc));return
        if lowered:
            password = self.ask_password(method)
            if not password:
                self.status.setText('Korumayı azaltan işlem iptal edildi: yönetici parolası yeniden girilmedi.')
                return
            params['password'] = password
        generation=self._mutation_serial
        if method=='status':self._reading_status=True
        else:
            self._mutation_serial+=1
            self._busy=True
        if method != 'status':
            self._set_enabled()
            self.status.setText('İşlem sürüyor…'+(' Servis: '+str(params.get('name')) if method=='service' else ''))
        def task():
            try:
                result = ReaderClient(SOCKET_PATH, timeout=180).call(method, **params)
            except Exception as exc:
                result = {'error': str(exc)}
            if method=='status':result['_ui_generation']=generation
            try:
                self.completed.emit(method, result)
            except RuntimeError:
                pass
        threading.Thread(target=task, daemon=True).start()

    def _done(self, method, result):
        if method=='status':
            self._reading_status=False
            if self._busy or result.get('_ui_generation',self._mutation_serial)!=self._mutation_serial:return
        else:self._busy=False
        if method == 'login':
            self.token = result.get('token') if result.get('ok') else None
        elif method == 'logout':
            self.token = None
        if result.get('error'):
            self.status.setText('İşlem uygulanamadı: ' + str(result['error']))
            if method == 'wireguard':
                # Kept next to the WireGuard controls; the next status read must not hide it.
                self.wg_state.setText('WireGuard işlemi yapılamadı: ' + str(result['error']))
                self._wg_error = True
            if 'oturumu' in str(result['error']):
                self.token = None
        elif method == 'status':
            boot, job = result.get('early_boot') or {}, result.get('maintenance') or {}
            self.verification_job_label.setText(job_text(job)+'\n'+decision_text(result.get('verification'))+'\nSon kontrol: '+str(boot.get('state','UNKNOWN')))
            states={'auto_network':(result.get('policy') or {}).get('network_enabled'),
                'enforcement':(result.get('enforcement') or {}).get('enabled'),
                'lan_access':not result['lan']['enabled'] if type((result.get('lan') or {}).get('enabled')) is bool else None,
                'subnet_protection':(result.get('subnet') or {}).get('enabled'),
                'otx_enabled':(result.get('otx') or {}).get('enabled'),
                'otx_blocker':(result.get('otx') or {}).get('blocker_enabled'),
                'dns_filter':(result.get('dns') or {}).get('enabled'),
                'hagezi_enabled':(result.get('hagezi') or {}).get('enabled')}
            for name,toggle in self._toggles.items():
                value=states.get(name);toggle._state_known=type(value) is bool
                toggle.blockSignals(True)
                if toggle._state_known:toggle.setChecked(value)
                toggle.setText(toggle.text().split(' — ')[0]+' — '+('Açık' if value else 'Kapalı' if value is False else 'Durum alınamadı'))
                toggle.blockSignals(False)
            self._show_egress(result.get('egress'))
            snitch=result.get('opensnitch') or {}
            self.opensnitch_state.setText('OpenSnitch çalışıyor: uygulama izinlerini o veriyor, Satsuma App Control kenarda bekliyor. Satsuma kuralları: '+(', '.join(snitch.get('satsuma_rules') or []) or 'yok') if snitch.get('running')
                else 'OpenSnitch kurulu ama çalışmıyor; uygulama izinlerini Satsuma App Control veriyor.' if snitch.get('installed')
                else 'OpenSnitch kurulu değil; uygulama izinlerini Satsuma App Control veriyor. Kurulum: github.com/evilsocket/opensnitch/releases (opensnitch ve opensnitch-ui RPM).')
            app=result.get('app_control') or {}
            requests=[]
            for item in app.get('pending',[]):
                proc=item['application'];count=item.get('connection_count',1)
                requests.append((str(proc['executable'])+' · '+str(count)+' bağlantı → '+item['destination'],item['id']))
            update_choices(self.app_requests,requests)
            wg=result.get('wireguard') or {}
            keep_error=getattr(self,'_wg_error',False);self._wg_error=False
            update_choices(self.wg_profiles,[(item['name']+(' · etkin' if item.get('active') else '')+' · '+', '.join(item.get('endpoints',[])),item['name'])
                           for item in wg.get('profiles',[])])
            if not keep_error:self.wg_state.setText('WireGuard: '+('; '.join(item['name']+(' bağlı, UDP '+','.join(map(str,item.get('ports',[])))+' açık' if item.get('active') else ' bağlı değil')
                                  for item in wg.get('profiles',[])) or 'içe aktarılmış profil yok')+(' · NetworkManager okunamadı: '+wg['error'] if wg.get('error') else ''))
            vpn=result.get('vpn_proxy') or {}
            update_choices(self.vpn_targets,[(item['name']+' · '+item['kind'],item['id'])
                           for item in vpn.get('items',[]) if item.get('blockable')])
            rules=[]
            for scope,collection in (('session','rules'),('application','application_rules')):
                for key,rule in app.get(collection,{}).items():
                    rules.append((key[:16]+' · '+scope+' · '+rule,{'key':key,'scope':scope}))
            update_choices(self.app_rules,rules)
            summary=result.get('health_summary') or {}
            self.integrity_label.setText('Dosyalar: '+str(summary.get('files','Durum alınamıyor'))+' · Yapılandırma: '+str(summary.get('configuration','Durum alınamıyor'))+' · Koruma: '+str(summary.get('protection','Durum alınamıyor'))+'\nKontrol zamanı: '+timestamp(summary.get('checked_at'))+'\n'+str(summary.get('message') or summary.get('host_scope') or ''))
            enabled = (result.get('policy') or {}).get('network_enabled')
            self.status.setText('Otomatik ağ aksiyonu: ' + ('Açık' if enabled is True else 'Kapalı' if enabled is False else 'Veri alınamadı')
                + ' · Aksiyonlar: ' + decision_text(result.get('verification'))
                + '\nİzinli IP: ' + (', '.join(result.get('allow_ips') or []) or 'Liste boş')
                + '\nYerel ağ: ' + ('Kapalı' if result.get('lan', {}).get('enabled') else 'Açık')
                + ' · Subnet 10 farklı IP: ' + ('Açık' if result.get('subnet', {}).get('enabled') else 'Kapalı')
                + '\nDNS filtresi: ' + ('Açık' if result.get('dns', {}).get('enabled') else 'Kapalı')
                + ' · HaGeZi Ultimate: ' + label(result.get('hagezi', {}).get('count')) + ' alan adı'
                + otx_dns_text(result.get('otx_dns')))
            command = app.get('last_command') or {}
            if command.get('id') and command.get('id') == getattr(self, '_app_command_id', None):
                state = command.get('status')
                self.status.setText(self.status.text()+'\nİzin komutu: '+str(state)
                    +(' · '+str(command['error']) if command.get('error') else ''))
                if state in ('APPLIED', 'FAILED'):
                    self._app_command_id = None
        elif method == 'wireguard':
            done={'import':'WireGuard profili içe aktarıldı: '+str(result.get('name'))+'. Listeden seçip Bağlan’a basın.',
                  'up':'WireGuard bağlandı; UDP '+', '.join(map(str,result.get('ports',[])))+' açıldı.',
                  'down':'WireGuard bağlantısı kesildi; port kapatıldı.','remove':'WireGuard profili silindi.'}
            notes=' '.join(result.get('notes') or [])
            self.status.setText(done.get(getattr(self,'_wg_action',''),'WireGuard işlemi tamamlandı.')+(' '+notes if notes else ''))
            self.wg_name.clear()
            self._send('status',{})
        elif method == 'login':
            self.status.setText('Yönetim oturumu açıldı.' if self.token else 'Giriş doğrulanamadı.')
        elif method == 'logout':
            self.status.setText('Yönetim oturumu kapatıldı.')
        elif method in ('custom_list_update','custom_list_remove','custom_lists_status'):
            info=result.get('custom_lists') or {}
            lines=[str(item.get('url'))+' · '+str(item.get('count'))+' alan adı' for item in info.get('sources',[])]
            active=result.get('active',info.get('enabled') and info.get('dns_filter_enabled'))
            self.custom_list_status.setText(('DNS filtresine uygulandı.' if active else 'Kaydedildi; DNS filtresi aktif değil.')+'\n'+'\n'.join(lines))
            self.status.setText('Ek liste işlemi tamamlandı.')
        elif method == 'modem_inventory':
            import json
            data=result.get('modem_inventory') or {}
            self._modem_fingerprint=data.get('route_fingerprint')
            self.modem_confirm.setChecked(False)
            self.modem_choices.clear()
            for item in data.get('candidates',[]):
                self.modem_choices.addItem(f"Tablo {item['table']} · {item['interface']} · {item['gateway']} · MAC {item['gateway_mac']}",item['id'])
            self.modem_tables.setPlainText(detail_lines({'tables':data.get('tables',[]),'routes':data.get('routes',[]),'rules':data.get('rules',[])}))
            reasons='\n'.join(f"{r.get('dev')} · {r.get('gateway') or 'ağ geçidi yok'}: {r.get('reason')}" for r in data.get('rejected',[]))
            self.status.setText('Modem otomatik seçilmedi. Kendi cihazınızı doğrulayıp onaylayın.' if data.get('candidates') else
                                ('Modem bulunamadı. Sebebi:\n'+reasons if reasons else 'Modem bulunamadı: bu bilgisayarda varsayılan rota yok (internet bağlantısı kurulmamış).'))
        elif method == 'modem_manual':
            self.modem_confirm.setChecked(False)
            seen=result.get('observed_mac')
            note=('' if not seen else (' Ağda görülen MAC ile aynı.' if result.get('matches_observed')
                  else f' DİKKAT: ağda şu an bu adresten cevap veren MAC {seen}; yazdığınızla farklı.'))
            self.status.setText('Elle yazdığınız modem MAC adresi referans olarak kaydedildi.'+note)
        elif method == 'modem_approve':
            self.modem_confirm.setChecked(False)
            self.status.setText('Tek modem referansı kaydedildi. Komşu/rota/firewall tablosu değiştirilmedi.')
        elif method == 'application_control':
            command = result.get('application_control') or result
            self._app_command_id = command.get('command_id')
            self.status.setText('İstek alındı; uygulanma sonucu bekleniyor. · '+str(self._app_command_id)
                if command.get('status') == 'REQUESTED' else str(command))
        elif method in ('boot_check', 'systemd_security', 'device_inventory'):
            self.status.setText('Kontrol başlatıldı; henüz başarılı sonuç yok. · '+str(result.get('command_id') or '')[:12])
            self.verification_job_label.setText(job_text(result))
        elif method == 'egress_profile':
            self._egress_loaded=False
            self._show_egress(result.get('profile'))
            self.status.setText('İnternet trafiği profili uygulandı ve güvenlik duvarında doğrulandı.')
        elif method == 'service':
            self.status.setText(('İşlem tamamlandı.' if result.get('ok') else 'Servis işlemi başarısız.') + '\n' + str(result.get('output') or ''))
        else:
            self.status.setText('İşlem tamamlandı.' if result.get('ok') else 'Sonuç: ' + str(result.get('status') or result))
        self._set_enabled()
        if method != 'status' and self.token and not result.get('error'):
            self._send('status', {})

    def _show_egress(self, profile):
        if not profile:
            self.egress_state.setText('Etkin profil: durum alınamadı');return
        ports=profile.get('ports') or {}
        self.egress_state.setText('Etkin profil — dışarıya açık portlar: TCP '+', '.join(map(str,ports.get('tcp',[])))
            +' · UDP '+', '.join(map(str,ports.get('udp',[])))+'\n'+str(profile.get('incoming','')))
        if self._egress_loaded:
            return
        selection=profile.get('selection') or {}
        for key,box in self.egress_addons.items():
            box.setChecked(key in selection.get('addons',[]))
        custom=selection.get('custom') or {}
        self.egress_tcp.setText(', '.join(map(str,custom.get('tcp',[]))))
        self.egress_udp.setText(', '.join(map(str,custom.get('udp',[]))))
        self._egress_loaded=True

    def refresh(self):
        if self.token and not self._busy:
            self._send('status', {})
