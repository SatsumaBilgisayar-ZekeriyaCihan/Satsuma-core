"""Local scanner status and results; device discovery is a separate view."""
from ._module import ReadOnlyModulePanel, QPushButton, QHBoxLayout, QLabel
from . import register
from ...status_view import label, timestamp


def operator_request(panel, method, params):
    window=panel.window()
    window.nav.select('admin')
    admin=window.stack.currentWidget()
    if not admin.token:
        admin.status.setText('Bu işlem için yönetici oturumu açın; ardından tekrar seçin.')
        return
    admin._send(method,params)


@register
class ScannersPanel(ReadOnlyModulePanel):
    PANEL_ID='scanners'
    PANEL_TITLE='ANTİVİRÜS VE ROOTKİT TARAMALARI'
    PANEL_GROUP='system'
    PANEL_ORDER=14
    METHOD='security_scanners'
    KEY='items'
    PANEL_SUBTITLE='ClamAV · rkhunter · chkrootkit — yerel tarama, bulgular ve eksik ön koşullar'
    COLUMNS=(('Zaman','timestamp'),('Motor','tool'),('Durum','status'),('Bulgu','findings'),('Hata','error'))

    def _build(self):
        super()._build()
        self.engines=QLabel('Motor durumları bekleniyor')
        self.engines.setWordWrap(True)
        self._layout.insertWidget(2,self.engines)
        button=QPushButton('Üç motorla yerel taramayı başlat')
        button.clicked.connect(lambda:operator_request(self,'security_scan',{}))
        self._layout.insertWidget(3,button)
        self.manual_after_scan=QPushButton('Tarama sonrası manuel karantina önerilerini göster: KAPALI')
        self.manual_after_scan.setCheckable(True)
        self.manual_after_scan.toggled.connect(self._toggle_manual_after_scan)
        self._layout.insertWidget(4,self.manual_after_scan)
        self._last_manual_prompt_scan=None
        quarantine=QPushButton('Seçili ClamAV bulgusundaki dosyayı karantinaya al')
        quarantine.clicked.connect(self.quarantine)
        self._layout.insertWidget(5,quarantine)
        propose=QPushButton('Program denetiminin önerdiği dosyayı karantinaya al (açılmazsa geri alınır)')
        propose.clicked.connect(self.quarantine_proposal)
        self._layout.insertWidget(6,propose)
        restore=QPushButton('Karantinadaki bir dosyayı geri koy')
        restore.clicked.connect(self.restore)
        self._layout.insertWidget(7,restore)
        ssh=QPushButton('Onay bekleyen SSH anahtarları: tanıyorum / karantinaya al')
        ssh.clicked.connect(self.ssh_decision)
        self._layout.insertWidget(8,ssh)
        sshd=QPushButton('SSH sunucusunu kapat (dışarıdan girişi durdurur)')
        sshd.clicked.connect(self.ssh_server_off)
        self._layout.insertWidget(9,sshd)

    def _toggle_manual_after_scan(self, enabled):
        state='AÇIK' if enabled else 'KAPALI'
        self.manual_after_scan.setText('Tarama sonrası manuel karantina önerilerini göster: '+state)
        if enabled:
            self._offer_manual_quarantine()

    def _offer_manual_quarantine(self):
        if not self.manual_after_scan.isChecked():
            return
        # Only a completed ClamAV result with identified files may prompt.
        candidates=[r for r in getattr(self,'_rows',[]) if
                    r.get('tool')=='clamav' and r.get('status')=='FINDINGS'
                    and any(f.get('sha256') for f in (r.get('files') or []))]
        if not candidates:
            return
        scan=candidates[0]
        scan_id=scan.get('_id')
        if scan_id is None or scan_id==self._last_manual_prompt_scan:
            return
        self._last_manual_prompt_scan=scan_id
        self.status.setText('ClamAV taramasında doğrulanabilir dosya bulgusu var. '
                            'Karantina için kaydı seçip manuel karantina düğmesini kullanın. '
                            'Onay olmadan hiçbir dosya taşınmaz.')

    def ssh_decision(self):
        data=self._last_render[1] if self._last_render else {}
        keys={}
        for item in data.get('ssh_pending') or []:
            if item.get('kind')=='authorized':
                text='[yetkili] '+str(item.get('file'))+' · '+str(item.get('fingerprint'))+' '+str(item.get('comment') or '')
            else:
                text='[özel] '+str(item.get('path'))+(' (parolasız)' if item.get('encrypted') is False else '')
            keys[text]=item
        if not keys:
            self.status.setText('Onay bekleyen SSH anahtarı yok.');return
        choice=self._choose('SSH anahtarı','Bu anahtar bilginiz dahilinde mi? Önce anahtarı seçin:',keys)
        if not choice:return
        decision=self._choose('SSH anahtarı',choice,{'Tanımıyorum: karantinaya al (geri alınabilir)':'quarantine',
                                                       'Tanıyorum: bir daha sorma':'known'})
        if not decision:return
        item=keys[choice]
        operator_request(self,'ssh_key_decision',{'id':item['id'],'file':item.get('file'),
                         'decision':'quarantine' if decision.startswith('Tanımıyorum') else 'known','confirmed':True})

    def ssh_server_off(self):
        data=self._last_render[1] if self._last_render else {}
        if data.get('sshd_open') is False:
            self.status.setText('SSH sunucusu zaten kapalı.');return
        if self._choose('SSH sunucusu','İşlem:',['SSH sunucusunu durdur ve açılışta başlatma']):
            operator_request(self,'ssh_server_off',{'confirmed':True})

    def _choose(self,title,label,options):
        try:from PyQt6.QtWidgets import QInputDialog,QMessageBox
        except ImportError:from PyQt5.QtWidgets import QInputDialog,QMessageBox
        selection,ok=QInputDialog.getItem(self,title,label,list(options),0,False)
        if not ok:return None
        yes=QMessageBox.StandardButton.Yes if hasattr(QMessageBox,'StandardButton') else QMessageBox.Yes
        return selection if QMessageBox.question(self,title,selection+'\nOnaylıyor musunuz?')==yes else None

    def quarantine_proposal(self):
        data=self._last_render[1] if self._last_render else {}
        proposals={p['path']+' · '+str(p.get('sha256'))[:16]:p for p in data.get('proposals') or []}
        if not proposals:
            self.status.setText('Program denetiminin karantina önerisi yok.');return
        choice=self._choose('Program karantinası','Karantinaya alınacak program (açılış tamamlanmazsa geri konur):',proposals)
        if choice:
            item=proposals[choice]
            operator_request(self,'quarantine_system_file',{'path':item['path'],'sha256':item['sha256'],'confirmed':True})

    def restore(self):
        data=self._last_render[1] if self._last_render else {}
        rows={str(r['path'])+' · '+r['quarantine_id']:r for r in data.get('quarantine') or []}
        if not rows:
            self.status.setText('Karantinada dosya yok.');return
        choice=self._choose('Karantinadan geri al','Geri konacak dosya:',rows)
        if choice:
            operator_request(self,'quarantine_restore',{'quarantine_id':rows[choice]['quarantine_id'],'confirmed':True})

    def quarantine(self):
        row=self.table.currentRow()
        if not 0<=row<len(self._rows):
            self.status.setText('Önce bir ClamAV tarama kaydı seçin.');return
        scan=dict(self._rows[row]);files=scan.get('files') or []
        valid=[(i,item) for i,item in enumerate(files) if item.get('sha256')]
        if scan.get('tool')!='clamav' or scan.get('status')!='FINDINGS' or not valid:
            self.status.setText('Dosya kimliği olan bir ClamAV bulgusu gerekli; rootkit uyarıları dosya silme yetkisi vermez.');return
        try:from PyQt6.QtWidgets import QInputDialog,QMessageBox
        except ImportError:from PyQt5.QtWidgets import QInputDialog,QMessageBox
        labels=[str(i+1)+': '+item['path']+' · '+item['sha256'] for i,item in valid]
        selection,ok=QInputDialog.getItem(self,'Dosya seçimi','Karantinaya alınacak dosya:',labels,0,False)
        if not ok:return
        index,item=valid[labels.index(selection)]
        yes=QMessageBox.StandardButton.Yes if hasattr(QMessageBox,'StandardButton') else QMessageBox.Yes
        if QMessageBox.question(self,'Dosya karantinası',item['path']+' özgün konumundan kaldırılıp korumalı alana taşınsın mı?')!=yes:return
        operator_request(self,'quarantine_scan_file',{'scan_id':scan['_id'],'file_index':index,'confirmed':True})

    def refresh(self,*args):
        super().refresh(*args)
        self._offer_manual_quarantine()
        data=self._last_render[1] if self._last_render else {}
        lines=[]
        for name in ('clamav','rkhunter','chkrootkit'):
            engine=(data.get('engines') or {}).get(name) or {}
            last=engine.get('last_result') or {}
            installed='Kurulu' if engine.get('installed') is True else 'Kurulu değil' if engine.get('installed') is False else 'Durum alınamadı'
            line=name+' · '+installed+' · Son sonuç: '+label(last.get('status'))+' · '+timestamp(last.get('completed_at'))
            if last.get('error'):line+='\n    Hata: '+str(last['error'])
            if last.get('fallback_from'):line+='\n    clamd cevap vermedi; tarama clamscan ile yapıldı.'
            quarantined=[q for q in last.get('quarantine') or [] if q.get('status')=='quarantined']
            failed=[q for q in last.get('quarantine') or [] if q.get('status')!='quarantined']
            if quarantined:line+=f'\n    Otomatik karantinaya alınan dosya: {len(quarantined)}'
            for q in failed:line+='\n    Karantinaya alınamadı: '+str(q.get('source'))+' · '+str(q.get('reason'))
            lines.append(line)
        if data.get('ssh_pending'):
            lines.append(f"SSH: bilginiz dahilinde olup olmadığı sorulan {len(data['ssh_pending'])} anahtar var.")
        if data.get('sshd_open'):
            lines.append('SSH sunucusu açık: bu bilgisayara dışarıdan bağlanılabilir.')
        mitm=data.get('mitm_watch') or {}
        if mitm.get('updated_at'):
            counts=mitm.get('counts') or {}
            found=', '.join(f"{name} {counts[key]}" for key,name in (('critical','kritik'),('high','yüksek'),('medium','orta')) if counts.get(key))
            lines.append('Ortadaki adam izleyicisi (DNS, rota, profil, çekirdek, uzak erişim) · '+timestamp(mitm['updated_at'])
                         +' · '+(('Bulgu: '+found) if found else 'Sorun yok')+' · DNS üst sunucusu: '+str(mitm.get('upstream') or 'yok'))
            kernel=mitm.get('kernel') or {}
            if kernel.get('restored'):lines.append(f"    Geri yazılan çekirdek ağ ayarı: {kernel['restored']}")
        lines.append(data.get('scope') or 'Kapsam bilgisi bekleniyor')
        if data.get('error'):lines.append('Sonuçlar okunamadı: '+data['error'])
        self.engines.setText('\n'.join(lines))


@register
class NetworkDevicesPanel(ReadOnlyModulePanel):
    PANEL_ID='network_devices'
    PANEL_TITLE='AĞ KEŞFİ VE CİHAZ İNCELEMESİ'
    PANEL_GROUP='system'
    PANEL_ORDER=14
    METHOD='network_defense'
    KEY='devices'
    PANEL_SUBTITLE='Yeni cihazlar · ajan gereksinimi · inceleme sonrası engelle veya izin ver'
    COLUMNS=(('IP','ip'),('MAC','mac'),('Arayüz','interface'),('Tarama','scan_status'),('Karar','decision'),('Açıklama','message'))

    def _build(self):
        super()._build()
        row=QHBoxLayout()
        for text,choice in (('Seçili cihazı engelle','block'),('Seçili cihaza izin ver','allow')):
            button=QPushButton(text)
            button.clicked.connect(lambda checked,c=choice:self.decide(c))
            row.addWidget(button)
        self._layout.addLayout(row)

    @staticmethod
    def _row_key(item):
        return ('device_id',item.get('device_id'))

    def decide(self,choice):
        row=self.table.currentRow()
        if not 0<=row<len(self._rows):
            self.status.setText('Önce bir cihaz seçin.')
            return
        device=dict(self._rows[row])
        if choice=='block':
            try:from PyQt6.QtWidgets import QMessageBox
            except ImportError:from PyQt5.QtWidgets import QMessageBox
            yes=QMessageBox.StandardButton.Yes if hasattr(QMessageBox,'StandardButton') else QMessageBox.Yes
            if QMessageBox.question(self,'Cihaz engeli',str(device.get('ip'))+' ile bu bilgisayarın bağlantısı engellensin mi?')!=yes:
                return
        operator_request(self,'device_decision',{'device_id':device['device_id'],'decision':choice})
