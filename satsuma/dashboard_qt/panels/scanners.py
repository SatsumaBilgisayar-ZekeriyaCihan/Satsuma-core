"""Local scanner status and results; device discovery is a separate view."""
from ._module import ReadOnlyModulePanel, QPushButton, QHBoxLayout, QLabel
from . import register
from ...status_view import label, timestamp


def operator_request(panel, method, params):
    """Through the panel's one administrator lock (2.2.47); the page refreshes when the answer comes."""
    from ..links import run
    if not run(panel, method, params, then=lambda *args: panel.refresh()):
        panel.status.setText('Bu işlem için Satsuma panelinin ana penceresi gerekli.')


ENGINE_NAMES={'clamav':'ClamAV · virüs ve zararlı yazılım','rkhunter':'rkhunter · rootkit denetimi','chkrootkit':'chkrootkit · rootkit denetimi'}
TOOLS=(('Tüm motorlar',''),('ClamAV','clamav'),('rkhunter','rkhunter'),('chkrootkit','chkrootkit'),('Gizli süreç (unhide)','unhide'))


def engine_text(name, engine):
    """Card text for one engine: installed, last result, what ClamAV scanned (2.2.47)."""
    from ...scan_view import summary_of, problem_text, files_text
    last=engine.get('last_result') or {}
    if engine.get('installed') is False:
        return 'Kurulu değil.'+(' sudo rpm-ostree install '+name if name!='clamav' else ' sudo rpm-ostree install clamav clamd clamav-update')
    if not last:
        return ('Kurulu' if engine.get('installed') else 'Durum alınamadı')+' · henüz tarama yok'
    lines=[label(last.get('status'))+' · '+timestamp(last.get('completed_at') or last.get('timestamp'))]
    summary=summary_of(last)
    if name=='clamav':
        if 'scanned_files' in summary:
            lines.append(f"Taranan: {summary['scanned_files']:,} dosya".replace(',','.')+(' · '+summary['data_scanned'] if summary.get('data_scanned') else '')
                         +(' · '+summary['duration'].split(' (')[0] if summary.get('duration') else ''))
        found=files_text(last)
        lines.append(('Bulunan: '+str(len(found))+' dosya') if found else ('Zararlı dosya bulunmadı' if last.get('status')=='COMPLETED' else 'Bulgu: '+str(last.get('findings',0))))
    else:
        lines.append('Uyarı: '+str(last.get('findings',0)))
    problem=problem_text(last)
    if problem!='—':lines.append(problem)
    return '\n'.join(lines)


CLOSED_NAMES={'thread':'iş parçacığı','transient':'artık yok','visible':'artık görünür','terminated':'sonlandırıldı'}


def hidden_text(hidden):
    """Open and closed hidden-process findings in one or two lines."""
    if not isinstance(hidden,dict) or ('open' not in hidden and 'closed' not in hidden):
        return 'Veri alınamadı'
    open_=hidden.get('open') or []
    lines=[f'Açık: {len(open_)} gizli süreç' if open_ else 'Açık gizli süreç bulgusu yok']
    closed=hidden.get('closed') or {}
    if closed:
        lines.append('Kapatılan: '+', '.join(f'{n} {CLOSED_NAMES.get(k,k)}' for k,n in sorted(closed.items(),key=lambda x:-x[1])))
    return '\n'.join(lines)


@register
class ScannersPanel(ReadOnlyModulePanel):
    PANEL_ID='scanners'
    PANEL_TITLE='Antivirüs taramaları'
    PANEL_GROUP='system'
    PANEL_ORDER=14
    METHOD='security_scanners'
    KEY='items'
    PANEL_SUBTITLE='ClamAV ile virüs taraması, rkhunter ve chkrootkit ile rootkit denetimi; bulunan dosyalar ve karantina.'
    COLUMNS=(('Zaman','timestamp'),('Motor','tool'),('Sonuç','_result'),('Taranan','_scanned'),('Bulgu','findings'),('Not','_problem'))

    def _build(self):
        from ..qt import QFrame, QVBoxLayout, QWidget, QComboBox, QCheckBox
        super()._build()
        cards=QWidget();row=QHBoxLayout(cards);row.setContentsMargins(0,0,0,0);row.setSpacing(12)
        self.cards={}
        for name in ('clamav','rkhunter','chkrootkit'):
            card=QFrame();card.setObjectName('summaryCard');box=QVBoxLayout(card);box.setContentsMargins(16,12,16,12);box.setSpacing(4)
            title=QLabel(ENGINE_NAMES[name]);title.setObjectName('fieldLabel');box.addWidget(title)
            text=QLabel('Veri bekleniyor');text.setWordWrap(True);text.setObjectName('body');box.addWidget(text);box.addStretch()
            self.cards[name]=text;row.addWidget(card,2 if name=='clamav' else 1)
        # 2.2.48: hidden processes (unhide) with their own actions.
        card=QFrame();card.setObjectName('summaryCard');box=QVBoxLayout(card);box.setContentsMargins(16,12,16,12);box.setSpacing(4)
        title=QLabel('unhide · gizli süreçler');title.setObjectName('fieldLabel');box.addWidget(title)
        self.hidden_text=QLabel('Veri bekleniyor');self.hidden_text.setWordWrap(True);self.hidden_text.setObjectName('body');box.addWidget(self.hidden_text)
        buttons=QHBoxLayout();buttons.setSpacing(6)
        self.hidden_end=QPushButton('Sonlandır…');self.hidden_end.setObjectName('quiet');self.hidden_end.clicked.connect(self.end_hidden)
        recheck=QPushButton('Yeniden doğrula');recheck.setObjectName('quiet')
        recheck.clicked.connect(lambda:operator_request(self,'unhide_recheck',{}))
        buttons.addWidget(recheck);buttons.addWidget(self.hidden_end);buttons.addStretch();box.addLayout(buttons);box.addStretch()
        row.addWidget(card,1)
        self._layout.insertWidget(2,cards)
        self.engines=QLabel('');self.engines.setWordWrap(True);self.engines.setObjectName('secondary')
        self._layout.insertWidget(3,self.engines)
        actions=QHBoxLayout();actions.setSpacing(8)
        scan=QPushButton('Taramayı başlat');scan.setObjectName('primary')
        scan.clicked.connect(lambda:operator_request(self,'security_scan',{}))
        actions.addWidget(scan)
        actions.addStretch()
        caption=QLabel('Göster');caption.setObjectName('secondary');actions.addWidget(caption)
        self.tool=QComboBox()
        for text,value in TOOLS:self.tool.addItem(text,value)
        self.tool.currentIndexChanged.connect(self._filter_changed)
        actions.addWidget(self.tool)
        tools=QHBoxLayout();tools.setSpacing(6)
        for text,handler in (('Seçili bulguyu karantinaya al',self.quarantine),('Karantinadan geri koy',self.restore),
                             ('Program denetimi önerileri',self.quarantine_proposal),('SSH anahtarları',self.ssh_decision),
                             ('SSH sunucusunu kapat',self.ssh_server_off)):
            button=QPushButton(text);button.setObjectName('quiet');button.clicked.connect(handler);tools.addWidget(button)
        tools.addStretch()
        self.manual_after_scan=QCheckBox('Bulunan dosya için karantina öner')
        self.manual_after_scan.setToolTip('Tarama bitince doğrulanabilir bir ClamAV bulgusu varsa karantinayı önerir; onaysız hiçbir dosya taşınmaz.')
        self.manual_after_scan.toggled.connect(self._toggle_manual_after_scan)
        actions.insertWidget(1,self.manual_after_scan)
        holder=QWidget();box=QVBoxLayout(holder);box.setContentsMargins(0,0,0,0);box.setSpacing(4)
        box.addLayout(actions);box.addLayout(tools)
        self._layout.insertWidget(4,holder)
        self._last_manual_prompt_scan=None
        self.table.setMinimumHeight(220)

    def _filter_changed(self,*args):
        self._last_render=None
        self.refresh()

    def _rows_from(self, data):
        from ...scan_view import scanned_text, problem_text
        rows=[]
        wanted=self.tool.currentData() if hasattr(self,'tool') else ''
        for item in super()._rows_from(data):
            if not isinstance(item,dict) or (wanted and item.get('tool')!=wanted):continue
            rows.append({**item,'_result':label(item.get('status')),'_scanned':scanned_text(item),'_problem':problem_text(item)})
        return rows

    def _show_details(self):
        super()._show_details()
        import html
        from ...scan_view import files_text, summary_of
        row=self.table.currentRow()
        if not 0<=row<len(self._rows):return
        item=self._rows[row];extra=[]
        summary=summary_of(item)
        for key,caption in (('scanned_directories','Taranan klasör'),('data_scanned','Taranan veri'),('duration','Süre')):
            if summary.get(key) is not None:extra.append((caption,str(summary[key])))
        found=files_text(item)
        if found:extra.append(('Bulunan dosyalar','\n'.join(found)))
        hidden=[h for h in item.get('hidden') or [] if isinstance(h,dict)][:20]
        if hidden:
            extra.append(('Bulunanlar (tarama anında)','\n'.join(
                f"{h.get('kind')} · {h.get('pid') or str(h.get('proto'))+'/'+str(h.get('port'))} · {h.get('executable') or h.get('command') or ''}"
                for h in hidden)))
        recheck=item.get('recheck') or {}
        if recheck.get('dismissed'):
            extra.append(('Yeniden doğrulamada kapatılan',', '.join(f'{n} {CLOSED_NAMES.get(k,k)}' for k,n in recheck['dismissed'].items())))
        lines=[str(x) for x in (item.get('finding_lines') or [])][:12]
        if lines:extra.append(('Uyarı satırları','\n'.join(lines)))
        if extra:
            self.detail_view.setText(self.detail_view.text()+''.join(
                '<p style="margin:0 0 8px 0"><span style="color:#8a8a8a;font-size:11px">%s</span><br>%s</p>'
                %(html.escape(c),html.escape(v).replace('\n','<br>')) for c,v in extra))

    def _toggle_manual_after_scan(self, enabled):
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

    def end_hidden(self):
        """Pick one open hidden process, confirm, and let the operator end it (2.2.48)."""
        data=self._last_render[1] if self._last_render else {}
        found=[h for h in (data.get('hidden') or {}).get('open') or [] if type(h.get('pid')) is int]
        if not found:
            self.status.setText('Açık gizli süreç bulgusu yok.');return
        try:from PyQt6.QtWidgets import QInputDialog,QMessageBox
        except ImportError:from PyQt5.QtWidgets import QInputDialog,QMessageBox
        labels=[f"PID {h['pid']} · {h.get('executable') or h.get('cmdline') or 'program bilinmiyor'}" for h in found]
        selection,ok=QInputDialog.getItem(self,'Gizli süreç','Sonlandırılacak süreç:',labels,0,False)
        if not ok:return
        chosen=found[labels.index(selection)]
        yes=QMessageBox.StandardButton.Yes if hasattr(QMessageBox,'StandardButton') else QMessageBox.Yes
        text=(f"PID {chosen['pid']} sonlandırılsın mı?\n\nSatsuma önce yeniden doğrular: süreç hâlâ gizliyse önce kapanması "
              'istenir (SIGTERM), kapanmazsa zorla sonlandırılır (SIGKILL). Artık gizli değilse ya da bir programın iş '
              'parçacığıysa hiçbir şey sonlandırılmaz, bulgu kapatılır.')
        if QMessageBox.question(self,'Gizli süreci sonlandır',text)!=yes:return
        operator_request(self,'unhide_terminate',{'pid':chosen['pid'],'confirmed':True})

    def refresh(self,*args):
        super().refresh(*args)
        self._offer_manual_quarantine()
        hidden=(self._last_render[1] if self._last_render else {}).get('hidden') or {}
        self.hidden_text.setText(hidden_text(hidden))
        self.hidden_end.setEnabled(bool(hidden.get('open')))
        data=self._last_render[1] if self._last_render else {}
        engines=data.get('engines') or {}
        for name,widget in self.cards.items():
            widget.setText(engine_text(name,engines.get(name) or {}) if engines else 'Veri alınamadı')
        lines=[]
        if data.get('quarantine'):
            lines.append(f"Karantinada {len(data['quarantine'])} dosya var.")
        if data.get('ssh_pending'):
            lines.append(f"SSH: bilginiz dahilinde olup olmadığı sorulan {len(data['ssh_pending'])} anahtar var.")
        if data.get('sshd_open'):
            lines.append('SSH sunucusu açık: bu bilgisayara dışarıdan bağlanılabilir.')
        mitm=data.get('mitm_watch') or {}
        if mitm.get('updated_at'):
            counts=mitm.get('counts') or {}
            found=', '.join(f"{name} {counts[key]}" for key,name in (('critical','kritik'),('high','yüksek'),('medium','orta')) if counts.get(key))
            lines.append('Ortadaki adam izleyicisi · '+timestamp(mitm['updated_at'])+' · '+(('Bulgu: '+found) if found else 'Sorun yok'))
        lines.append(data.get('scope') or 'Kapsam bilgisi bekleniyor')
        if data.get('error'):lines.append('Sonuçlar okunamadı: '+data['error'])
        self.engines.setText(' · '.join(lines))


@register
class NetworkDevicesPanel(ReadOnlyModulePanel):
    PANEL_ID='network_devices'
    PANEL_TITLE='Ağdaki cihazlar'
    PANEL_GROUP='system'
    PANEL_ORDER=14
    METHOD='network_defense'
    KEY='devices'
    PANEL_SUBTITLE='Ağda görülen cihazlar; yeni cihazı inceledikten sonra engelleyin ya da izin verin.'
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
