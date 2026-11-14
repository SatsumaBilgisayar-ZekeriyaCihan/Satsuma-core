"""Desktop overview using reader evidence and visible detail failures.

Okuyucu kanıtını ve ayrıntı hatalarını birlikte gösteren genel bakış.
"""
from copy import deepcopy
try:
    from PyQt6.QtWidgets import QLabel,QGridLayout,QTableWidget,QTableWidgetItem,QAbstractItemView,QPushButton,QHBoxLayout,QVBoxLayout,QFrame,QScrollArea,QWidget,QHeaderView
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QColor
except ImportError:
    from PyQt5.QtWidgets import QLabel,QGridLayout,QTableWidget,QTableWidgetItem,QAbstractItemView,QPushButton,QHBoxLayout,QVBoxLayout,QFrame,QScrollArea,QWidget,QHeaderView
    from PyQt5.QtCore import Qt
    from PyQt5.QtGui import QColor
from .base import BasePanel
from . import register
from ..security_widgets import ShieldArtwork,SecurityCard
from ..style.theme import Colors
from ...status_view import label,timestamp
from ...presentation import fields,epoch


def presentation_health(data, errors):
    if not (errors or {}).get('integrity'):
        return data
    result = deepcopy(data)
    result['health_summary'] = {**(result.get('health_summary') or {}),
        'files':'Durum alınamıyor', 'overall':'Durum alınamıyor',
        'message':str(errors['integrity'])}
    return result


def protection_view(data):
    """Visual state never upgrades missing or contradictory health evidence."""
    summary=data.get('health_summary') or {}
    critical=(data.get('system') or {}).get('critical_integrity') or {}
    overall=summary.get('overall')
    if critical.get('status')=='CRITICAL' or overall=='Kritik':
        return ('critical','KRİTİK UYARI','Güvenlik kontrolü\nmüdahale gerektiriyor','Dosya bütünlüğü veya koruma denetimi kritik bir durum bildirdi. Ayrıntıları inceleyin.')
    if summary.get('inconsistent') or overall=='Sorun var':
        return ('warning','KONTROL GEREKLİ','Güvenliğinizi\ngözden geçirelim',summary.get('message') or 'Bazı güvenlik kontrolleri sorun bildirdi. Etkilenen bileşenleri ve önerilen adımları inceleyin.')
    if overall=='Sağlıklı' and all(summary.get(k)=='Sağlıklı' for k in ('files','configuration','protection')):
        return ('healthy','KONTROLLER BAŞARILI','Koruma kontrolleri\nbaşarıyla tamamlandı','Son dosya, yapılandırma ve koruma denetimleri başarılı. Kontrol kapsamını ve zamanını aşağıdan inceleyebilirsiniz.')
    if summary.get('files')=='Sağlıklı' and summary.get('configuration')=='Sağlıklı':
        state=summary.get('protection_status') or 'NOT_RUN'
        return ('unknown','OTOMATİK KONTROL','Dosyalar doğrulandı;\nkoruma kontrolü bekleniyor',
                'Dosya ve yapılandırma kontrolü başarılı. İşlevsel koruma kontrolü otomatik yürütülür. Durum: '+label(state)+'. Sonuç Sistem Sağlığı bölümünde gösterilir.')
    return ('unknown','DURUM BEKLENİYOR','Koruma durumunuz\ndoğrulanıyor','Güvenlik servislerinden güncel veri bekleniyor. Durum alındığında koruma bilgileri burada görünecek.')


@register
class OverviewPanel(BasePanel):
    PANEL_ID='overview';PANEL_TITLE='Güvenlik merkezi';PANEL_ORDER=1;REFRESH_MS=5000
    def _build(self):
        self._layout.setContentsMargins(0,0,0,0)
        scroll=QScrollArea();scroll.setWidgetResizable(True);scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff if hasattr(Qt,'ScrollBarPolicy') else Qt.ScrollBarAlwaysOff)
        body=QWidget();body.setObjectName('transparent');content=QVBoxLayout(body);content.setContentsMargins(30,24,30,24);content.setSpacing(16)
        scroll.setWidget(body);self._layout.addWidget(scroll);self.scroll=scroll
        heading=QHBoxLayout();text=QVBoxLayout();text.setSpacing(5);eyebrow=QLabel('KORUMA MERKEZİ');eyebrow.setObjectName('eyebrow');text.addWidget(eyebrow)
        title=QLabel('Cihazınızın güvenlik panoraması.');title.setObjectName('pageTitle');text.addWidget(title);heading.addLayout(text);heading.addStretch()
        self.live=QLabel('YEREL CİHAZ');self.live.setObjectName('eyebrow');heading.addWidget(self.live);content.addLayout(heading)
        hero=QFrame();hero.setObjectName('securityHero');hero_layout=QHBoxLayout(hero);hero_layout.setContentsMargins(20,20,26,20);hero_layout.setSpacing(18)
        self.art=ShieldArtwork();hero_layout.addWidget(self.art)
        hero_text=QVBoxLayout();hero_text.setSpacing(10)
        self.badge=QLabel('DURUM BEKLENİYOR');self.badge.setStyleSheet('color:'+Colors.TEXT_MUTED+';font-size:10px;font-weight:700;letter-spacing:1.2px;');hero_text.addWidget(self.badge)
        self.status=QLabel('Koruma durumunuz\ndoğrulanıyor');self.status.setWordWrap(True);self.status.setStyleSheet('font-size:29px;font-weight:700;');hero_text.addWidget(self.status)
        self.explanation=QLabel('Güvenlik servislerinden güncel veri bekleniyor.');self.explanation.setObjectName('secondary');self.explanation.setWordWrap(True);hero_text.addWidget(self.explanation)
        buttons=QHBoxLayout();self.inspect_button=QPushButton('Koruma durumunu incele');self.inspect_button.setObjectName('primary');self.inspect_button.clicked.connect(lambda:self._open('system_health'));buttons.addWidget(self.inspect_button)
        apps=QPushButton('Uygulama izinleri');apps.clicked.connect(self._open_apps);buttons.addWidget(apps);buttons.addStretch();hero_text.addLayout(buttons)
        hero_layout.addLayout(hero_text,1);content.addWidget(hero)
        grid=QGridLayout();grid.setSpacing(14)
        self.security_cards={}
        specs=(('files','Dosya bütünlüğü','Uygulama dosyalarının güvenilir referansla doğrulanması.','shield','Doğrulamayı incele','integrity'),
               ('network','Ağ koruması','Trafik denetimi, bağlantı kararları ve IP engelleri.','network','Ağ korumasını incele','network_response'),
               ('intel','Tehdit istihbaratı','OTX kaynakları ve kaydedilmiş tehdit eşleşmeleri.','activity','İstihbaratı incele','otx'))
        for i,(key,title,desc,symbol,button,target) in enumerate(specs):
            card=SecurityCard(title,desc,symbol,button,lambda checked=False,p=target:self._open(p));self.security_cards[key]=card;grid.addWidget(card,0,i);grid.setColumnStretch(i,1)
        content.addLayout(grid)
        metrics=QFrame();metrics.setObjectName('securityCard');metrics_layout=QHBoxLayout(metrics);metrics_layout.setContentsMargins(22,18,22,18);metrics_layout.setSpacing(18)
        self.cards={}
        for name in ('Son 24 saat bulgu','Aktif kurallar','Yapılandırma'):
            col=QVBoxLayout();caption=QLabel(name);caption.setObjectName('secondary');col.addWidget(caption)
            value=QLabel('—');value.setStyleSheet('font-size:25px;font-weight:700;');col.addWidget(value);col.addStretch();metrics_layout.addLayout(col,1);self.cards[name]=value
        content.addWidget(metrics)
        activity=QFrame();activity.setObjectName('securityCard');activity_layout=QVBoxLayout(activity);activity_layout.setContentsMargins(20,17,20,17);activity_layout.setSpacing(14)
        row=QHBoxLayout();recent=QLabel('Son güvenlik etkinlikleri');recent.setStyleSheet('font-size:15px;font-weight:700;');row.addWidget(recent);row.addStretch();all_events=QPushButton('Tüm etkinlikler  →');all_events.setObjectName('quiet');all_events.clicked.connect(lambda:self._open('events'));row.addWidget(all_events);activity_layout.addLayout(row)
        self.table=QTableWidget(0,3);self.table.setHorizontalHeaderLabels(['Zaman','Bulgu','Önem']);self.table.verticalHeader().hide();self.table.setShowGrid(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers if hasattr(QAbstractItemView,'EditTrigger') else QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows if hasattr(QAbstractItemView,'SelectionBehavior') else QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(False)
        stretch=QHeaderView.ResizeMode.Stretch if hasattr(QHeaderView,'ResizeMode') else QHeaderView.Stretch
        self.table.horizontalHeader().setSectionResizeMode(1,stretch);self.table.setColumnWidth(0,170);self.table.setColumnWidth(2,100)
        self.table.setFixedHeight(164);self.table.verticalHeader().setDefaultSectionSize(42);activity_layout.addWidget(self.table);self.table.hide()
        self.empty=QLabel('Etkinlik verisi bekleniyor');self.empty.setStyleSheet('color:'+Colors.TEXT_SECONDARY+';font-size:13px;padding:16px 0;');self.empty.setWordWrap(True);activity_layout.addWidget(self.empty)
        content.addWidget(activity)
        self.sensors=QLabel('Son kontrol: Veri bekleniyor');self.sensors.setObjectName('secondary');self.sensors.setWordWrap(True);content.addWidget(self.sensors)
        content.addStretch();self._last=None;self._activity_key=None;self._activity_rows=[]

    def _open(self,panel_id):self.window().nav.select(panel_id)
    def _open_apps(self):
        self._open('admin');panel=self.window().stack.currentWidget()
        if hasattr(panel,'sections'):panel.sections.setCurrentRow(1)

    def refresh(self):
        try:data=presentation_health(self.backend.overview() or {}, getattr(self.backend, 'presentation_errors', {}))
        except Exception as exc:
            data={};self.explanation.setToolTip(str(exc))
        if data==self._last:return
        self._last=deepcopy(data)
        tone,badge,title,description=protection_view(data);self.art.set_tone(tone);self.status.setText(title);self.explanation.setText(description)
        color={'healthy':Colors.STATUS_OK,'warning':Colors.STATUS_WARN,'critical':Colors.STATUS_CRIT}.get(tone,Colors.TEXT_MUTED)
        self.badge.setText(badge);self.badge.setStyleSheet('color:'+color+';font-size:10px;font-weight:700;letter-spacing:1.2px;')
        summary=data.get('health_summary') or {};protection=data.get('protection') or {}
        for key,field in (('files','files'),('network','protection')):
            value=summary.get(field)
            state='Kontrol başarılı' if value=='Sağlıklı' else 'Kontrol gerekli' if value=='Sorun var' else 'Doğrulanmadı'
            card_tone='healthy' if value=='Sağlıklı' else 'warning' if value=='Sorun var' else 'unknown'
            detail=('Son kontrol: '+timestamp(summary.get('checked_at' if key=='files' else 'protection_checked_at')))
            self.security_cards[key].set_state(state,card_tone,detail)
        otx=protection.get('otx_state');otx_labels={'ACTIVE':'Kaynak etkin','DISABLED':'Kapalı','KEY_MISSING':'Anahtar gerekli','ERROR':'Bağlantı sorunu','CONFIGURED':'Yapılandırıldı','CONNECTING':'Bağlanıyor'}
        self.security_cards['intel'].set_state(otx_labels.get(otx,'Doğrulanmadı'),'warning' if otx=='ERROR' else 'unknown','Eşleşme ve müdahale kayıtlarını ayrı inceleyin.')
        findings=data.get('findings') or {};count=findings.get('last_24h') if findings.get('data_state')=='OK' else None
        self.cards['Son 24 saat bulgu'].setText(str(count) if count is not None else '—')
        rules=protection.get('active_rule_count');self.cards['Aktif kurallar'].setText(str(rules) if rules is not None else '—')
        self.cards['Yapılandırma'].setText('Doğrulandı' if summary.get('configuration')=='Sağlıklı' else 'Kontrol gerekli' if summary.get('configuration')=='Sorun var' else 'Bekleniyor')
        rows=data.get('last_findings') or []
        self._render_activity(rows)
        self.empty.setVisible(not rows);self.table.setVisible(bool(rows))
        self.empty.setText('Bu kayıt aralığında bulgu bulunmuyor.' if findings.get('data_state')=='OK' else 'Etkinlik verisi henüz alınamadı. Bileşenlerin durumunu inceleyebilirsiniz.')
        self.sensors.setText('Son koruma kontrolü: '+timestamp(summary.get('protection_checked_at'))+'\n'+str(summary.get('host_scope') or 'Genel sistem temizliği bu kontrol kapsamında doğrulanmadı.'))

    def _render_activity(self,rows):
        if rows==self._activity_rows:return
        old=self.table.currentRow();selected=self._activity_rows[old].get('finding_id') if 0<=old<len(self._activity_rows) else None
        scroll=self.table.verticalScrollBar().value();self.table.setUpdatesEnabled(False)
        try:
            self.table.clearSelection();self.table.setCurrentCell(-1,-1);self.table.setRowCount(len(rows))
            for r,item in enumerate(rows):
                view=fields(item)
                values=(view['time_label'],item.get('title') or 'Açıklama kayıtta belirtilmemiş',view['severity_label'])
                for c,value in enumerate(values):
                    cell=QTableWidgetItem(str(value));self.table.setItem(r,c,cell)
                    if c==2:cell.setForeground(QColor({'critical':Colors.STATUS_CRIT,'high':Colors.STATUS_WARN}.get(view['severity'],Colors.TEXT_MUTED)))
                if selected and item.get('finding_id')==selected:self.table.selectRow(r)
            self.table.verticalScrollBar().setValue(scroll);self._activity_rows=deepcopy(rows)
        finally:self.table.setUpdatesEnabled(True)
