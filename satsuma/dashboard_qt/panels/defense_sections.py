"""Dedicated evidence views using the existing authenticated read-only reader.

The memory view shows partial comparisons and executable memory without a
verifiable file, which is observed but never stops a process.

Mevcut kimliği doğrulanmış salt okunur okuyucuyla ayrılmış kanıt görünümleri.
Bellek görünümü kısmi karşılaştırmaları ve doğrulanabilir dosyası olmayan
çalıştırılabilir belleği gösterir; ikincisi yalnızca gözlenir, işlem durdurmaz.
"""
from ._module import ReadOnlyModulePanel, QPlainTextEdit, QPushButton
from . import register
from ...status_view import timestamp, label
from ...memory_health_view import summary as memory_health_summary
import json
import time


def memory_status(health):
    count = health.get('inspected')
    stamp = health.get('updated_at')
    fresh = isinstance(stamp, (int, float)) and 0 <= time.time() - stamp <= 90
    validations = health.get('validation_counts')
    if not health:
        state = 'Doğrulama bekleniyor'
    elif not fresh:
        state = 'Durum bildirimi gecikti'
    elif not isinstance(count, int) or count == 0:
        state = 'Doğrulama yapılamadı'
    elif not isinstance(validations, dict):
        state = 'Eski tarayıcı: yalnızca üstveri; kod doğrulaması yok'
    elif validations.get('CODE_MISMATCH'):
        state = 'RAM kod farkı doğrulandı; müdahale sonucu aksiyon kayıtlarında'
    elif health.get('incomplete_validations'):
        state = 'Kod doğrulaması kısmen tamamlandı'
    else:
        state = 'İncelenen executable kodunda fark bulunmadı'
    text = (state + ' · Son tarama: ' + timestamp(stamp)
            + '\nİncelenen: ' + label(count) + ' · Erişilemeyen: '
            + label(health.get('unreadable')) + ' · Kaybolan süreç: ' + label(health.get('vanished')))
    if isinstance(validations, dict):
        text += ('\nKod eşleşen: ' + str(validations.get('CODE_MATCH', 0))
                 + ' · Kod farkı: ' + str(validations.get('CODE_MISMATCH', 0))
                 + ' · Bellek erişimi reddedilen: ' + str(validations.get('ACCESS_DENIED', 0))
                 + ' · Eksik doğrulama: ' + str(health.get('incomplete_validations', 0))
                 + '\nKapsam: ana executable kodu, süreç başına en fazla 1 MiB; tüm RAM taraması değildir.')
        if health.get('partial_matches'):
            text += '\nKısmi tarama: ' + str(health['partial_matches']) + ' süreçte kodun yalnızca ilk 1 MiB\'ı karşılaştırıldı.'
        totals = health.get('unverifiable_exec_totals') or {}
        count = sum(v for v in totals.values() if isinstance(v, int))
        if count:
            text += ('\nDoğrulanamayan çalıştırılabilir bellek: ' + str(health.get('unverifiable_exec_processes', 0))
                     + ' süreçte ' + str(count) + ' bölge (anonim ' + str(totals.get('anonymous_exec', 0))
                     + ', memfd ' + str(totals.get('memfd_exec', 0)) + ', silinmiş dosya '
                     + str(totals.get('deleted_exec', 0)) + '). Tarayıcı ve Java gibi programlar bunu meşru '
                     'olarak kullanır; gözlem amaçlıdır, durdurma yapmaz.')
    elif health:
        text += '\nKapsam bilgisi eksik; başarılı RAM kodu karşılaştırması kanıtı yok.'
    else:
        text += '\nBellek işçisi sağlık kaydı alınamadı; engel nedeni bu ekrandan belirlenemez.'
    extended=health.get('extended_scope') or {}
    totals=extended.get('totals') or {}
    if extended:
        text += '\nBellek worker: '+label(health.get('status'))+(' (durum eski)' if not fresh else '')
        text += '\nRAM okuması: '+('başarılı' if totals.get('valid_snapshot_read_bytes',0)>0 else 'geçerli okuma kanıtı yok')
        text += '\nGüvenilir referans doğrulaması: '+('karşılaştırma kanıtı mevcut; kapsamı inceleyin' if extended.get('trusted_reference_provider_configured') is True and totals.get('reference_verified_bytes',0)>0 else 'bekliyor; bağımsız güvenilir referans henüz doğrulanmadı')
        incomplete=extended.get('mapping_denominator_incomplete') is True
        percentage=extended.get('partial_observed_coverage_percent') if incomplete else extended.get('read_coverage_percent')
        scope_label='KISMİ GÖZLENEN KAPSAM · Payda eksik' if incomplete else 'İncelenen süreçlerin bilinen yürütülebilir kapsamı'
        text += ('\nBölge tarama motoru: '+str(extended.get('engine_state') or 'Bilinmiyor')
                 +' · Kapsam: '+str(extended.get('coverage') or 'Bilinmiyor')
                 +'\nGerçekten okunan: '+str(totals.get('regions_read',0))+' bölge / '+str(totals.get('bytes_read',0))+' bayt'
                 +' · Yalnız üstveri: '+str(totals.get('metadata_only_bytes',0))+' bayt'
                 +' · Erişim reddi: '+str(totals.get('access_denied_regions',0))
                 +' · Atlanan bölgeler: '+str(totals.get('skipped_regions',0))
                 +'\n'+scope_label+': '+(str(percentage)+'%' if percentage is not None else 'Belirlenemedi')+' (tüm RAM değildir)'
                 +'\nBütçe atlanan: '+str(totals.get('budget_skipped_bytes',0))+' bayt · Kimlik değişimi: '+str(totals.get('identity_changed_bytes',0))+' bayt · Eşleme değişimi: '+str(totals.get('mapping_changed_bytes',0))+' bayt'
                 +'\nGüvenilir referansla karşılaştırılan: '+str(totals.get('reference_verified_bytes',0))+' bayt'
                 +' · Ham bellek saklanmaz veya DeepSeek’e gönderilmez.'
                 +'\nDeepSeek: yalnız imzalı öneri · Müdahale sonucu: ayrı aksiyon kaydı gerekir.')
    return text


class DefensePanel(ReadOnlyModulePanel):
    METHOD='findings'
    KEY='items'
    PARAMS={'limit':2000}
    COLUMNS=(('Zaman','timestamp'),('Önem','severity'),('Sınıflandırma','classification'),('Kural','rule_id'),('Açıklama','title'),('PID','pid'))
    PREFIXES=()
    SOURCES=()
    def _rows_from(self,data):
        rows=super()._rows_from(data)
        return [r for r in rows if isinstance(r,dict) and (any(str(r.get('rule_id','')).startswith(p) for p in self.PREFIXES) or str(r.get('source','')).lower() in self.SOURCES)]


@register
class MemoryDefensePanel(DefensePanel):
    METHOD='memory_defense'
    PANEL_ID='memory_defense'
    PANEL_TITLE='Bellek savunması'
    PANEL_ICON='◈'
    PANEL_ORDER=13
    PANEL_GROUP='system'
    PANEL_SUBTITLE='Bellekte yazılabilir ve çalıştırılabilir alan taşıyan programlar; doğrulama ve otomatik durdurma kararı.'
    PREFIXES=('SATSUMA-RAM-','SATSUMA-MEM-','SATSUMA-FILELESS-')
    COLUMNS=DefensePanel.COLUMNS+(('Süreç takibi','process_state'),('Müdahale kararı','process_decision'),('İlişkili süreç','related_processes'))
    def _build(self):
        super()._build()
        self.scope_details=QPlainTextEdit();self.scope_details.setReadOnly(True)
        self.scope_details.setMaximumHeight(200);self.scope_details.hide()
        button=QPushButton('Tarama kapsamı ve teknik ayrıntılar')
        button.clicked.connect(lambda:self.scope_details.setVisible(self.scope_details.isHidden()))
        index=self._layout.indexOf(self.table)
        self._layout.insertWidget(index,button);self._layout.insertWidget(index+1,self.scope_details)

    def _show_details(self):
        row=self.table.currentRow()
        if not 0<=row<len(self._rows):
            self.details.setPlainText('Bir kayıt seçin.');return
        item=self._rows[row]
        try:
            detail=self.backend.call('finding',finding_id=item.get('finding_id'),record_key=item.get('record_key')) or {}
            followup=detail.get('process_followup') or item.get('process_followup') or {}
            lines=['Süreç: '+str(followup.get('summary','Takip kaydı yok')),
                   'Karar: '+str(followup.get('decision_summary','Karar kaydı yok')),
                   'İlişkili süreçler bağlantı gözlemidir; zararlı oldukları anlamına gelmez.']
            evidence=followup.get('evidence_summary') or {}
            lines.append('Program: '+str(evidence.get('exe') or item.get('process_name') or 'Kayıtta yok')+' · İmza: '+str(evidence.get('signature') or 'Kayıtta yok'))
            for member in followup.get('members',[]):
                lines.append('PID '+str(member.get('pid'))+' · '+str(member.get('observed_exe') or member.get('exe',''))+' · '+str(member.get('relation_label'))+' · '+str(member.get('state_label'))+' · İlk gözlem: '+timestamp(member.get('first_seen')))
            self.details.setPlainText('\n'.join(lines)+'\n\n'+json.dumps(detail,ensure_ascii=False,indent=2,default=str))
        except Exception as exc:
            self.details.setPlainText('Seçili bulgunun takip ayrıntıları alınamadı / yükleniyor: '+str(exc)[:200]+'\n'+json.dumps(item,ensure_ascii=False,indent=2,default=str))

    def refresh(self,*args):
        # Health and historical evidence use independent reader requests/queues.
        try:
            data = self.backend.call('memory_health') or {}
            text = memory_health_summary(data)
            self.scope_details.setPlainText(json.dumps(data,ensure_ascii=False,indent=2,default=str))
        except Exception as exc:
            text = 'Bellek sağlık bilgisi alınamadı: ' + str(exc)[:300]
        self.status.setText(getattr(self, '_memory_evidence_status', 'Veri bekleniyor'))
        super().refresh(*args)
        # Preserve historical request errors rather than replacing them with no-data.
        evidence_status = self.status.text()
        self._memory_evidence_status = evidence_status
        self.status.setText(text + '\nBulgu listesi: ' + evidence_status)



@register
class NetworkDefensePanel(DefensePanel):
    METHOD='network_defense'
    PANEL_ID='network_defense'
    PANEL_TITLE='Ağ bulguları'
    PANEL_ICON='🛡'
    PANEL_ORDER=14
    PANEL_GROUP='system'
    PANEL_SUBTITLE='Ağ, veri sızdırma ve yanal hareket göstergeleri. Ağ ayarları Koruma bölümündedir.'
    PREFIXES=('SATSUMA-NET-','SATSUMA-C2-','SATSUMA-EXFIL-','SATSUMA-LAT-')
    SOURCES=('suricata','dns','network')

    def _build(self):
        super()._build()
        try:
            from PyQt6.QtWidgets import QPushButton,QPlainTextEdit
        except ImportError:
            from PyQt5.QtWidgets import QPushButton,QPlainTextEdit
        button=QPushButton('Ağ koruması ayarları  →');button.setObjectName('quiet')
        button.clicked.connect(lambda:__import__('satsuma.dashboard_qt.links',fromlist=['open_target']).open_target(self,'firewall_settings'))
        self._layout.insertWidget(2,button)
        self.discovery=QPlainTextEdit()
        self.discovery.setReadOnly(True)
        self.discovery.setMaximumHeight(220)
        self.discovery.setAccessibleName('Ağ keşfi: arayüzler, rotalar ve komşular')
        self._layout.insertWidget(3,self.discovery)

    def refresh(self,*args):
        super().refresh(*args)
        data=self._last_render[1] if self._last_render else {}
        telemetry=data.get('telemetry') or {};collector=data.get('collector') or {}
        discovery=data.get('discovery') or {}
        lines=['Ağ keşfi (pasif) · '+label(discovery.get('status'))+' · '+timestamp(discovery.get('updated_at'))]
        for row in discovery.get('interfaces',[]):
            lines.append(str(row.get('interface'))+' · '+str(row.get('state'))+' · '+', '.join(row.get('addresses') or []))
        for row in discovery.get('routes',[]):
            lines.append('Rota: '+str(row.get('dst','default'))+' · '+str(row.get('dev',''))+' · '+str(row.get('gateway','')))
        for row in discovery.get('neighbors',[]):
            lines.append('Komşu: '+str(row.get('ip'))+' · '+str(row.get('mac') or 'MAC bilinmiyor')+' · '+str(row.get('interface'))+' · '+str(row.get('state')))
        if discovery.get('errors'):lines.append('Eksik ölçümler: '+str(discovery['errors']))
        lines.append(discovery.get('scope') or 'Keşif verisi bekleniyor; cihaz yok sonucu çıkarılamaz')
        text='\n'.join(lines)
        if self.discovery.toPlainText()!=text:self.discovery.setPlainText(text)
        stamp=collector.get('last_run');fresh=isinstance(stamp,(int,float)) and 0<=time.time()-stamp<90
        records=(collector.get('raw') or {}).get('record_count')
        state='Veri alınamıyor' if not fresh else 'İzleme kapalı' if collector.get('status') in ('DISABLED','STOPPED') else 'Trafik bekleniyor' if records==0 else 'İzleme aktif; son ölçümde trafik işlendi' if isinstance(records,int) and records>0 else 'İşlenen trafik ölçümü alınamadı'
        interfaces=(collector.get('raw') or {}).get('interfaces') or []
        self.status.setText(state+' · Son trafik: '+timestamp(telemetry.get('last_event'))+'\nSon ölçümde işlenen kayıt: '+label(records)+' · İzlenen arayüz: '+(', '.join(interfaces) or 'Kayıtta belirtilmemiş')+' · Yerel IP: Kayıtta belirtilmemiş\n'+str(data.get('scope') or 'Kapsam alınamadı'))
