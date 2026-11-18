"""Owned block history with explicit limits of enforcement evidence.

Satsuma's own block list, with what each block means in plain Turkish.

Satsuma'nın kendi engel listesi; her engelin ne anlama geldiği sade Türkçeyle.
"""
from ._module import ReadOnlyModulePanel
from . import register

REASON_PREFIXES=(('Operator OTX threshold (TLS verified): ','OTX: eşikten fazla tehdit raporu (TLS doğrulandı) — raporlar: '),
                 ('Subnet distinct-IP limit: ','Alt ağ engelleyici: aynı ağda eşikten fazla farklı IP — '))
REASON_LIMIT=140


def display_rows(rows):
    """Plain-Turkish reason, short enough that the IP column stays in view;
    the full text stays in "Teknik ayrıntılar"."""
    out=[]
    for row in rows:
        if not isinstance(row,dict):out.append(row);continue
        row=dict(row);reason=str(row.get('reason') or '')
        for old,new in REASON_PREFIXES:
            if reason.startswith(old):reason=new+reason[len(old):]
        row['reason']=reason if len(reason)<=REASON_LIMIT else reason[:REASON_LIMIT-1]+'…'
        out.append(row)
    return out


@register
class NetworkResponsePanel(ReadOnlyModulePanel):
    PANEL_ID='network_response';PANEL_TITLE='Engel geçmişi'
    PANEL_ORDER=12;PANEL_GROUP='system'
    PANEL_SUBTITLE=('Satsuma’nın engellediği adresler. Ağ korumasını güvenlik duvarı, Suricata alarmları, alt ağ '
                    'engelleyici (aynı /24 içinde 10 farklı IP) ve PTR kuralı yapar; bunlar OTX anahtarı olmadan çalışır. '
                    'OTX isteğe bağlı ek kaynaktır: OTX satırlarındaki adres AlienVault OTX’te eşik sayısından fazla tehdit '
                    'raporunda geçtiği için engellendi; neden sütunundaki adlar o raporların başlıklarıdır, size yapılan '
                    'saldırının türü değildir. “TLS doğrulandı”: '
                    'OTX sorgusu doğrulanmış şifreli bağlantıyla yapıldı.')
    METHOD='response';KEY='blocked_ips'
    COLUMNS=(('IP','ip'),('Neden','reason'),('Başlangıç','added_at'),('Bitiş','expires_at'),('Kaynak','source'))
    REASON_LIMIT=REASON_LIMIT

    def _rows_from(self,data):
        return display_rows(super()._rows_from(data))

    def refresh(self,*args):
        super().refresh(*args)
        data=self._last_render[1] if self._last_render else {}
        if not isinstance(data,dict):return
        if data.get('data_state')!='OK':text='Engel kayıtları okunamadı; durum doğrulanamadı.'
        elif not data.get('response_enabled'):text='Müdahale yapılandırması kapalı. Varsa geçmiş engeller aşağıdadır.'
        else:text='Müdahale yapılandırması açık. '+('Ön koşullar uygun; gerçek trafik engellemesi ayrıca doğrulanmalıdır.' if data.get('execution_ready') else 'Bütünlük veya politika ön koşulları doğrulanmadı.')
        if not data.get('blocked_ips'):text+=' Henüz engel kaydı yok.'
        if data.get('response_errors'):text+=' Müdahale hatası kaydı var; teknik ayrıntıları inceleyin.'
        if data.get('suricata_guard_state')=='UNREADABLE':text+=' Suricata engel listesi okunamadı; yalnızca Satsuma kayıtları gösteriliyor.'
        kernel=data.get('kernel_inventory') or {}
        text += ' · Listelenen kayıt: '+str(data.get('listed_record_count',len(data.get('blocked_ips') or [])))
        text += ' · Çekirdekte benzersiz IP: '+(str(kernel['unique_ip_count']) if kernel.get('unique_ip_count') is not None else 'Bilinmiyor')
        text += ' · Kayıt penceresi ile canlı nft kümesi aynı sayaç değildir.'
        self.status.setText(text)
