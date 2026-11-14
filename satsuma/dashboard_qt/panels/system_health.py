"""Human-readable functional health with explicit scope and retained technical evidence.

Each card answers one question in plain Turkish. With no problem it says
so in one line and names what was checked; with a problem it says what
broke, what that means and what to do. Field photo 2026-10-25: every card
repeated "Kontrol başarılı (rapor kapsamı)" twice and showed repair advice
even when nothing was wrong.

Anlaşılır işlevsel sağlık; kapsamı açık, teknik kanıtı saklı.

Her kart tek bir soruyu sade Türkçeyle cevaplar. Sorun yoksa bunu tek
satırda söyler ve neyin denetlendiğini adlandırır; sorun varsa neyin
bozulduğunu, bunun ne anlama geldiğini ve ne yapılacağını söyler. Saha
fotoğrafı 2026-10-25: her kart "Kontrol başarılı (rapor kapsamı)" ifadesini
iki kez tekrarlıyor, hiçbir sorun yokken bile onarım önerisi gösteriyordu.
"""
import json
try:
    from PyQt6.QtWidgets import QLabel,QGridLayout,QPushButton,QPlainTextEdit,QScrollArea,QWidget,QVBoxLayout,QHBoxLayout,QFrame,QSizePolicy
    from PyQt6.QtCore import QSize
except ImportError:
    from PyQt5.QtWidgets import QLabel,QGridLayout,QPushButton,QPlainTextEdit,QScrollArea,QWidget,QVBoxLayout,QHBoxLayout,QFrame,QSizePolicy
    from PyQt5.QtCore import QSize
from .base import BasePanel
from . import register
from ...status_view import timestamp,label
from ...network_health_view import network_model
from ..security_widgets import ShieldArtwork,icon
from ..style.theme import Colors


CHECK_LABELS={'services':'Satsuma servisleri','services_after_repair':'Onarım sonrası servisler',
    'packet_drop':'paket engelleme testi','production_incoming_rules':'gelen trafik kuralları',
    'nfqueue_consumers':'ağ kuyruğu servisleri','app_control':'uygulama internet izinleri',
    'competing_ips':'ikinci Suricata servisi','dns_filter':'DNS filtresi','dns_policy':'DNS yapılandırması',
    'dns_resolver_alignment':'sistemin DNS sunucusu','dns_threat_lists':'zararlı alan adı listeleri',
    'worker_heartbeats':'bileşenlerin çalışma kayıtları','core_state':'çekirdek durum kaydı',
    'subnet_protection':'alt ağ engelleyici'}
GROUPS={
    'services':('Servisler',('services_after_repair','services'),
        'Duran bir servis kendi korumasını yapamaz.','Servisler sayfasından servisi yeniden başlatın; tekrar durursa günlüğünü bana gönderin.'),
    'traffic':('Trafik engelleme',('packet_drop','production_incoming_rules','subnet_protection','nfqueue_consumers','app_control','competing_ips'),
        'Zararlı adreslere giden trafik durdurulamayabilir.','Yukarıdaki adımı uygulayın; çözülmezse Teknik ayrıntıları bana gönderin.'),
    'dns':('DNS',('dns_filter','dns_policy','dns_resolver_alignment','dns_threat_lists'),
        'Ad sorguları beklenmeyen bir sunucuya gidebilir ya da zararlı adlar engellenmeyebilir.','Yönetim → DNS bölümünde kullandığınız sunucuyu kontrol edin.'),
    'events':('Olay işleme',('worker_heartbeats','core_state'),
        'Olaylar geç değerlendirilir; uyarılar gecikebilir.','Arka plan bileşenleri sayfasında "Sorunlu" görünen bileşene bakın.'),
}
TONES={'ok':Colors.STATUS_OK,'problem':Colors.STATUS_CRIT,'unknown':Colors.STATUS_MUTED,'info':Colors.STATUS_WARN}
STATE_TEXT={'ok':'Sorun yok','problem':'Sorun var','unknown':'Bilgi yok','info':'Kapalı'}
ICONS={'services':'activity','traffic':'shield','dns':'network','events':'app','otx':'lock','identity':'network'}


def card_model(key,report,checks):
    """Structured card: title, tone, summary, items (problems), impact, action."""
    title,names,impact,action=GROUPS[key]
    model={'key':key,'title':title,'tone':'unknown','summary':'','items':[],'impact':None,'action':None}
    present=[(n,checks[n]) for n in names if isinstance(checks.get(n),dict)]
    if key=='services' and present:present=present[:1]
    status=report.get('status')
    if status in ('STALE','NOT_RUN','UNAVAILABLE','RUNNING') or not present:
        model['summary']={'NOT_RUN':'İlk sağlık kontrolü henüz yapılmadı.','STALE':'Son kontrol eski; yeni kontrol bekleniyor.',
                          'RUNNING':'Kontrol şu anda sürüyor.'}.get(status,'Bu alan için kontrol sonucu yok.')
        return model
    failed=[(n,c) for n,c in present if c.get('ok') is False]
    if key=='dns' and not any(n!='dns_filter' for n,_ in failed) and (checks.get('dns_filter') or {}).get('status') in ('DISABLED','NOT_CONFIGURED'):
        model.update(tone='info',summary='DNS filtresi kapalı; bu sonuç ad çözümlemesinin çalıştığını tek başına kanıtlamaz. Açmak için: Yönetim → DNS.')
        return model
    if not failed:
        model.update(tone='ok',summary='Denetlenen: '+', '.join(CHECK_LABELS.get(n,n) for n,_ in present)+'.')
        return model
    for name,check in failed:
        detail=check.get('error') or check.get('message') or ''
        if name.startswith('services'):
            down=[u for u,s in (check.get('states') or {}).items() if s.get('ActiveState')!='active']
            detail=', '.join(down[:5])+(' çalışmıyor' if down else '')
        model['items'].append(CHECK_LABELS.get(name,name)+(': '+str(detail) if detail else ''))
    model.update(tone='problem',summary=str(len(failed))+' denetim başarısız.',impact=impact,action=action)
    return model


def card_text(key,report,checks):
    """(text, tone) for one card; tone is ok, problem, info or unknown."""
    m=card_model(key,report,checks);tone=m['tone']
    if tone=='ok':return '✓ '+m['title']+' — sorun yok\n'+m['summary'],tone
    if tone=='info':return m['title']+' — filtre kapalı\n'+m['summary'],tone
    if tone=='unknown':return m['title']+' — bilgi yok\n'+m['summary'],tone
    return '\n'.join(['⚠ '+m['title']+' — sorun var']+['• '+i for i in m['items']]
                     +['Ne anlama gelir: '+m['impact'],'Ne yapmalı: '+m['action']]),tone


class HealthCard(QFrame):
    """One area: icon, title, coloured state pill, summary; problems and the next step when needed."""
    def __init__(self,key,title,parent=None):
        super().__init__(parent);self.setObjectName('healthCard')
        self.key=key;layout=QVBoxLayout(self);layout.setContentsMargins(20,18,20,18);layout.setSpacing(10)
        row=QHBoxLayout();row.setSpacing(12)
        self.glyph=QLabel();row.addWidget(self.glyph)
        self.heading=QLabel(title);self.heading.setStyleSheet('font-size:16px;font-weight:700;background:transparent;border:none;')
        row.addWidget(self.heading);row.addStretch()
        self.pill=QLabel('Bilgi yok');row.addWidget(self.pill);layout.addLayout(row)
        self.summary=QLabel('');self.summary.setWordWrap(True);self.summary.setStyleSheet('color:'+Colors.TEXT_SECONDARY+';background:transparent;border:none;')
        layout.addWidget(self.summary)
        self.items=QLabel('');self.items.setWordWrap(True);self.items.setStyleSheet('color:'+Colors.TEXT_PRIMARY+';background:transparent;border:none;')
        layout.addWidget(self.items)
        self.step=QLabel('');self.step.setWordWrap(True);layout.addWidget(self.step)
        self.setSizePolicy(QSizePolicy.Policy.Preferred if hasattr(QSizePolicy,'Policy') else QSizePolicy.Preferred,
                           QSizePolicy.Policy.Minimum if hasattr(QSizePolicy,'Policy') else QSizePolicy.Minimum)
        self.set_model({'tone':'unknown','summary':'Veri bekleniyor.','items':[]})

    def set_model(self,m):
        tone=m.get('tone','unknown');color=TONES[tone]
        self.setStyleSheet('QFrame#healthCard {background:'+Colors.BG_SURFACE+';border:1px solid '+Colors.BORDER_LIGHT
                           +';border-left:4px solid '+color+';border-radius:14px;}')
        name='check' if tone=='ok' else 'warning' if tone in ('problem','info') else ICONS.get(self.key,'activity')
        self.glyph.setPixmap(icon(name,color,26).pixmap(QSize(26,26)));self.glyph.setStyleSheet('background:transparent;border:none;')
        self.pill.setText(m.get('state') or STATE_TEXT[tone])
        self.pill.setStyleSheet('color:'+color+';border:1px solid '+color+';border-radius:10px;padding:2px 10px;font-weight:600;background:transparent;')
        self.summary.setText(m.get('summary') or '')
        items=m.get('items') or []
        self.items.setText('\n'.join('•  '+i for i in items));self.items.setVisible(bool(items))
        if m.get('action'):
            self.step.setText('<b>Ne anlama gelir:</b> '+m.get('impact','')+'<br><b>Ne yapmalı:</b> '+m['action'])
            self.step.setStyleSheet('background:'+Colors.BG_ELEVATED+';border:1px solid '+Colors.BORDER+';border-radius:8px;padding:10px;color:'+Colors.TEXT_PRIMARY+';')
            self.step.show()
        else:self.step.hide()


@register
class SystemHealthPanel(BasePanel):
    PANEL_ID='system_health';PANEL_TITLE='Sistem Sağlığı';PANEL_ORDER=14;PANEL_GROUP='security'
    def _build(self):
        self._layout.addWidget(self.make_title(self.PANEL_TITLE))
        hero=QFrame();hero.setObjectName('securityCard');top=QHBoxLayout(hero);top.setContentsMargins(22,16,22,16);top.setSpacing(22)
        self.shield=ShieldArtwork();top.addWidget(self.shield)
        texts=QVBoxLayout();texts.setSpacing(6)
        self.headline=QLabel('Durum bekleniyor');self.headline.setWordWrap(True);self.headline.setStyleSheet('font-size:22px;font-weight:700;background:transparent;border:none;')
        texts.addStretch();texts.addWidget(self.headline)
        self.status=QLabel('Durum alınamıyor');self.status.setWordWrap(True);self.status.setStyleSheet('color:'+Colors.TEXT_SECONDARY+';background:transparent;border:none;')
        texts.addWidget(self.status);texts.addStretch();top.addLayout(texts,1)
        self._layout.addWidget(hero)
        scroll=QScrollArea();scroll.setWidgetResizable(True);scroll.setFrameShape(QFrame.Shape.NoFrame if hasattr(QFrame,'Shape') else QFrame.NoFrame)
        body=QWidget();grid=QGridLayout(body);grid.setSpacing(16);grid.setContentsMargins(0,8,0,8)
        self.cards={}
        for i,(key,title) in enumerate((('services','Servisler'),('traffic','Trafik engelleme'),('dns','DNS'),('events','Olay işleme'),('otx','OTX tehdit istihbaratı'),('identity','Modem ve yönlendirme'))):
            card=HealthCard(key,title);grid.addWidget(card,i//2,i%2);self.cards[key]=card
        grid.setRowStretch(3,1)  # spare height goes below the cards, not into them
        scroll.setWidget(body);self._layout.addWidget(scroll,1)
        self.repairs=QLabel('Otomatik onarım: henüz çalışmadı');self.repairs.setWordWrap(True);self.repairs.setObjectName('secondary');self._layout.addWidget(self.repairs)
        toggle=QPushButton('Teknik ayrıntılar ve geçmiş hata kaydı');toggle.setObjectName('quiet');self._layout.addWidget(toggle)
        self.details=QPlainTextEdit();self.details.setReadOnly(True);self.details.setMaximumHeight(220);self.details.hide();self._layout.addWidget(self.details)
        toggle.clicked.connect(lambda:self.details.setVisible(self.details.isHidden()))

    def refresh(self):
        try:data=self.backend.call('system_health') or {}
        except Exception as exc:
            self.status.setText('Durum alınamıyor: '+str(exc));return
        summary=data.get('summary') or {};report=data.get('self_health') or {};checks=report.get('checks') or {}
        self.status.setText('Dosyalar: '+str(summary.get('files') or 'bilinmiyor')+' · Yapılandırma: '+str(summary.get('configuration') or 'bilinmiyor')
            +' · Koruma: '+str(summary.get('protection') or 'bilinmiyor')
            +'\nSon kontrol: '+timestamp(summary.get('checked_at'))+' · Koruma doğrulaması: '+timestamp(summary.get('protection_checked_at'))
            +'\n'+str(summary.get('message') or summary.get('host_scope') or 'Bu sayfa Satsuma’nın kendi bileşenlerini denetler; bilgisayarın virüsten temiz olduğunu göstermez.'))
        problems=[]
        for key in GROUPS:
            model=card_model(key,report,checks)
            if model['tone']=='problem':problems.append(model['title'])
            self.cards[key].set_model(model)
        identity=network_model(data.get('network_identity'))
        self.cards['identity'].set_model(identity)
        if identity['tone']=='problem':problems.append(identity['title'])
        otx=data.get('otx') or {}
        otx_ok=str(otx.get('status') or '').lower() in ('active','etkin','running','ok')
        self.cards['otx'].set_model({'tone':'ok' if otx_ok else 'unknown','state':label(otx.get('status') or 'UNKNOWN'),
            'summary':'İsteğe bağlı ek istihbarat: ağ koruması (güvenlik duvarı, Suricata, alt ağ engelleyici) OTX anahtarı olmadan da çalışır. '
                      'Anahtar varsa bağlandığınız adresler AlienVault OTX raporlarıyla da karşılaştırılır. Son başarılı sorgu: '
                      +timestamp(otx.get('last_successful_update'))+'. Engellenen adresler: Ağ güvenliği → Ağ koruması ve engeller.'})
        overall=str(summary.get('overall') or '')
        if problems:
            # The summary covers files and configuration; a red card must not sit under "Sağlıklı".
            self.headline.setText('⚠ Dikkat: '+', '.join(problems)+' alanında sorun var');self.shield.set_tone('critical')
        elif report.get('status') in (None,'NOT_RUN','STALE','UNAVAILABLE','RUNNING'):
            self.headline.setText('Sağlık kontrolü bekleniyor');self.shield.set_tone('unknown')
        else:
            self.headline.setText('Satsuma’nın bileşenleri sağlıklı' if overall in ('','Sağlıklı') else overall)
            self.shield.set_tone('healthy' if overall in ('','Sağlıklı') else 'warning')
        repairs=report.get('repairs') or []
        self.repairs.setText('Otomatik onarım: '+('; '.join(str(r.get('unit'))+': '+label(r.get('status')) for r in repairs) if repairs else 'gerekmedi.'))
        self.details.setPlainText(json.dumps(data,ensure_ascii=False,indent=2,default=str))
