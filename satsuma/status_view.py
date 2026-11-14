"""Evidence presentation only. No authorization decisions are made here."""
import time
from datetime import datetime

LABELS = {
    'AGENT_REQUIRED':'Uzak tarama için ajan gerekli',
    'REMOTE_AGENT_REQUIRED':'Cihazda tarama ajanı gerekli',
    'PENDING':'Kullanıcı kararı bekleniyor', 'ALLOW':'İzin verildi', 'BLOCK':'Engellendi',
    'FINDINGS':'İnceleme gerektiren bulgular var', 'QUARANTINED':'Karantinaya alındı',
    'UNKNOWN':'Veri alınamadı', 'NO_DATA':'Henüz çalışmadı', 'NOT_RUN':'Henüz çalışmadı',
    'NOT_RUNNING':'Çalışmıyor', 'MISSING':'Kayıtta belirtilmemiş', 'UNAVAILABLE':'Veri alınamadı',
    'STALE':'Durum bildirimi gecikti', 'NOT_APPLICABLE':'Uygulanmaz',
    'RUNNING':'Çalışıyor', 'DEGRADED':'Sorunlu çalışıyor', 'STOPPED':'Durdu',
    'DISABLED':'Devre dışı', 'ACTIVE':'Etkin', 'INACTIVE':'Etkin değil',
    'HEALTHY':'Sağlıklı', 'PASSED':'Kontroller başarılı', 'OK':'Veri alındı',
    'FAILED':'Başarısız', 'ERROR':'Hata', 'WARNING':'Uyarı', 'UNTRUSTED':'Doğrulanamadı',
    'REQUESTED':'İstek alındı; sonuç bekleniyor', 'APPLIED':'Karar uygulandı',
    'COMPLETED':'Kontrol tamamlandı; sonucu inceleyin', 'READY':'Ön koşullar uygun; trafik testi gerekli',
    'FULL_CHECKED':'Dosya ve yapılandırma kontrolü tamamlandı',
}

def label(value):
    if value is None or value=='':return 'Kayıtta belirtilmemiş'
    return LABELS.get(str(value).upper(), str(value))

def timestamp(value):
    if value is None or value=='':return 'Kayıtta belirtilmemiş'
    try:
        if isinstance(value,str):
            try:value=float(value)
            except ValueError:value=datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()
        return datetime.fromtimestamp(value).astimezone().strftime('%d.%m.%Y %H:%M:%S %Z')
    except (ValueError,TypeError,OverflowError,OSError):return 'Veri alınamadı'

def health_summary(runtime, early, functional, now=None):
    now=time.time() if now is None else now
    checks=runtime.get('checks') or early.get('checks') or {}
    stamp=runtime.get('checked_at') or early.get('generated_at')
    fresh=isinstance(stamp,(int,float)) and 0<=now-stamp<=900
    def evidence(name):
        result=(checks.get(name) or {}).get('ok')
        return ('Sağlıklı' if result is True else 'Sorun var' if result is False else 'Durum alınamıyor') if fresh else 'Durum alınamıyor'
    files=evidence('application');config=evidence('configuration')
    fallback=fresh and (checks.get('configuration') or {}).get('fallback_active') is True
    if fallback:config='Önceki geçerli ayarlar etkin'
    # Older runtime evidence has no separate checks; HEALTHY means both gates passed.
    if not checks and runtime.get('status')=='HEALTHY' and fresh:files=config='Sağlıklı'
    fstamp=functional.get('updated_at')
    ffresh=isinstance(fstamp,(int,float)) and 0<=now-fstamp<=900
    fstatus=functional.get('status')
    protection=('Sağlıklı' if fstatus=='PASSED' else 'Sorun var' if fstatus in ('DEGRADED','FAILED') else 'Durum alınamıyor') if ffresh else 'Durum alınamıyor'
    conflict=(runtime.get('status')=='HEALTHY' and any((checks.get(k) or {}).get('ok') is False for k in ('application','configuration'))
              or fstatus=='PASSED' and ffresh and ('Sorun var' in (files,config)))
    overall='Kritik' if files=='Sorun var' else 'Sorun var' if 'Sorun var' in (config,protection) else 'Sağlıklı' if all(v=='Sağlıklı' for v in (files,config,protection)) else 'Durum alınamıyor'
    if conflict:overall='Sorun var'
    labels={'modem_reference':'Modem/rota referansı','dns_filter':'DNS filtresi','app_control':'Uygulama ağ koruması','response_integrity':'Müdahale bütünlüğü','worker_heartbeats':'Bileşen durum kayıtları','subnet_protection':'Alt ağ engelleyici'}
    failures=[labels.get(k,k) for k,v in (functional.get('checks') or {}).items() if isinstance(v,dict) and v.get('ok') is False]
    detail='Başarısız kontroller: '+', '.join(failures) if failures and ffresh else ''
    return {'overall':overall,'files':files,'configuration':config,'protection':protection,
            'protection_status':fstatus or 'NOT_RUN',
            'protection_message':str(functional.get('error') or detail), 'failed_checks':failures,
            'checked_at':stamp,'protection_checked_at':fstamp,'fresh':fresh,'inconsistent':bool(conflict),
            'message':'Yeni ayar geçersiz; koruma son geçerli ayarlarla sürüyor' if fallback else 'Kontrol sonuçları tutarsız; yeniden doğrulama gerekli' if conflict else detail,
            'scope':'Satsuma dosyaları, yapılandırması ve raporlanan işlev kontrolleri',
            'host_scope':'Genel sistem temizliği bu kontrol kapsamında doğrulanmadı.'}
