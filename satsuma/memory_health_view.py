"""Explain sampled RAM evidence without claiming full coverage or intervention.

Örneklem RAM kanıtını, tam tarama veya müdahale iddiasında bulunmadan açıklar.
"""
import time
from .status_view import timestamp

def summary(data, now=None):
    now=time.time() if now is None else now
    ram=data.get('ram_v2') or {};legacy=data.get('collector') or {}
    stamp=ram.get('updated_at') or legacy.get('updated_at')
    fresh=isinstance(stamp,(int,float)) and 0<=now-stamp<=45
    if not fresh:
        return 'RAM taraması: Güncel çalışma bilgisi alınamadı.\nSon bildirim: '+timestamp(stamp)+'\nBu durum, belleğin temiz olduğunu göstermez.'
    scanner=ram.get('scanner_state')
    if scanner=='UNAVAILABLE':
        lines=['RAM taraması: Bazı süreç sonuçlarında tarayıcıya erişilemedi.',
               'Eksik kalan taramalar var; koruma bütünüyle doğrulanmış değil.']
    elif scanner=='BYTES_SUBMITTED':
        lines=['RAM taraması: Son süreç sonuçlarında bellek verisi tarayıcıya iletildi.',
               'Kapsam: Sınırlı süreç belleği; tüm RAM taranmış değil.']
    else:
        lines=['RAM taraması: İşçi durum bildiriyor; tarayıcıya veri iletimi henüz doğrulanmadı.']
    reports=ram.get('last_observed_processes')
    if isinstance(reports,list) and reports:
        rows=[row for row in reports if isinstance(row,dict)]
        def amount(key):
            return sum(row.get(key,0) for row in rows
                       if isinstance(row.get(key,0),(int,float))
                       and not isinstance(row.get(key,0),bool) and row.get(key,0)>=0)
        lines.append('Son gözlem penceresi: '+str(len(rows))+' süreç kaydı; '
                     +str(ram.get('enumerated_processes','bilinmiyor'))+' süreç listelendi.')
        lines.append('Bu kayıtlardaki son tarama adımları: '
                     +format(amount('read_bytes_this_turn')/1048576,'.2f')+' MiB okundu; '
                     +format(amount('scanner_bytes_this_turn')/1048576,'.2f')+' MiB imza tarayıcısına iletildi.')
        lines.append('Bu sayılar toplam RAM kapsamı veya benzersiz taranan bellek miktarı değildir.')
    counts=ram.get('result_status_counts') or {}
    if counts:
        lines.append('Eksik değerlendirmeler: tarayıcıya erişilemeyen '
                     +str(counts.get('SCANNER_UNAVAILABLE',0))+'; süreç bilgisi alınamayan '
                     +str(counts.get('PROCESS_UNAVAILABLE',0))+'; tarama sırasında değişen '
                     +str(counts.get('PROCESS_CHANGED',0))+'.')
    lines.append('Bulgu ve müdahale: Veri tarayıcıya gönderildi bilgisi, tehdit bulunduğu veya program durdurulduğu anlamına gelmez. Sonuç için bulgu ve güvenlik aksiyonu kayıtları gerekir.')
    if ram.get('coverage_state')=='INCOMPLETE':
        lines.append('Eksikler: Tamamlanmamış veya erişim/değişim nedeniyle değerlendirilemeyen süreçler var.')
    decision=ram.get('intervention') or {}
    lines.append('Müdahale doğrulaması: '+('Güven koşulları sağlandı; her bulgu ayrıca değerlendirilir.'
        if decision.get('status')=='READY' and decision.get('allowed') is True else 'Güven koşulları henüz sağlanmadı veya bilgisi alınamadı.'))
    lines.append('Son bildirim: '+timestamp(stamp))
    return '\n'.join(lines)
