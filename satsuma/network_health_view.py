"""Human-readable network identity evidence; no enrollment or network changes."""
import time
from .status_view import timestamp

def network_model(data, now=None):
    data=data if isinstance(data,dict) else {}
    now=time.time() if now is None else now
    stamp=data.get('updated_at')
    fresh=isinstance(stamp,(int,float)) and 0<=now-stamp<30
    reference=data.get('reference') or {}
    gateways=data.get('gateways') or []
    match=bool(reference) and any(c==reference for c in gateways)
    additional=data.get('additional_gateway_candidates') or []
    model={'title':'Modem ve yönlendirme','tone':'unknown','state':'Bilgi yok',
           'summary':'Güncel ağ kimliği kaydı alınamadı.','items':[],'impact':None,'action':None}
    if not data:return model
    items=['Son gözlem: '+timestamp(stamp)]
    if reference:
        items+=['Kayıtlı ağ geçidi: '+str(reference.get('gateway','?'))+' · '+str(reference.get('interface','?')),
                'Kayıtlı modem MAC: '+str(reference.get('gateway_mac','?'))]
    if not fresh:
        model.update(summary='Ağ kimliği kaydı eski veya zaman bilgisi eksik; güncel eşleşme doğrulanamadı.',items=items)
        return model
    state=data.get('status')
    if state=='MATCHED_USER_APPROVAL' and match and data.get('routing_snapshot_matches') is True and not additional:
        model.update(tone='ok',state='Eşleşiyor',summary='Modem kimliği ve rota özeti onaylı referansla eşleşiyor.',items=items)
    elif match and data.get('routing_snapshot_matches') is False and not additional:
        model.update(tone='problem',state='Rota değişikliği',summary='Modem kimliği eşleşiyor; yönlendirme tablosunda değişiklik var.',
                     items=items+['Ek ağ geçidi yok.','Eski rota ayrıntısı bu kayıtta yok; hangi rotanın değiştiği bu veriden belirlenemiyor.'],
                     impact='VPN veya bağlantı değişimi de buna neden olabilir; bu kayıt tek başına saldırı kanıtı değildir.',
                     action='Ağ güvenliği bölümünden mevcut rotaları inceleyin; beklenen değişiklik doğrulanmadan modem referansını yenilemeyin.')
    else:
        model.update(tone='problem',state='İnceleme gerekli',summary='Modem veya ağ gözlemi onaylı referansla eşleşmiyor.',
                     items=items+['Durum: '+str(state or 'UNKNOWN'),'Ek ağ geçidi: '+str(len(additional))],
                     impact='Ağ geçidi, arayüz veya gözlem koşulları değişmiş olabilir.',
                     action='Yönetim ekranındaki modem adaylarıyla kayıtlı referansı karşılaştırın; otomatik yeniden onaylamayın.')
    return model
