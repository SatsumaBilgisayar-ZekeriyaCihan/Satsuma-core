"""Passive local VPN/proxy observations; changes are authenticated in Management."""
import time
from ._module import ReadOnlyModulePanel
from . import register


@register
class VpnProxyPanel(ReadOnlyModulePanel):
    PANEL_ID='vpn_proxy';PANEL_TITLE='VPN / Proxy'
    PANEL_ORDER=13;PANEL_GROUP='system'
    PANEL_SUBTITLE='Yerel göstergeler; gizli veya uzak proxy kullanımının tamamı tespit edilemez.'
    METHOD='vpn_proxy';KEY='items'
    COLUMNS=(('Ad','name'),('Gösterge','kind'),('Arayüz türü','type'),('PID','pid'),('Kapatma destekleniyor','blockable'))
    def refresh(self,*args):
        super().refresh(*args)
        data=self._last_render[1] if self._last_render else {}
        if not isinstance(data,dict) or not 0<=time.time()-data.get('updated_at',0)<=90:
            self.status.setText('Güncel VPN/proxy gözlemi yok.');return
        self.status.setText(('Envanter kısmen alınabildi. ' if data.get('errors') else '')+
            str(len(data.get('items',[])))+' gösterge. Bağlantı kesmek için Yönetim → VPN / Proxy bölümünü kullanın. Otomatik engelleme kapalı.')
