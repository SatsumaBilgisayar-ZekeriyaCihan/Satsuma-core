"""VPN and proxy indicators; a chosen connection is cut only with the user's confirmation (2.2.47).

Until 2.2.46 cutting was on the management page; it is here now, through the
shared lock. Göstergeler ve, açık onayla, seçilen bağlantıyı kesme.
"""
import time
from ._module import ReadOnlyModulePanel, QPushButton, QHBoxLayout
from . import register
from ...status_view import label


@register
class VpnProxyPanel(ReadOnlyModulePanel):
    PANEL_ID='vpn_proxy';PANEL_TITLE='VPN ve proxy'
    PANEL_ORDER=13;PANEL_GROUP='system'
    PANEL_SUBTITLE='Bu bilgisayardaki VPN ve proxy göstergeleri. Gösterge saldırı kanıtı değildir; gizli ya da uzak proxy kullanımının tamamı görülemez.'
    METHOD='vpn_proxy';KEY='items'
    COLUMNS=(('Ad','name'),('Gösterge','kind'),('Arayüz türü','type'),('PID','pid'),('Kapatılabilir','blockable'))

    def _build(self):
        super()._build()
        from ..qt import QCheckBox
        row=QHBoxLayout()
        self.confirm=QCheckBox('Seçtiğim bağlantının kesilmesini onaylıyorum; ağ erişimim kesilebilir.')
        row.addWidget(self.confirm,1)
        self.cut=QPushButton('Seçili bağlantıyı kes');self.cut.setObjectName('danger')
        self.cut.clicked.connect(self._disconnect);row.addWidget(self.cut)
        self._layout.insertLayout(3,row)

    def _disconnect(self):
        from ..links import run
        row=self.table.currentRow()
        item=self._rows[row] if 0<=row<len(self._rows) else None
        if not item or not item.get('blockable') or not item.get('id'):
            self.status.setText('Kapatılabilir bir bağlantı seçin.');return
        if not self.confirm.isChecked():
            self.status.setText('Önce bağlantının kesilmesini onaylayın.');return
        self.confirm.setChecked(False)
        run(self,'vpn_proxy_disconnect',{'target_id':item['id'],'confirmed':True},then=lambda *a:self.refresh())

    def refresh(self,*args):
        super().refresh(*args)
        data=self._last_render[1] if self._last_render else {}
        if not isinstance(data,dict) or not 0<=time.time()-data.get('updated_at',0)<=90:
            self.status.setText('Güncel VPN/proxy gözlemi yok.');return
        self.status.setText(('Envanter kısmen alınabildi. ' if data.get('errors') else '')+
            str(len(data.get('items',[])))+' gösterge. Kesmek için kapatılabilir bir satır seçip onaylayın; otomatik engelleme yapılmaz, servis yeniden bağlanabilir.')
