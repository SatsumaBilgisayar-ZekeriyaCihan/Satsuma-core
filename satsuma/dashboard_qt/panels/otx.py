"""Bounded OTX evidence view; querying and verified blocking are separate."""
from ._module import ReadOnlyModulePanel
from . import register
from ...status_view import label,timestamp

@register
class OtxPanel(ReadOnlyModulePanel):
    PANEL_ID='otx';PANEL_TITLE='OTX';PANEL_ORDER=5;METHOD='otx';KEY='items'
    PANEL_SUBTITLE='İstihbarat sorguları, kanıtlı eşleşmeler ve müdahaleler; uygulama/domain ilişkisi yalnız kayıtta varsa gösterilir.'
    COLUMNS=(('Zaman','timestamp'),('IP / alan adı','target'),('Tehdit bilgisi','reason'),('Uygulama','application'),('İşlem sonucu','outcome'))
    FILTERS=(('search','Ara',()),('outcome','Sonuç',('Eşleşme','Engelleme')))
    def _params(self):return {}
    def _rows_from(self,data):
        rows=super()._rows_from(data);search=self._filter_widgets['search'].text().casefold()
        outcome=self._filter_widgets['outcome'].currentData()
        return [r for r in rows if (not search or search in str(r).casefold()) and (not outcome or (r.get('reason')=='otx_confirmed' if outcome=='Eşleşme' else r.get('traffic_drop_verified') is True))]
    def refresh(self,*args):
        super().refresh(*args)
        data=self._last_render[1] if self._last_render else {}
        if not isinstance(data,dict):return
        self.status.setText('Bağlantı: '+label(data.get('status') or 'UNKNOWN')+' · Son başarılı sorgu: '+timestamp(data.get('last_successful_update'))+'\nSorgulanan gösterge/cache: '+label(data.get('cache_count'))+' · Kanıtlı eşleşme: '+label(data.get('match_count'))+' · Paket düşürmesi doğrulanmış engelleme: '+label(data.get('verified_block_count'))+'\n'+str(data.get('counts_scope') or 'Veri alınamadı'))
