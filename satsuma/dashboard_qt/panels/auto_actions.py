from ._module import ReadOnlyModulePanel
from . import register
from ...presentation import action_view

@register
class AutoActionsPanel(ReadOnlyModulePanel):
    PANEL_ID = 'auto_actions'
    PANEL_TITLE = 'Otomatik Aksiyonlar'
    PANEL_ORDER = 3
    METHOD = 'rows'
    PARAMS = {'kind': 'actions', 'limit': 200}
    COLUMNS = (('Zaman', 'timestamp'), ('Aksiyon', 'action'), ('Sonuç', 'outcome'), ('Hedef', 'target'), ('Neden', 'reason'), ('Tekrar', 'repeat_count'))

    FILTERS = (('search', 'Ara', ()), ('kind', 'Görünüm', ('Güvenlik aksiyonları','İç kayıtlar')))

    def _params(self):
        return dict(self.PARAMS)

    def _rows_from(self, data):
        rows=[];grouped={}
        for item in super()._rows_from(data):
            row=action_view(item);row['repeat_count']=1
            # Only group a proven shared detection; no IP/time-only attribution.
            identity=item.get('detection_id')
            if identity:
                key=(identity,row.get('action'),str(row.get('target')),row.get('outcome'))
                if key in grouped:
                    grouped[key]['repeat_count']+=1;grouped[key]['related'].append(item);continue
                row['_group_id']=str(key);row['related']=[item];grouped[key]=row
            rows.append(row)
        search=self._filter_widgets['search'].text().casefold()
        internal=self._filter_widgets['kind'].currentData()=='İç kayıtlar'
        return [r for r in rows if r['internal']==internal and (not search or search in str(r).casefold())]
