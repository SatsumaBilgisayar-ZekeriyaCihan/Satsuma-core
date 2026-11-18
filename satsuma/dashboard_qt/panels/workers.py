# -*- coding: utf-8 -*-
"""WORKERLAR modülü — gerçek worker durumları."""
try:
    from ._module import ReadOnlyModulePanel
    from . import register
except ImportError:
    from _module import ReadOnlyModulePanel
    from panels import register


@register
class WorkersPanel(ReadOnlyModulePanel):
    PANEL_ID = 'workers'
    PANEL_TITLE = 'Bileşenler'
    PANEL_ICON = '⚙'
    PANEL_ORDER = 6
    PANEL_GROUP = 'system'
    PANEL_SUBTITLE = 'Satsuma’nın arka plan bileşenleri: çalışıyor mu, en son ne zaman iş üretti.'
    METHOD = 'workers'
    KEY = 'items'
    COLUMNS = (
        ('Ad', 'name'),
        ('Görev', 'purpose'),
        ('Durum', 'status_tr'),
        ('Son Çalışma', 'last_run'),
        ('Son Başarılı Event', 'last_successful_event'),
        ('İşlenen', 'processed_count'),
        ('Hata', 'error_count'),
        ('Son Hata', 'last_error'),
        ('Degraded Nedeni', 'degraded_reason'),
    )

    def _rows_from(self, data):
        if isinstance(data, dict):
            return list(data.values())
        return data if isinstance(data, list) else []
