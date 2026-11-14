# -*- coding: utf-8 -*-
"""AUDIT modülü — güvenlikle ilgili olaylar, ayrıcalık gözlemleri."""
try:
    from ._module import ReadOnlyModulePanel
    from . import register
except ImportError:
    from _module import ReadOnlyModulePanel
    from panels import register


@register
class AuditPanel(ReadOnlyModulePanel):
    PANEL_ID = 'audit'
    PANEL_TITLE = 'AUDIT'
    PANEL_ICON = '🧾'
    PANEL_ORDER = 10
    PANEL_GROUP = 'system'
    PANEL_SUBTITLE = 'AYRICALIK GÖZLEMLERİ · DOSYA/SÜREÇ KANITI · KORELASYON'
    METHOD = 'audit'
    KEY = 'recent_events'
    COLUMNS = (
        ('Zaman', 'timestamp'),
        ('Olay', 'summary'),
        ('Kapsam', 'category'),
        ('Süreç', 'process'),
        ('PID', 'pid'),
        ('UID', 'uid'),
        ('AUID', 'auid'),
        ('Başarılı', 'success'),
        ('Yol', 'paths'),

    )
