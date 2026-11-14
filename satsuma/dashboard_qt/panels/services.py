# -*- coding: utf-8 -*-
"""SERVİSLER modülü — systemd servis sağlığı (PID/uptime/restart)."""
try:
    from ._module import ReadOnlyModulePanel
    from . import register
except ImportError:
    from _module import ReadOnlyModulePanel
    from panels import register


@register
class ServicesPanel(ReadOnlyModulePanel):
    PANEL_ID = 'services'
    PANEL_TITLE = 'SERVİSLER'
    PANEL_ICON = '🧩'
    PANEL_ORDER = 7
    PANEL_GROUP = 'system'
    PANEL_SUBTITLE = 'SYSTEMD SERVİS SAĞLIĞI'
    METHOD = 'services'
    KEY = 'items'
    COLUMNS = (
        ('Servis', 'service'),
        ('Çalışma biçimi', 'lifecycle'),
        ('Durum', 'status'),
        ('PID', 'pid'),
        ('Uptime (sn)', 'uptime_seconds'),
        ('Son Hata', 'last_failure_seconds_ago'),
        ('Restart', 'restart_count'),
    )
