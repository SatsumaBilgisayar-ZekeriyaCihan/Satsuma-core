# -*- coding: utf-8 -*-
"""DNS sorguları modülü — DNS kayıtları, istek/cevap ve anomali özeti."""
try:
    from ._module import ReadOnlyModulePanel
    from . import register
except ImportError:
    from _module import ReadOnlyModulePanel
    from panels import register


@register
class DnsPanel(ReadOnlyModulePanel):
    PANEL_ID = 'dns'
    PANEL_TITLE = 'DNS'
    PANEL_ICON = '🌐'
    PANEL_ORDER = 4
    PANEL_GROUP = 'main'
    PANEL_SUBTITLE = 'Bu bilgisayarın sorduğu alan adları ve aldığı yanıtlar.'
    METHOD = 'dns'
    KEY = 'items'
    PARAMS = {'limit': 500}
    COLUMNS = (
        ('Zaman', 'timestamp'),
        ('Domain', 'domain'),
        ('RR Type', 'rrtype'),
        ('İstek/Cevap', 'direction'),
        ('Resolver', 'resolver'),
        ('Sonuç IP', 'result_ips'),
        ('RCODE', 'rcode'),
        ('Flags', 'flags'),
    )
    FILTERS = ()
