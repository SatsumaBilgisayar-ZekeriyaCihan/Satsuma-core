# -*- coding: utf-8 -*-
"""SURICATA modülü — EVE health ve ağ alarm özeti."""
try:
    from ._module import ReadOnlyModulePanel
    from . import register
except ImportError:
    from _module import ReadOnlyModulePanel
    from panels import register


@register
class SuricataPanel(ReadOnlyModulePanel):
    PANEL_ID = 'suricata'
    PANEL_TITLE = 'SURICATA'
    PANEL_ICON = '📡'
    PANEL_ORDER = 11
    PANEL_GROUP = 'system'
    PANEL_SUBTITLE = 'EVE AKIŞI · AĞ ALARMLARI · SÜREÇ AYRI DURUM'
    METHOD = 'suricata'
    KEY = 'network_alert_summary'
    COLUMNS = (
        ('Zaman', 'timestamp'),
        ('İmza', 'signature'),
        ('Önem', 'severity'),
        ('Kaynak', 'src_ip'),
        ('Hedef', 'dest_ip'),
        ('Protokol', 'protocol'),
        ('Sınıflama', 'classification'),
    )

    def refresh(self, *args):
        super().refresh(*args)
        try:
            data = self.backend.call('suricata')
            eve = data.get('eve_input') or {}
            self.status.setText(
                f"EVE: {eve.get('state')}  ·  SÜREÇ: {data.get('process_state')}  ·  "
                f"ALARM: {data.get('alert_count')}  ·  DNS EVENT: {data.get('dns_event_count')}"
            )
        except Exception as exc:
            self.status.setText('UNKNOWN · Veri okunamadı: '+str(exc)[:200])
