# -*- coding: utf-8 -*-
"""Trafik analizi (Suricata) modülü — EVE health ve ağ alarm özeti."""
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
    PANEL_SUBTITLE = 'Suricata’nın ağ trafiğinde bulduğu alarmlar. Tüm bağlantılar bu denetimden geçer.'
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
            states={'running':'çalışıyor','RUNNING':'çalışıyor','OK':'akıyor','STALE':'eski','MISSING':'yok'}
            self.status.setText(
                f"Suricata: {states.get(str(data.get('process_state')), data.get('process_state'))} · Olay akışı: {states.get(str(eve.get('state')), eve.get('state'))} · "
                f"{data.get('alert_count')} alarm · {data.get('dns_event_count')} DNS olayı")
        except Exception as exc:
            self.status.setText('Suricata verisi okunamadı: '+str(exc)[:200])
