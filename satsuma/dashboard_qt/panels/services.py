# -*- coding: utf-8 -*-
"""Servisler modülü — systemd servis sağlığı (PID/uptime/restart)."""
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
    PANEL_SUBTITLE = 'Satsuma’nın systemd servisleri: çalışıyor mu, ne zamandır, kaç kez yeniden başladı.'
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

    def _build(self):
        super()._build()
        # 2.2.47: start, stop and restart moved here from the management page.
        from ._module import QPushButton, QHBoxLayout
        row=QHBoxLayout()
        caption=__import__('satsuma.dashboard_qt.ui',fromlist=['label']).label('Seçili servis:', 'secondary', wrap=False)
        row.addWidget(caption)
        for text,action,kind in (('Başlat','start',None),('Yeniden başlat','restart',None),('Durdur','stop','danger')):
            widget=QPushButton(text)
            if kind:widget.setObjectName(kind)
            widget.clicked.connect(lambda checked=False,a=action:self._service(a))
            row.addWidget(widget)
        row.addStretch()
        self._layout.insertLayout(3,row)

    def _service(self,action):
        from ..links import run
        from ...operator_service import SERVICES
        row=self.table.currentRow()
        name=str((self._rows[row] if 0<=row<len(self._rows) else {}).get('service') or '')
        if name and not name.endswith('.service'):name+='.service'
        if name not in SERVICES:
            self.status.setText('Yönetilebilir bir Satsuma servisi seçin.');return
        run(self,'service',{'action':action,'name':name},then=lambda *a:self.refresh())

