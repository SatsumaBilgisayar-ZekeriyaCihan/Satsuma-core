# -*- coding: utf-8 -*-
"""Satsuma Core — Ana pencere.

Katmanlar (yukaridan asagiya):
  HeaderBar        — turuncu bant (SATSUMA-SECURITY)
  NavigationBar    — 1-9 bolum secici
  QStackedWidget   — aktif panel
  QStatusBar       — alt durum cubugu

Panel yonetimi:
  - panels.autodiscover() ile registry doldurulur
  - all_panels() sirali panel siniflarini verir
  - her panel kendi refresh()'ini calistirir
  - QTimer her panelin REFRESH_MS'ine gore tetiklenir
"""
try:
    from PyQt6.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
        QStatusBar, QLabel, QApplication,
    )
    from PyQt6.QtCore import Qt, QTimer
    QT_VERSION = 6
except ImportError:
    from PyQt5.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
        QStatusBar, QLabel, QApplication,
    )
    from PyQt5.QtCore import Qt, QTimer
    QT_VERSION = 5

import datetime
import sys

try:
    from ..style.theme import Colors, GLOBAL_QSS, FONT_MONO
    from .header import HeaderBar
    from .nav import NavigationBar
    from .. import panels as panel_registry
except ImportError:
    from style.theme import Colors, GLOBAL_QSS, FONT_MONO
    from header import HeaderBar
    from nav import NavigationBar
    import panels as panel_registry


UI_VERSION = '0.8.0'


class MainWindow(QMainWindow):
    """Satsuma Core — Operasyon Merkezi ana penceresi."""

    def __init__(self, backend, parent=None):
        super().__init__(parent)
        self.backend = backend
        self._panels = {}           # panel_id -> panel instance
        self._stack_index = {}      # panel_id -> stack index
        self._timers = {}           # panel_id -> QTimer

        self.setWindowTitle('Satsuma Internet Security')
        self.resize(1280, 820)
        self.setMinimumSize(1000, 680)

        # 1) Registry'yi doldur (panels/ altindaki dosyalari import et)
        panel_registry.autodiscover()

        # 2) Arayuzu kur
        self._build_ui()

        # 3) Panelleri yukle
        self._load_panels()

        # 4) Zamanlayicilari baslat
        self._start_timers()
        from ..app_notifications import AppNotifications
        self.app_notifications = AppNotifications(self)
        # Independent desktop notice; read-only count over reader socket,
        # authenticated decisions exclusively over Operator IPC.
        from ..process_approval_notifications import ProcessApprovalNotifications
        self.process_approval_notifications = ProcessApprovalNotifications(self)

        # 5) Ilk yenileme
        self.backend.updates.updated.connect(self._on_reader_updated)
        QTimer.singleShot(0, self._refresh_all)

    # ------------------------------------------------------------------
    # UI kurulumu
    # ------------------------------------------------------------------

    def _build_ui(self):
        central = QWidget()
        central.setObjectName('central')
        self.setCentralWidget(central)

        self.setStyleSheet(GLOBAL_QSS)
        root=QHBoxLayout(central)
        root.setContentsMargins(0,0,0,0);root.setSpacing(0)
        self.nav=NavigationBar()
        self.nav.panel_selected.connect(self._on_panel_selected)
        root.addWidget(self.nav)
        content=QWidget();content.setObjectName('transparent')
        column=QVBoxLayout(content);column.setContentsMargins(0,0,0,0);column.setSpacing(0)
        self.header=HeaderBar(version=self._safe_backend_version())
        self.header.manage_requested.connect(lambda:self.nav.select('admin'))
        column.addWidget(self.header)
        self.health_notice=QLabel();self.health_notice.setWordWrap(True)
        self.health_notice.setStyleSheet('background:#32291f;color:#f5c882;padding:10px 28px;font-size:12px;border-bottom:1px solid #534332;')
        self.health_notice.hide();column.addWidget(self.health_notice)
        self.stack=QStackedWidget();column.addWidget(self.stack,1)
        root.addWidget(content,1)

        # Status bar
        self._build_statusbar()

    def _build_statusbar(self):
        sb = QStatusBar()
        sb.setFixedHeight(24)
        self.setStatusBar(sb)

        # Sol taraf: backend durumu
        self.db_label = QLabel(self._db_status_text())
        self.db_label.setStyleSheet(
            f'color: {Colors.TEXT_MUTED}; '
            f'font-family: {FONT_MONO}; '
            f'font-size: 10px; '
            f'padding-left: 8px; '
            f'background: transparent;'
        )
        sb.addWidget(self.db_label)

        # Sag taraf: surum
        self.version_label = QLabel(f'Qt {QT_VERSION}  ·  Arayüz {UI_VERSION}')
        self.version_label.setStyleSheet(
            f'color: {Colors.TEXT_MUTED}; '
            f'font-family: {FONT_MONO}; '
            f'font-size: 10px; '
            f'padding-right: 8px; '
            f'background: transparent;'
        )
        sb.addPermanentWidget(self.version_label)

    # ------------------------------------------------------------------
    # Panel yukleme
    # ------------------------------------------------------------------

    def _load_panels(self):
        """Registry'deki tum panelleri olustur ve stack'e ekle."""
        panel_classes = panel_registry.all_panels()
        if not panel_classes:
            self._show_empty_state()
            return

        for cls in panel_classes:
            try:
                panel = QWidget()
                panel._panel_class = cls
            except Exception as e:
                print(f'[main_window] {cls.__name__} yuklenemedi: {e}',
                      file=sys.stderr)
                continue

            idx = self.stack.addWidget(panel)
            self._panels[cls.PANEL_ID] = panel
            self._stack_index[cls.PANEL_ID] = idx

        # Navigasyonu simdi kur (paneller hazir olduktan sonra)
        self.nav.build()
        self.nav.set_connected(self.backend.is_connected())
        # Instantiate the opening panel instead of leaving a lazy placeholder.
        self.nav.select('overview')

    def _show_empty_state(self):
        """Hic panel yoksa bilgilendirici bir sayfa goster."""
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setAlignment(
            Qt.AlignmentFlag.AlignCenter if QT_VERSION == 6
            else Qt.AlignCenter
        )
        msg = QLabel('Henüz panel yok.\n\n'
                     'panels/ altina bir panel dosyasi ekleyin.')
        msg.setStyleSheet(
            f'color: {Colors.TEXT_MUTED}; '
            f'font-size: 14px; background: transparent;'
        )
        layout.addWidget(msg)
        self.stack.addWidget(w)

    # ------------------------------------------------------------------
    # Panel secimi
    # ------------------------------------------------------------------

    def _on_panel_selected(self, panel_id):
        """Navigasyondan panel secildi."""
        if getattr(self, '_restoring_navigation', False):
            return
        import time
        started = time.perf_counter()
        current = self._current_panel_id()
        idx = self._stack_index.get(panel_id)
        panel = self._panels.get(panel_id)
        if idx is None or panel is None:
            return
        created = hasattr(panel, '_panel_class')
        candidate = panel
        try:
            if created:
                candidate = panel._panel_class(self.backend)
            candidate.on_activate()
        except Exception as exc:
            if created and candidate is not panel:
                candidate.deleteLater()
            self._update_status(f'Panel açılamadı: {exc}')
            if current:
                self._restoring_navigation = True
                try:
                    self.nav.select(current)
                finally:
                    self._restoring_navigation = False
            return
        if current and current != panel_id and hasattr(self._panels[current], 'on_deactivate'):
            try:
                self._panels[current].on_deactivate()
            except Exception as exc:
                self._update_status(f'Panel kapatılamadı: {exc}')
        if created:
            self.stack.removeWidget(panel)
            idx = self.stack.insertWidget(idx, candidate)
            self._stack_index[panel_id] = idx
            self._panels[panel_id] = candidate
            panel.deleteLater()
        self.stack.setCurrentIndex(idx)
        from .nav import TITLES
        self.header.set_page(TITLES.get(panel_id, 'Güvenlik merkezi'))
        # Keep initial construction and cached navigation timings separate.
        if not hasattr(self, '_panel_timings'):
            self._panel_timings = {}
        self._panel_timings[(panel_id, 'initial' if created else 'subsequent')] = time.perf_counter() - started

        # Navigation has a persistent header; avoid transient status overlays.

    def _current_panel_id(self):
        """Su an aktif olan panelin ID'si."""
        idx = self.stack.currentIndex()
        for pid, sidx in self._stack_index.items():
            if sidx == idx:
                return pid
        return None

    # ------------------------------------------------------------------
    # Zamanlayicilar
    # ------------------------------------------------------------------

    def _start_timers(self):
        """Her panel icin kendi REFRESH_MS'ine gore QTimer kur."""
        for panel_id, panel in self._panels.items():
            interval = getattr(getattr(panel, '_panel_class', panel), 'REFRESH_MS', 3000)
            if interval <= 0:
                continue
            timer = QTimer(self)
            timer.setInterval(interval)
            timer.timeout.connect(
                lambda pid=panel_id: self._refresh_panel(pid)
            )
            timer.start()
            self._timers[panel_id] = timer

        # Header saatini her saniye guncelle
        self._clock_timer = QTimer(self)
        self._clock_timer.setInterval(1000)
        self._clock_timer.timeout.connect(self.header.tick)
        self._clock_timer.start()

        health_timer = QTimer(self)
        health_timer.setInterval(1000)
        health_timer.timeout.connect(self._refresh_self_health)
        health_timer.start()
        self._timers["_self_health"] = health_timer

    def _refresh_panel(self, panel_id):
        """Tek bir paneli yenile."""
        panel = self._panels.get(panel_id)
        if not panel or panel_id != self._current_panel_id() or self.isMinimized():
            return
        try:
            panel.refresh()
        except Exception as e:
            print(f'[main_window] refresh({panel_id}): {e}',
                  file=sys.stderr)
            self._update_status(f'Panel {panel_id} yenilenemedi: {e}')

    def _refresh_self_health(self):
        try:
            result = self.backend.call('self_health') or {}
            from satsuma.self_health import notice_text
            text = notice_text(result)
            summary=self.backend.call('health_summary') or {}
            if summary.get('overall') and summary['overall']!='Sağlıklı':
                text=str(summary.get('message') or ('Genel durum: '+summary['overall']))+' · Dosyalar: '+str(summary.get('files'))+' · Yapılandırma: '+str(summary.get('configuration'))+' · Koruma: '+str(summary.get('protection'))
            self.health_notice.setText(text)
            self.health_notice.setVisible(bool(text))
        except Exception:
            self.health_notice.setText('Sağlık kontrolü durumu alınamıyor; okuyucu bağlantısını inceleyin.')
            self.health_notice.show()

    def _on_reader_updated(self):
        self.header.set_version(self._safe_backend_version())
        self.db_label.setText(self._db_status_text())
        self.nav.set_connected(self.backend.is_connected())
        self._refresh_all()

    def _refresh_all(self):
        """Tum panelleri bir kere yenile (baslangicta)."""
        panel_id = self._current_panel_id()
        if panel_id:
            self._refresh_panel(panel_id)

    # ------------------------------------------------------------------
    # Klavye
    # ------------------------------------------------------------------

    def keyPressEvent(self, event):
        """1-9 tuslari ile panel degistir (TUI uyumu)."""
        key = event.key()
        if self.nav.handle_key(key):
            event.accept()
            return
        # Q = cikis
        if key == (Qt.Key.Key_Q if QT_VERSION == 6 else Qt.Key_Q):
            self.close()
            event.accept()
            return
        super().keyPressEvent(event)

    # ------------------------------------------------------------------
    # Yardimcilar
    # ------------------------------------------------------------------

    def _safe_backend_version(self):
        try:
            return self.backend.version()
        except Exception:
            return '-'

    def _db_status_text(self):
        try:
            if self.backend.client and self.backend.client.last_error:
                return 'Okuyucu hatası; son veriler güncel olmayabilir'
            if self.backend.is_connected():
                return 'Yerel okuyucu bağlantısı etkin'
            return 'Okuyucu bekleniyor / bağlantı yok; veriler doğrulanmadı'
        except Exception:
            return 'DB  ·  bilinmiyor'

    def _update_status(self, text):
        now = datetime.datetime.now().strftime('%H:%M:%S')
        self.statusBar().showMessage(f'{text}  ·  {now}', 4000)

    # ------------------------------------------------------------------
    # Kapanis
    # ------------------------------------------------------------------

    def closeEvent(self, event):
        # Tum zamanlayicilari durdur
        for timer in self._timers.values():
            timer.stop()
        if getattr(self, '_clock_timer', None):
            self._clock_timer.stop()

        # Panellere kapanis sinyali
        for panel in self._panels.values():
            try:
                panel.on_deactivate()
            except Exception:
                pass

        self.app_notifications.timer.stop()
        self.app_notifications.command_id=None
        self.app_notifications.busy=False
        self.app_notifications.close()
        self.process_approval_notifications.timer.stop()
        self.process_approval_notifications.hide()

        # Backend'i kapat
        try:
            self.backend.close()
        except Exception:
            pass

        super().closeEvent(event)
