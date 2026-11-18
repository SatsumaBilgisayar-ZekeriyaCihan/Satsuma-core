# -*- coding: utf-8 -*-
"""Satsuma Internet Security main window (2.2.45 redesign).

Layout: sidebar (Durum, Olanlar, Koruma, Sağlık, Ayarlar, optional Uzman
görünümü) | top bar (title, search, waiting count, lock) + feedback line +
page stack. Pages are created when first opened and refresh only while
visible. One administrator lock (OperatorSession) serves every page.

Ana pencere: kenar çubuğu | üst çubuk + geri bildirim + sayfa yığını. Sayfalar
ilk açıldığında oluşturulur ve yalnızca görünürken yenilenir. Tek yönetici kilidi
tüm sayfalara hizmet eder.
"""
import datetime
import sys

from ..qt import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget, QStatusBar, QLabel, QTimer, Qt,
                  QKeySequence, QShortcut, QT as QT_VERSION, enum)
from ..style.theme import Colors, GLOBAL_QSS, FONT_MONO
from .nav import NavigationBar, TITLES, PRIMARY
from .topbar import TopBar, Feedback
from .. import panels as panel_registry
from ..session import OperatorSession

UI_VERSION = '2.0.0'


class MainWindow(QMainWindow):
    def __init__(self, backend, parent=None, session=None):
        super().__init__(parent)
        self.backend = backend
        self._panels = {}
        self._stack_index = {}
        self._timers = {}
        self.setWindowTitle('Satsuma Internet Security')
        self.resize(1320, 860)
        self.setMinimumSize(1060, 700)
        self.session = session or OperatorSession(parent=self)
        panel_registry.autodiscover()
        self._build_ui()
        self._load_panels()
        self._start_timers()
        self._notifications()
        self.session.changed.connect(self._lock_changed)
        self.session.message.connect(self.feedback.show_message)
        self.backend.updates.updated.connect(self._on_reader_updated)
        QTimer.singleShot(0, self._refresh_all)

    def _notifications(self):
        try:
            from ..app_notifications import AppNotifications
            self.app_notifications = AppNotifications(self)
        except Exception as exc:  # the panel works without the desktop popup
            print(f'[main_window] app notifications: {exc}', file=sys.stderr)
            self.app_notifications = None
        try:
            from ..process_approval_notifications import ProcessApprovalNotifications
            self.process_approval_notifications = ProcessApprovalNotifications(self)
        except Exception as exc:
            print(f'[main_window] approval notifications: {exc}', file=sys.stderr)
            self.process_approval_notifications = None

    # -- layout
    def _build_ui(self):
        central = QWidget()
        central.setObjectName('central')
        self.setCentralWidget(central)
        self.setStyleSheet(GLOBAL_QSS)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.nav = NavigationBar()
        self.nav.panel_selected.connect(self._on_panel_selected)
        root.addWidget(self.nav)
        content = QWidget()
        content.setObjectName('transparent')
        column = QVBoxLayout(content)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        self.header = self.topbar = TopBar()
        self.topbar.lock_clicked.connect(self._lock_clicked)
        self.topbar.attention_clicked.connect(lambda: self.nav.select('home'))
        self.topbar.search_requested.connect(self._search)
        column.addWidget(self.topbar)
        self.feedback = Feedback()
        column.addWidget(self.feedback)
        self.health_notice = QLabel()
        self.health_notice.setObjectName('attentionStrip')
        self.health_notice.setWordWrap(True)
        self.health_notice.hide()
        column.addWidget(self.health_notice)
        self.stack = QStackedWidget()
        column.addWidget(self.stack, 1)
        root.addWidget(content, 1)
        bar = QStatusBar()
        bar.setFixedHeight(24)
        self.setStatusBar(bar)
        self.db_label = QLabel(self._db_status_text())
        self.db_label.setStyleSheet(f'color:{Colors.TEXT_MUTED};font-family:{FONT_MONO};font-size:10px;padding-left:8px;')
        bar.addWidget(self.db_label)
        self.version_label = QLabel(f'Qt {QT_VERSION}  ·  Arayüz {UI_VERSION}')
        self.version_label.setStyleSheet(f'color:{Colors.TEXT_MUTED};font-family:{FONT_MONO};font-size:10px;padding-right:8px;')
        bar.addPermanentWidget(self.version_label)
        QShortcut(QKeySequence('Ctrl+F'), self, activated=lambda: self.topbar.search.setFocus())
        QShortcut(QKeySequence('Ctrl+Q'), self, activated=self.close)
        QShortcut(QKeySequence('Ctrl+L'), self, activated=self._lock_clicked)
        QShortcut(QKeySequence('F5'), self, activated=self._reload_current)
        for index, (panel_id, _, _) in enumerate(PRIMARY):
            QShortcut(QKeySequence('Ctrl+%d' % (index + 1)), self, activated=lambda p=panel_id: self.nav.select(p))

    # -- pages
    def _load_panels(self):
        for cls in panel_registry.all_panels():
            placeholder = QWidget()
            placeholder._panel_class = cls
            self._stack_index[cls.PANEL_ID] = self.stack.addWidget(placeholder)
            self._panels[cls.PANEL_ID] = placeholder
        self.nav.build()
        self.nav.set_connected(self.backend.is_connected())

    def _on_panel_selected(self, panel_id):
        if getattr(self, '_restoring_navigation', False):
            return
        import time
        started = time.perf_counter()
        current = self._current_panel_id()
        panel = self._panels.get(panel_id)
        if panel is None:
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
            self.feedback.show_message('error', f'Sayfa açılamadı: {exc}')
            if current and current != panel_id:
                self._restoring_navigation = True
                try:
                    self.nav.select(current)
                finally:
                    self._restoring_navigation = False
            return
        if current and current != panel_id and hasattr(self._panels[current], 'on_deactivate'):
            try:
                self._panels[current].on_deactivate()
            except Exception:
                pass
        index = self._stack_index[panel_id]
        if created:
            self.stack.removeWidget(panel)
            index = self.stack.insertWidget(index, candidate)
            self._stack_index[panel_id] = index
            self._panels[panel_id] = candidate
            panel.deleteLater()
            self._sync_admin(candidate)
        self.stack.setCurrentIndex(index)
        self.topbar.set_page(TITLES.get(panel_id, getattr(candidate, 'PANEL_TITLE', 'Satsuma')))
        self._restart_timer(panel_id)
        if not hasattr(self, '_panel_timings'):
            self._panel_timings = {}
        self._panel_timings[(panel_id, 'initial' if created else 'subsequent')] = time.perf_counter() - started

    def _current_panel_id(self):
        index = self.stack.currentIndex()
        return next((pid for pid, sidx in self._stack_index.items() if sidx == index), None)

    def current_panel(self):
        return self._panels.get(self._current_panel_id())

    def open_target(self, target, context=None):
        """'home', 'protection:dns', 'settings:modem', 'expert:findings', 'activity' (+ row)."""
        context = context or {}
        page, _, part = str(target or 'home').partition(':')
        if page == 'expert':
            page, part = part, ''
        self.nav.select(page)
        panel = self._panels.get(page)
        if panel is None or hasattr(panel, '_panel_class'):
            return
        if part and hasattr(panel, 'scroll_to'):
            QTimer.singleShot(50, lambda: panel.scroll_to(part))
        if page == 'activity' and context.get('row') and hasattr(panel, 'focus_row'):
            panel.focus_row(context['row'])
        if page == 'activity' and context.get('search') is not None and hasattr(panel, 'search'):
            panel.search.setText(context['search'])
            panel.reload()
        if page == 'admin' and context.get('section') == 'apps' and hasattr(panel, 'sections'):
            panel.sections.setCurrentRow(1)

    def _search(self, text):
        self.open_target('activity', {'search': text})

    # -- lock
    def _lock_clicked(self):
        if self.session.unlocked():
            self.session.lock()
        else:
            self.session.unlock(self, self._reload_current)

    def _lock_changed(self, unlocked):
        self.topbar.set_locked(not unlocked)
        admin = self._panels.get('admin')
        if admin is not None and not hasattr(admin, '_panel_class'):
            self._sync_admin(admin)
        self._reload_current()

    def _sync_admin(self, panel):
        """The advanced management page uses the same lock as the rest of the panel."""
        if getattr(panel, 'PANEL_ID', None) != 'admin':
            return
        if not getattr(panel, '_session_bound', False):
            panel._session_bound = True
            panel.completed.connect(lambda method, result: self.session.adopt(panel.token) if method in ('login', 'logout') else None)
        panel.token = self.session.token
        if hasattr(panel, '_set_enabled'):
            panel._set_enabled()

    # -- timers
    def _start_timers(self):
        self._page_timer = QTimer(self)
        self._page_timer.timeout.connect(self._refresh_current)
        self._restart_timer(self._current_panel_id())
        self._attention_timer = QTimer(self)
        self._attention_timer.setInterval(10000)
        self._attention_timer.timeout.connect(self._refresh_attention)
        self._attention_timer.start()
        self._timers['_page'] = self._page_timer
        self._timers['_attention'] = self._attention_timer

    def _restart_timer(self, panel_id):
        panel = self._panels.get(panel_id)
        interval = getattr(getattr(panel, '_panel_class', panel), 'REFRESH_MS', 5000) if panel is not None else 5000
        self._page_timer.stop() if hasattr(self, '_page_timer') else None
        if hasattr(self, '_page_timer') and interval > 0:
            self._page_timer.setInterval(interval)
            self._page_timer.start()

    def _refresh_current(self):
        panel_id = self._current_panel_id()
        panel = self._panels.get(panel_id)
        if panel is None or hasattr(panel, '_panel_class') or self.isMinimized():
            return
        try:
            panel.refresh()
        except Exception as exc:
            print(f'[main_window] refresh({panel_id}): {exc}', file=sys.stderr)
            self.statusBar().showMessage(f'Sayfa yenilenemedi: {exc}', 4000)

    _refresh_panel = lambda self, panel_id=None: self._refresh_current()

    def _reload_current(self):
        panel = self.current_panel()
        if panel is not None and hasattr(panel, 'reload'):
            panel.reload()
        else:
            self._refresh_current()

    def _refresh_attention(self):
        try:
            data = self.backend.call('home') or {}
        except Exception:
            return
        items = data.get('attention') or []
        urgent = [i for i in items if i.get('tone') in ('critical', 'warning')]
        tone = 'critical' if any(i.get('tone') == 'critical' for i in urgent) else 'warn'
        self.topbar.set_attention(len(urgent), tone)
        self.nav.set_count('home', len(urgent))
        on_home = self._current_panel_id() == 'home'
        if urgent and not on_home:
            first = urgent[0]['title']
            more = ' ve %d konu daha' % (len(urgent) - 1) if len(urgent) > 1 else ''
            self.health_notice.setText(first + more + ' — ayrıntılar Durum sayfasında (Ctrl+1).')
            self.health_notice.setStyleSheet('background:%s;color:%s;padding:9px 32px;font-size:12px;' % (
                '#2e1510' if tone == 'critical' else '#2b2210', Colors.STATUS_CRIT if tone == 'critical' else Colors.STATUS_WARN))
            self.health_notice.show()
        else:
            self.health_notice.hide()

    _refresh_self_health = _refresh_attention

    def _on_reader_updated(self):
        self.db_label.setText(self._db_status_text())
        self.nav.set_connected(self.backend.is_connected())
        self._refresh_all()

    def _refresh_all(self):
        self._refresh_current()
        self._refresh_attention()

    # -- keys
    def keyPressEvent(self, event):
        ctrl = bool(event.modifiers() & enum(Qt, 'KeyboardModifier', 'ControlModifier'))
        if self.nav.handle_key(event.key(), ctrl):
            event.accept()
            return
        super().keyPressEvent(event)

    # -- helpers
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
            return 'Okuyucu durumu bilinmiyor'

    def _update_status(self, text):
        now = datetime.datetime.now().strftime('%H:%M:%S')
        self.statusBar().showMessage(f'{text}  ·  {now}', 4000)

    def closeEvent(self, event):
        for timer in self._timers.values():
            timer.stop()
        for panel in self._panels.values():
            try:
                panel.on_deactivate()
            except Exception:
                pass
        if self.app_notifications is not None:
            self.app_notifications.timer.stop()
            self.app_notifications.command_id = None
            self.app_notifications.busy = False
            self.app_notifications.close()
        if self.process_approval_notifications is not None:
            self.process_approval_notifications.timer.stop()
            self.process_approval_notifications.hide()
        try:
            self.backend.close()
        except Exception:
            pass
        super().closeEvent(event)
