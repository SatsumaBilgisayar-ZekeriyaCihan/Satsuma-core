"""One sidebar section: a row of tabs over the pages they open; pages are made when first opened (2.2.47).

Bir kenar çubuğu bölümü: üstte sekmeler, altında açtıkları sayfalar; sayfa ilk
açıldığında oluşturulur.
"""
from ..qt import QWidget, QFrame, QVBoxLayout, QHBoxLayout, QPushButton, QStackedWidget, QButtonGroup, POINTING
from .. import panels as registry


class SectionPage(QWidget):
    def __init__(self, section, tabs, backend, window, parent=None):
        super().__init__(parent)
        self.setObjectName('section_' + section)
        self.section, self.tabs, self.backend, self.window_ref = section, tabs, backend, window
        self.panels = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.bar = QFrame()
        self.bar.setObjectName('tabBar')
        row = QHBoxLayout(self.bar)
        row.setContentsMargins(28, 10, 28, 0)
        row.setSpacing(4)
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self.buttons = {}
        for tab, title in tabs:
            item = QPushButton(title)
            item.setObjectName('sectionTab')
            item.setCheckable(True)
            item.setCursor(POINTING)
            item.clicked.connect(lambda checked=False, t=tab: window.nav.select(t))
            self.group.addButton(item)
            self.buttons[tab] = item
            row.addWidget(item)
        row.addStretch()
        self.bar.setVisible(len(tabs) > 1)
        layout.addWidget(self.bar)
        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)
        self.current = None

    def panel(self, tab, create=True):
        """The page for ``tab``; created (and activated) the first time. Raises when it cannot be built."""
        if tab in self.panels or not create:
            return self.panels.get(tab)
        cls = registry.get_panel(tab)
        if cls is None:
            raise LookupError('Sayfa bulunamadı: ' + tab)
        page = cls(self.backend)
        page._main_window = self.window_ref
        try:
            page.on_activate()
        except Exception:
            page.deleteLater()
            raise
        self.panels[tab] = page
        self.stack.addWidget(page)
        return page

    def show_tab(self, tab):
        created = tab not in self.panels
        page = self.panel(tab)
        if not created:
            page.on_activate()
        self.stack.setCurrentWidget(page)
        self.buttons[tab].setChecked(True)
        self.current = tab
        return page, created

    def current_panel(self):
        return self.panels.get(self.current)
