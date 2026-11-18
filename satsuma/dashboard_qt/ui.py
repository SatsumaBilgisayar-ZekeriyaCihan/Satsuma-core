"""Building blocks of the 2.2.45 panel: cards, state pills, switches, rows, page frame.

2.2.45 panelinin yapı taşları: kartlar, durum etiketleri, anahtarlar, satırlar, sayfa çerçevesi.
"""
from .qt import (QWidget, QFrame, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QScrollArea, QSize, QPainter,
                 QColor, QPen, QBrush, QRectF, Qt, pyqtSignal, enum, NO_SCROLL, POINTING, ALIGN_TOP, QSizePolicy,
                 EXPANDING, PREFERRED, TEXT_SELECTABLE)
from .style.theme import Colors

TONES = {
    'ok': (Colors.STATUS_OK, '#16240f'), 'on': (Colors.STATUS_OK, '#16240f'),
    'warn': (Colors.STATUS_WARN, '#2b2210'), 'warning': (Colors.STATUS_WARN, '#2b2210'),
    'attention': (Colors.STATUS_WARN, '#2b2210'), 'problem': (Colors.STATUS_WARN, '#2b2210'),
    'crit': (Colors.STATUS_CRIT, '#2e1510'), 'critical': (Colors.STATUS_CRIT, '#2e1510'), 'error': (Colors.STATUS_CRIT, '#2e1510'),
    'info': (Colors.STATUS_INFO, '#141d2b'), 'off': (Colors.TEXT_MUTED, '#1d1d1d'), 'unknown': (Colors.TEXT_MUTED, '#1d1d1d'),
}
OUTCOME_TONES = {'stopped': 'ok', 'blocked': 'ok', 'cut': 'ok', 'quarantined': 'ok', 'waiting': 'warn',
                 'not_stopped': 'warn', 'reported': 'unknown'}


def tone_color(tone):
    return TONES.get(tone, TONES['unknown'])[0]


def label(text='', name=None, wrap=True, selectable=False):
    widget = QLabel(text)
    widget.setWordWrap(wrap)
    if name:
        widget.setObjectName(name)
    if selectable:
        widget.setTextInteractionFlags(TEXT_SELECTABLE)
    return widget


def button(text, callback=None, kind=None, tip=None):
    widget = QPushButton(text)
    if kind:
        widget.setObjectName(kind)
    widget.setCursor(POINTING)
    if tip:
        widget.setToolTip(tip)
    if callback:
        widget.clicked.connect(lambda checked=False: callback())
    return widget


def clear(layout):
    """Remove every item of a layout (rows are rebuilt from fresh data)."""
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.hide()
            widget.deleteLater()
        elif item.layout() is not None:
            clear(item.layout())


class Card(QFrame):
    def __init__(self, parent=None, name='card', margins=(20, 18, 20, 18), spacing=10):
        super().__init__(parent)
        self.setObjectName(name)
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(*margins)
        self.body.setSpacing(spacing)


class Pill(QLabel):
    """A short state label in its tone's colour: Açık, Sorunlu, Durduruldu…"""

    def __init__(self, text='', tone='unknown', parent=None):
        super().__init__(parent)
        self.set(text, tone)

    def set(self, text, tone='unknown'):
        fg, bg = TONES.get(tone, TONES['unknown'])
        self.setText(text)
        self.setStyleSheet(f'color:{fg};background:{bg};border-radius:9px;padding:3px 10px;font-size:11px;font-weight:600;')
        self.setAccessibleName(text)


class Dot(QWidget):
    def __init__(self, tone='unknown', size=10, parent=None):
        super().__init__(parent)
        self.tone = tone
        self.setFixedSize(size, size)

    def set(self, tone):
        self.tone = tone
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(enum(QPainter, 'RenderHint', 'Antialiasing'))
        painter.setPen(enum(Qt, 'PenStyle', 'NoPen'))
        painter.setBrush(QBrush(QColor(tone_color(self.tone))))
        painter.drawEllipse(QRectF(0, 0, self.width(), self.height()))
        painter.end()


class Switch(QPushButton):
    """On/off switch. ``known`` is False until the real state arrives: then it shows neither."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setCursor(POINTING)
        self.setFixedSize(46, 26)
        self.setObjectName('switch')
        self.known = False

    def set_state(self, value):
        self.blockSignals(True)
        self.known = type(value) is bool
        self.setChecked(bool(value))
        self.setAccessibleName('Açık' if value is True else 'Kapalı' if value is False else 'Durum bilinmiyor')
        self.blockSignals(False)
        self.update()

    def sizeHint(self):
        return QSize(46, 26)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(enum(QPainter, 'RenderHint', 'Antialiasing'))
        on = self.isChecked() and self.known
        track = QColor(Colors.ACCENT if on else '#3a3a3a')
        if not self.isEnabled():
            track.setAlpha(110)
        painter.setPen(enum(Qt, 'PenStyle', 'NoPen'))
        painter.setBrush(QBrush(track))
        painter.drawRoundedRect(QRectF(1, 3, 44, 20), 10, 10)
        knob = QColor('#1a1715' if on else (Colors.TEXT_SECONDARY if self.known else '#6a6a6a'))
        painter.setBrush(QBrush(knob))
        x = 24 if on else (13 if not self.known else 4)
        painter.drawEllipse(QRectF(x, 5, 16, 16) if self.known else QRectF(x + 4, 9, 8, 8))
        if self.hasFocus():
            painter.setPen(QPen(QColor(Colors.ACCENT), 1))
            painter.setBrush(enum(Qt, 'BrushStyle', 'NoBrush'))
            painter.drawRoundedRect(QRectF(0.5, 2.5, 45, 21), 10.5, 10.5)
        painter.end()


class Page(QWidget):
    """Scrolling page with a title line; content goes into ``self.content``."""

    def __init__(self, title, subtitle='', parent=None):
        super().__init__(parent)
        self.setObjectName('page')
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(NO_SCROLL)
        body = QWidget()
        body.setObjectName('transparent')
        self.content = QVBoxLayout(body)
        self.content.setContentsMargins(32, 26, 32, 32)
        self.content.setSpacing(18)
        self.content.setAlignment(ALIGN_TOP)
        heading = QVBoxLayout()
        heading.setSpacing(4)
        self.title = label(title, 'pageTitle')
        heading.addWidget(self.title)
        self.subtitle = label(subtitle, 'pageSubtitle')
        self.subtitle.setVisible(bool(subtitle))
        heading.addWidget(self.subtitle)
        self.content.addLayout(heading)
        scroll.setWidget(body)
        outer.addWidget(scroll)
        self.scroll = scroll


def section(title, hint=''):
    box = QVBoxLayout()
    box.setSpacing(2)
    box.addWidget(label(title, 'sectionTitle'))
    if hint:
        box.addWidget(label(hint, 'secondary'))
    return box


class ActionRow(QFrame):
    """One thing that needs the user: dot, title, detail and its buttons."""

    def __init__(self, item, on_action, parent=None):
        super().__init__(parent)
        self.setObjectName('actionRow')
        self.item = item
        row = QHBoxLayout(self)
        row.setContentsMargins(16, 12, 14, 12)
        row.setSpacing(12)
        row.addWidget(Dot({'critical': 'critical', 'warning': 'warn', 'info': 'info'}.get(item.get('tone'), 'unknown')), 0)
        text = QVBoxLayout()
        text.setSpacing(2)
        text.addWidget(label(item.get('title', ''), 'rowTitle'))
        if item.get('detail'):
            text.addWidget(label(item['detail'], 'secondary', selectable=True))
        row.addLayout(text, 1)
        for index, action in enumerate(item.get('actions') or []):
            row.addWidget(button(action['label'], lambda a=action: on_action(a, item),
                                 'primary' if index == 0 and action.get('method') and item.get('tone') != 'info' else None))


class LayerTile(QFrame):
    clicked = pyqtSignal(str)

    def __init__(self, layer, parent=None):
        super().__init__(parent)
        self.setObjectName('layerTile')
        self.setCursor(POINTING)
        self.layer = layer
        box = QVBoxLayout(self)
        box.setContentsMargins(16, 14, 16, 14)
        box.setSpacing(6)
        top = QHBoxLayout()
        top.addWidget(label(layer['title'], 'tileTitle'), 1)
        top.addWidget(Dot(layer['state']), 0)
        box.addLayout(top)
        state = label(layer['label'], 'tileState')
        state.setStyleSheet(f'color:{tone_color(layer["state"])};font-weight:600;')
        box.addWidget(state)
        detail = label(layer['detail'], 'secondary')
        box.addWidget(detail)
        box.addStretch()
        self.setToolTip(layer['detail'])
        self.setAccessibleName(layer['title'] + ': ' + layer['label'])

    def mouseReleaseEvent(self, event):
        self.clicked.emit(self.layer.get('target') or '')
        super().mouseReleaseEvent(event)


class Metric(QFrame):
    def __init__(self, caption, parent=None):
        super().__init__(parent)
        self.setObjectName('metric')
        box = QVBoxLayout(self)
        box.setContentsMargins(16, 12, 16, 12)
        box.setSpacing(2)
        self.value = label('—', 'metricValue', wrap=False)
        box.addWidget(self.value)
        box.addWidget(label(caption, 'secondary'))

    def set(self, value):
        self.value.setText('—' if value is None else str(value))


class Empty(QFrame):
    def __init__(self, title, text, parent=None):
        super().__init__(parent)
        self.setObjectName('empty')
        box = QVBoxLayout(self)
        box.setContentsMargins(20, 22, 20, 22)
        self.title = label(title, 'rowTitle')
        self.text = label(text, 'secondary')
        box.addWidget(self.title)
        box.addWidget(self.text)

    def set(self, title, text):
        self.title.setText(title)
        self.text.setText(text)


class SettingRow(QFrame):
    """A labelled switch with one line that says what it changes."""
    toggled = pyqtSignal(bool)

    def __init__(self, title, explanation, parent=None):
        super().__init__(parent)
        self.setObjectName('settingRow')
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 10, 0, 10)
        row.setSpacing(14)
        text = QVBoxLayout()
        text.setSpacing(2)
        self.title = label(title, 'rowTitle')
        text.addWidget(self.title)
        self.explanation = label(explanation, 'secondary')
        text.addWidget(self.explanation)
        row.addLayout(text, 1)
        self.state = label('', 'secondary', wrap=False)
        row.addWidget(self.state)
        self.switch = Switch()
        self.switch.setAccessibleDescription(explanation)
        self.switch.clicked.connect(lambda checked: self.toggled.emit(checked))
        row.addWidget(self.switch)

    def set(self, value, note=None):
        self.switch.set_state(value)
        self.state.setText(note if note is not None else ('Açık' if value is True else 'Kapalı' if value is False else 'Bilinmiyor'))


def stretch_policy(widget, horizontal=EXPANDING, vertical=PREFERRED):
    widget.setSizePolicy(QSizePolicy(horizontal, vertical))
    return widget
