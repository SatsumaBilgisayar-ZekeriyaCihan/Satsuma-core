"""Native Qt vector artwork and reusable security surfaces. No external assets."""
try:
    from PyQt6.QtWidgets import QWidget,QFrame,QLabel,QVBoxLayout,QHBoxLayout,QPushButton
    from PyQt6.QtGui import QPainter,QPainterPath,QPen,QColor,QPixmap,QIcon,QBrush
    from PyQt6.QtCore import Qt,QRectF,QSize,QPointF
except ImportError:
    from PyQt5.QtWidgets import QWidget,QFrame,QLabel,QVBoxLayout,QHBoxLayout,QPushButton
    from PyQt5.QtGui import QPainter,QPainterPath,QPen,QColor,QPixmap,QIcon,QBrush
    from PyQt5.QtCore import Qt,QRectF,QSize,QPointF
from .style.theme import Colors


def vector(painter,name,color):
    """Draw at 24×24 logical coordinates, with a consistent rounded stroke."""
    pen=QPen(QColor(color),1.65)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap if hasattr(Qt,'PenCapStyle') else Qt.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin if hasattr(Qt,'PenJoinStyle') else Qt.RoundJoin)
    painter.setPen(pen);painter.setBrush(Qt.BrushStyle.NoBrush if hasattr(Qt,'BrushStyle') else Qt.NoBrush)
    if name=='shield':
        p=QPainterPath();p.moveTo(12,2.5);p.lineTo(20,6);p.lineTo(19,14);p.cubicTo(18,18,14,20.5,12,22);p.cubicTo(10,20.5,6,18,5,14);p.lineTo(4,6);p.closeSubpath();painter.drawPath(p)
    elif name=='home':
        p=QPainterPath();p.moveTo(3,10);p.lineTo(12,3);p.lineTo(21,10);p.moveTo(5,9);p.lineTo(5,21);p.lineTo(19,21);p.lineTo(19,9);p.moveTo(10,21);p.lineTo(10,14);p.lineTo(14,14);p.lineTo(14,21);painter.drawPath(p)
    elif name=='network':
        painter.drawRoundedRect(QRectF(8,2,8,6),1,1);painter.drawRoundedRect(QRectF(2,16,7,6),1,1);painter.drawRoundedRect(QRectF(15,16,7,6),1,1)
        p=QPainterPath();p.moveTo(12,8);p.lineTo(12,12);p.moveTo(5.5,16);p.lineTo(5.5,12);p.lineTo(18.5,12);p.lineTo(18.5,16);painter.drawPath(p)
    elif name=='activity':
        p=QPainterPath();p.moveTo(2,13);p.lineTo(6,13);p.lineTo(9,5);p.lineTo(13,20);p.lineTo(16,10);p.lineTo(18,13);p.lineTo(22,13);painter.drawPath(p)
    elif name=='settings':
        for x,y in ((6,8),(12,16),(18,6)):
            painter.drawLine(x,3,x,y-2);painter.drawLine(x,y+2,x,21);painter.drawEllipse(QRectF(x-2,y-2,4,4))
    elif name=='database':
        painter.drawEllipse(QRectF(5,2.5,14,5))
        p=QPainterPath();p.moveTo(5,5);p.lineTo(5,19);p.cubicTo(5,22.5,19,22.5,19,19);p.lineTo(19,5)
        p.moveTo(5,12);p.cubicTo(5,15.5,19,15.5,19,12);painter.drawPath(p)
    elif name=='app':
        for x,y in ((3,3),(14,3),(3,14),(14,14)):painter.drawRoundedRect(QRectF(x,y,7,7),1.5,1.5)
    elif name=='lock':
        painter.drawRoundedRect(QRectF(5,10,14,12),2,2);painter.drawArc(QRectF(8,2,8,14),0,180*16);painter.drawLine(12,15,12,18)
    elif name=='arrow':
        p=QPainterPath();p.moveTo(5,12);p.lineTo(19,12);p.moveTo(14,7);p.lineTo(19,12);p.lineTo(14,17);painter.drawPath(p)
    elif name=='check':
        p=QPainterPath();p.moveTo(5,12);p.lineTo(10,17);p.lineTo(19,7);painter.drawPath(p)
    elif name=='warning':
        p=QPainterPath();p.moveTo(12,3);p.lineTo(22,21);p.lineTo(2,21);p.closeSubpath();painter.drawPath(p);painter.drawLine(12,9,12,14);painter.drawEllipse(QRectF(11.4,17,1.2,1.2))
    elif name=='pulse':
        p=QPainterPath();p.moveTo(12,20);p.cubicTo(4,14,2,10,4,6.5);p.cubicTo(6,3.5,10,3.5,12,7);p.cubicTo(14,3.5,18,3.5,20,6.5);p.cubicTo(22,10,20,14,12,20)
        p.moveTo(3,12);p.lineTo(8,12);p.lineTo(10,9);p.lineTo(13,15);p.lineTo(15,12);p.lineTo(21,12);painter.drawPath(p)
    elif name=='code':
        p=QPainterPath();p.moveTo(8,7);p.lineTo(3,12);p.lineTo(8,17);p.moveTo(16,7);p.lineTo(21,12);p.lineTo(16,17);p.moveTo(14,5);p.lineTo(10,19);painter.drawPath(p)
    elif name=='bell':
        p=QPainterPath();p.moveTo(6,17);p.lineTo(6,11);p.cubicTo(6,7,8.5,5,12,5);p.cubicTo(15.5,5,18,7,18,11);p.lineTo(18,17);p.lineTo(20,19);p.lineTo(4,19);p.lineTo(6,17)
        p.moveTo(10,21);p.lineTo(14,21);painter.drawPath(p)
    elif name=='search':
        painter.drawEllipse(QRectF(4,4,12,12));painter.drawLine(15,15,20,20)
    elif name=='bug':
        painter.drawEllipse(QRectF(7.5,8,9,12));painter.drawLine(12,8,12,20);painter.drawArc(QRectF(9,4,6,6),0,180*16)
        for y in (11,14.5,18):painter.drawLine(QPointF(7.5,y),QPointF(3.5,y-1.5));painter.drawLine(QPointF(16.5,y),QPointF(20.5,y-1.5))
    elif name=='firewall':
        painter.drawRoundedRect(QRectF(3,5,18,15),1.5,1.5)
        for y in (10,15):painter.drawLine(QPointF(3,y),QPointF(21,y))
        for x,y0,y1 in ((9,5,10),(15,5,10),(6,10,15),(12,10,15),(18,10,15),(9,15,20),(15,15,20)):painter.drawLine(QPointF(x,y0),QPointF(x,y1))
    elif name=='logs':
        for y in (6,12,18):painter.drawEllipse(QRectF(3.2,y-1,2,2));painter.drawLine(QPointF(8,y),QPointF(21,y))
    elif name=='unlock':
        painter.drawRoundedRect(QRectF(5,10,14,12),2,2);painter.drawArc(QRectF(8,2,8,14),40*16,140*16);painter.drawLine(12,15,12,18)
    else:
        painter.drawEllipse(QRectF(3,3,18,18));painter.drawLine(12,7,12,12);painter.drawLine(12,12,16,14)


def icon(name,color=None,size=24):
    pixmap=QPixmap(size*2,size*2);pixmap.fill(Qt.GlobalColor.transparent if hasattr(Qt,'GlobalColor') else Qt.transparent)
    painter=QPainter(pixmap);painter.setRenderHint(QPainter.RenderHint.Antialiasing if hasattr(QPainter,'RenderHint') else QPainter.Antialiasing)
    painter.scale(size*2/24,size*2/24);vector(painter,name,color or Colors.TEXT_SECONDARY);painter.end();pixmap.setDevicePixelRatio(2)
    return QIcon(pixmap)


class ShieldArtwork(QWidget):
    def __init__(self,parent=None):
        super().__init__(parent);self.setFixedSize(184,190);self.tone='unknown';self.setAccessibleName('Koruma durumu simgesi: veri bekleniyor')
    def set_tone(self,tone):
        self.tone=tone;self.setAccessibleName('Koruma durumu simgesi: '+tone);self.update()
    def paintEvent(self,event):
        p=QPainter(self);p.setRenderHint(QPainter.RenderHint.Antialiasing if hasattr(QPainter,'RenderHint') else QPainter.Antialiasing)
        colors={'healthy':Colors.STATUS_OK,'warning':Colors.STATUS_WARN,'critical':Colors.STATUS_CRIT,'unknown':Colors.TEXT_MUTED}
        color=QColor(colors[self.tone]);glow=QColor(color);glow.setAlpha(12)
        p.setPen(QPen(QColor('#2e2e2e'),1));p.setBrush(QBrush(glow));p.drawEllipse(QRectF(9,12,166,166))
        p.setPen(QPen(QColor('#3a3a3a'),1));p.drawEllipse(QRectF(24,27,136,136))
        p.save();p.translate(34,30);p.scale(4.8,4.8)
        fill=QColor(color);fill.setAlpha(14);p.setBrush(fill)
        path=QPainterPath();path.moveTo(12,2.5);path.lineTo(20,6);path.lineTo(19,14);path.cubicTo(18,18,14,20.5,12,22);path.cubicTo(10,20.5,6,18,5,14);path.lineTo(4,6);path.closeSubpath()
        p.setPen(QPen(color,.45));p.drawPath(path);p.restore()
        p.save();p.translate(72,66);p.scale(1.7,1.7)
        if self.tone=='healthy':vector(p,'check',color.name())
        elif self.tone in ('warning','critical'):vector(p,'warning',color.name())
        else:vector(p,'clock',color.name())
        p.restore();p.end()


class SecurityCard(QFrame):
    def __init__(self,title,description,symbol,button_text,callback,parent=None):
        super().__init__(parent);self.setObjectName('securityCard');self.setMinimumWidth(0)
        layout=QVBoxLayout(self);layout.setContentsMargins(18,17,18,15);layout.setSpacing(8)
        row=QHBoxLayout();glyph=QLabel();glyph.setPixmap(icon(symbol,Colors.ACCENT,26).pixmap(QSize(26,26)));row.addWidget(glyph);row.addStretch()
        self.state=QLabel('Veri bekleniyor');self.state.setStyleSheet('color:'+Colors.TEXT_MUTED+';font-size:11px;');row.addWidget(self.state);layout.addLayout(row)
        heading=QLabel(title);heading.setStyleSheet('font-size:15px;font-weight:700;');layout.addWidget(heading)
        text=QLabel(description);text.setWordWrap(True);text.setObjectName('secondary');text.setMinimumHeight(34);layout.addWidget(text)
        self.detail=QLabel('Durum henüz doğrulanmadı.');self.detail.setWordWrap(True);self.detail.setObjectName('secondary');self.detail.setMinimumHeight(28);layout.addWidget(self.detail)
        button=QPushButton(button_text+'  →');button.setObjectName('quiet');button.clicked.connect(callback);layout.addWidget(button)
    def set_state(self,text,tone='unknown',detail=None):
        color={'healthy':Colors.STATUS_OK,'warning':Colors.STATUS_WARN,'critical':Colors.STATUS_CRIT}.get(tone,Colors.TEXT_MUTED)
        self.state.setText(text);self.state.setStyleSheet('color:'+color+';font-size:11px;font-weight:600;')
        if detail is not None:self.detail.setText(detail)
