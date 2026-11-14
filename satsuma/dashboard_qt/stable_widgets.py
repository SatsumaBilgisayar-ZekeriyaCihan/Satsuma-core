"""Controls that keep user intent stable during background refresh."""
try:
    from PyQt6.QtWidgets import QComboBox
except ImportError:
    from PyQt5.QtWidgets import QComboBox

class StableComboBox(QComboBox):
    def wheelEvent(self,event):
        event.ignore()

def update_choices(widget,items):
    """Never replace an open popup, or silently select a different request."""
    if widget.view().isVisible():return
    items=list(items)
    before=[(widget.itemText(i),widget.itemData(i)) for i in range(widget.count())]
    if before==items:return
    selected=widget.currentData();widget.blockSignals(True)
    try:
        widget.clear()
        for title,value in items:widget.addItem(title,value)
        index=widget.findData(selected)
        widget.setCurrentIndex(index if index>=0 else -1)
    finally:widget.blockSignals(False)
