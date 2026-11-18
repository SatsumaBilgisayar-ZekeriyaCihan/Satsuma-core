"""How any page reaches the main window: open another page, use the shared lock, send a request (2.2.47).

Pages used to call window.nav.select('admin') and borrow the old management
page's login token. That page is gone; every page now goes through these
helpers to the one OperatorSession and to MainWindow.open_target.

Herhangi bir sayfanın ana pencereye ulaşma yolu: başka sayfa açmak, ortak kilidi
kullanmak, istek göndermek. Eski yönetim sayfası kaldırıldı.
"""


def main_window(widget):
    """The main window, also while a page is being created before it is placed in the window."""
    node = widget
    while node is not None:
        found = getattr(node, '_main_window', None)
        if found is not None:
            return found
        node = node.parent() if hasattr(node, 'parent') else None
    window = widget.window() if hasattr(widget, 'window') else None
    return window if window is not widget else None


def session(widget):
    from .session import OperatorSession
    value = getattr(main_window(widget), 'session', None)
    return value if isinstance(value, OperatorSession) else None


def open_target(widget, target, context=None):
    window = main_window(widget)
    if window is not None and hasattr(window, 'open_target'):
        window.open_target(target, context or {})


def run(widget, method, params=None, then=None):
    """Send one operator request through the shared lock; False when there is no main window."""
    value = session(widget)
    if value is None:
        return False
    return value.run(method, params or {}, widget, then)


def token(widget):
    value = session(widget)
    return value.token if value is not None else None
