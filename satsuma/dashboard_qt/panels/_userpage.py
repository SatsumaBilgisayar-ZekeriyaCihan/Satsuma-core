"""Base of the 2.2.45 user pages: reader data in, operator actions out through the shared lock.

2.2.45 kullanıcı sayfalarının temeli: okuyucudan veri, ortak kilit üzerinden işlem.
"""
from copy import deepcopy

from .base import BasePanel
from ..ui import Page


class UserPage(BasePanel):
    PAGE_TITLE = ''
    PAGE_SUBTITLE = ''
    PANEL_GROUP = 'user'
    REFRESH_MS = 5000

    def _build(self):
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)
        self.page = Page(self.PAGE_TITLE, self.PAGE_SUBTITLE)
        self._layout.addWidget(self.page)
        self._last = {}
        self.build(self.page.content)

    def build(self, content):
        raise NotImplementedError

    # -- data
    def fetch(self, method, **params):
        """(data, None) or (None, reason). The first call of a method returns 'loading'."""
        try:
            data = self.backend.call(method, **params)
        except ConnectionError as exc:
            text = str(exc)
            return None, ('loading' if 'arka planda' in text else text)
        except Exception as exc:
            return None, str(exc)
        return (data if data is not None else {}), None

    def changed(self, key, data):
        """True only when ``data`` differs from what was last drawn under ``key``."""
        if self._last.get(key) == data:
            return False
        self._last[key] = deepcopy(data)
        return True

    # -- window services
    def main_window(self):
        from ..links import main_window
        return main_window(self)

    def session(self):
        from ..links import session
        return session(self)

    def act(self, action, refresh=True):
        """Run an action dict from the view model: {'method', 'params'} or {'open': target}."""
        if action.get('open'):
            self.open(action['open'], action)
            return
        session = self.session()
        if session is None:
            return
        session.run(action['method'], action.get('params') or {}, self,
                    then=(lambda *args: self.reload()) if refresh else None)

    def open(self, target, context=None):
        window = self.main_window()
        if hasattr(window, 'open_target'):
            window.open_target(target, context or {})

    def reload(self):
        client = getattr(self.backend, 'client', None)
        if hasattr(client, 'invalidate'):
            client.invalidate()
        self._last = {}
        self.refresh()
