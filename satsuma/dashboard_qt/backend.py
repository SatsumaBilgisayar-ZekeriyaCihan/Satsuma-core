# -*- coding: utf-8 -*-
"""Satsuma Core Qt dashboard backend bridge.

The dashboard does not open core.db directly. Data is obtained through the
root-owned Unix socket reader service.
"""
try:
    from satsuma.dashboard import (
        readable as tui_readable,
        policy_lines as tui_policy_lines,
        MODULES as TUI_MODULES,
        _system_metrics as tui_system_metrics,
        _net_bytes as tui_net_bytes,
        _forward_dns as tui_forward_dns,
    )
    TUI_AVAILABLE = True
except ImportError as e:
    print(f'[backend] TUI helpers yuklenemedi: {e}')
    TUI_AVAILABLE = False
    tui_readable = tui_policy_lines = None
    tui_system_metrics = tui_net_bytes = tui_forward_dns = None
    TUI_MODULES = []

try:
    from satsuma.dashboard_api_client import ReaderClient
    SOCKET_AVAILABLE = True
except ImportError as e:
    print(f'[backend] ReaderClient yuklenemedi: {e}')
    SOCKET_AVAILABLE = False
    ReaderClient = None


try:
    from PyQt6.QtCore import QObject, pyqtSignal
except ImportError:
    from PyQt5.QtCore import QObject, pyqtSignal
from .async_reader import AsyncReader


class ReaderUpdates(QObject):
    updated = pyqtSignal()


class Backend:
    """Reader socket bridge. core.db is never opened by the GUI."""

    def __init__(self):
        self.updates = ReaderUpdates()
        self.client = AsyncReader(ReaderClient(), self.updates.updated.emit) if SOCKET_AVAILABLE else None
        # Independent bounded queue: historical queries cannot block RAM health.
        self.health_client = AsyncReader(ReaderClient(), self.updates.updated.emit, capacity=4) if SOCKET_AVAILABLE else None
        self.db_path = 'reader:///run/satsuma-reader/reader.sock'

    def connect(self):
        if not self.client:
            raise ConnectionError('reader socket istemcisi yok')
        if not self.client.ping():
            raise ConnectionError('reader socket yanit vermiyor')
        return True

    def close(self):
        if self.client:
            self.client.close()
        if self.health_client:
            self.health_client.close()

    def is_connected(self):
        if not self.client:
            return False
        try:
            return self.client.ping()
        except Exception:
            return False

    def ensure_connected(self):
        if not self.is_connected():
            raise ConnectionError(
                'reader socket erisilemiyor '
                '(systemctl status satsuma-reader.service)'
            )

    def state(self, key, default=None):
        if not self.client:
            return default
        try:
            r = self.client.call('state', key=key, default=default)
            return r if r is not None else default
        except Exception as e:
            print(f'[backend.state:{key}] {e}')
            return default

    def rows(self, kind, limit=8):
        if not self.client:
            return []
        try:
            return self.client.call('rows', kind=kind, limit=limit) or []
        except Exception as e:
            print(f'[backend.rows:{kind}] {e}')
            return []

    def health(self):
        if not self.client:
            return {}
        try:
            return self.client.call('health') or {}
        except Exception as e:
            print(f'[backend.health] {e}')
            return {}

    def tickets(self, limit=50, status=None):
        if not self.client:
            return []
        try:
            return self.client.call('tickets', limit=limit, status=status) or []
        except Exception as e:
            print(f'[backend.tickets] {e}')
            return []

    def tickets_stats(self):
        empty = {'total': 0, 'by_status': {}, 'by_level': {}}
        if not self.client:
            return empty
        try:
            raw = self.client.call('tickets_stats') or empty
            by_status = {
                str(k): int(v or 0)
                for k, v in (raw.get('by_status') or {}).items()
            }
            # JSON object keys arrive as strings. Normalize them here so all
            # panels can safely use integer level keys.
            by_level = {}
            for k, v in (raw.get('by_level') or {}).items():
                try:
                    by_level[int(k)] = int(v or 0)
                except (TypeError, ValueError):
                    continue
            return {
                'total': int(raw.get('total') or sum(by_status.values())),
                'by_status': by_status,
                'by_level': by_level,
            }
        except Exception as e:
            print(f'[backend.tickets_stats] {e}')
            return empty

    def workers(self):
        if not self.client:
            return {}
        try:
            return self.client.call('workers') or {}
        except Exception as e:
            print(f'[backend.workers] {e}')
            return {}

    def teams(self):
        if not self.client:
            return {}
        try:
            return self.client.call('teams') or {}
        except Exception as e:
            print(f'[backend.teams] {e}')
            return {}

    def call(self, method, **params):
        """Generic read-only reader RPC."""
        if not self.client:
            raise ConnectionError('reader socket istemcisi yok')
        client = self.health_client if method == 'memory_health' else self.client
        return client.call(method, **params)

    def overview(self):
        return self.call('overview') or {}

    def findings(self, **filters):
        return self.call('findings', **filters) or {'items': [], 'data_state': 'UNKNOWN'}

    def finding(self, finding_id, record_key=None):
        return self.call('finding', finding_id=finding_id, record_key=record_key) or {'available': False}

    def dns(self, limit=500):
        return self.call('dns', limit=limit) or {'items': [], 'data_state': 'UNKNOWN'}

    def dns_summary(self, limit=5000):
        return self.call('dns_summary', limit=limit) or {}

    def otx(self):
        return self.call('otx') or {'status': 'UNKNOWN'}

    def services(self):
        return self.call('services') or {'items': [], 'data_state': 'UNKNOWN'}

    def rules(self):
        return self.call('rules') or {'rules': [], 'future': []}


    def audit(self, limit=50):
        return self.call('audit', limit=limit) or {}

    def suricata(self, limit=100):
        return self.call('suricata', limit=limit) or {}

    def response(self, limit=100):
        return self.call('response', limit=limit) or {}

    def network(self, limit=100):
        return self.call('network', limit=limit) or {}

    def integrity(self):
        return self.call('integrity') or {}

    def system_health(self):
        return self.call('system_health') or {}

    def ticket_detail(self, ticket_id):
        return self.call('ticket_detail', ticket_id=ticket_id) or {}

    # Reader servisi read-only'dir. Operator yazma kanali ayri bir
    # socket olarak gelene kadar ticket aksiyonlari fail-closed kalir.
    def ticket_actions_available(self):
        return False

    def update_ticket_status(self, ticket_id, status, note=''):
        return {
            'ok': False,
            'error': 'reader API read-only; operator yazma kanali yok',
        }

    def readable(self, kind, item):
        if not TUI_AVAILABLE:
            return [('Veri', str(item))]
        try:
            return tui_readable(kind, item)
        except Exception as e:
            print(f'[backend.readable:{kind}] {e}')
            return [('Veri', str(item))]

    def policy_lines(self, policy):
        if not TUI_AVAILABLE:
            return [('Politika', 'TUI yuklenemedi')]
        try:
            return tui_policy_lines(policy)
        except Exception as e:
            print(f'[backend.policy_lines] {e}')
            return [('Hata', str(e))]

    def system_metrics(self):
        if TUI_AVAILABLE:
            try:
                return tui_system_metrics()
            except Exception as e:
                print(f'[backend.system_metrics] {e}')
        return (0, 0, 0)

    def net_bytes(self):
        if TUI_AVAILABLE:
            try:
                return tui_net_bytes()
            except Exception as e:
                print(f'[backend.net_bytes] {e}')
        return 0

    def forward_dns(self, dns_rows):
        if TUI_AVAILABLE:
            try:
                return tui_forward_dns(dns_rows)
            except Exception as e:
                print(f'[backend.forward_dns] {e}')
        return list(dns_rows or [])

    def version(self):
        return self.health().get('version', '-')

    def modules(self):
        return list(TUI_MODULES)

    def db_exists(self):
        return True
