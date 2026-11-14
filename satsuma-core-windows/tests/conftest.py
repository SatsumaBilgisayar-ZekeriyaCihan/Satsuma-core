"""satsuma_win from this folder, satsuma (shared rules) from the repository root.

satsuma_win bu klasörden, satsuma (ortak kurallar) depo kökünden alınır.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(HERE), str(HERE.parent)]


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def no_real_memory_scanner(monkeypatch):
    """A test never runs the real memory scanner: on Windows it would stop real processes of the test machine.

    Bir test gerçek bellek tarayıcısını asla çalıştırmaz: Windows'ta test makinesinin gerçek süreçlerini durdururdu.
    Tests that need one pass their own memory_factory; the live Win32 test builds its reader itself.
    """
    from contextlib import contextmanager
    from satsuma import memory_decision
    from satsuma_win import guard, machine_key, memory

    class Empty:
        def pids(self):
            return []

        @contextmanager
        def open(self, pid):
            yield None
    rules = memory_decision.load_rules()

    class NoSignatures:
        """Never downloads ClamAV or starts clamd in a test. Testte ClamAV indirilmez, clamd başlatılmaz."""
        enforce = True

        def start(self):
            return self

        def drain(self):
            return []

        def health(self):
            return {'state': 'TEST'}

        def close(self):
            pass
    monkeypatch.setattr(guard, 'default_signature_monitor', lambda directory=None, enforce=True: NoSignatures())
    monkeypatch.setattr(guard, 'default_memory_scanner',
                        lambda record, directory=None, key=None, enforce=True: memory.Scanner(rules, Empty(), record))
    real_ensure = machine_key.ensure
    reverse = lambda b: b[::-1]
    monkeypatch.setattr(machine_key, 'ensure', lambda directory, protect=reverse, unprotect=reverse: real_ensure(
        directory, protect=protect, unprotect=unprotect))

    class NoSysmon:
        def read(self):
            return []
    monkeypatch.setattr(guard, 'default_sysmon_reader', lambda: NoSysmon())

    class NoGateway:
        counts = {}
        def load(self):
            return None
        def approve_now(self):
            return {'gateway': '192.168.1.1', 'mac': 'aa-bb-cc-dd-ee-ff', 'interface': '192.168.1.5'}
        def check(self):
            return []
    monkeypatch.setattr(guard, 'default_gateway', lambda *a: NoGateway())

    class NoAccounts:
        def enforce(self):
            return {'ok': True, 'status': 'LOCKED', 'owner': 'S-1-5-21-1-2-3-1001', 'disabled': []}
    monkeypatch.setattr(guard, 'default_accounts', lambda *a: NoAccounts())

    class NoDevices:
        def check(self):
            return []
    monkeypatch.setattr(guard, 'default_devices', lambda *a: NoDevices())
    monkeypatch.setattr(guard, 'default_sysmon_installer', lambda: {'ok': False, 'status': 'TEST'})
