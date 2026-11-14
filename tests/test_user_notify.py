"""A stopped program is announced on the desktop (2.2.33).

Field 2026-11-04: AnyDesk was stopped and no warning appeared.
Durdurulan program masaüstünde duyurulur.
"""
from pathlib import Path

from satsuma.user_notify import Notifier, message

ROOT = Path(__file__).parents[1]


class Client:
    def __init__(self):
        self.items = []

    def call(self, method, **params):
        assert method == 'stopped_processes'
        return {'items': list(self.items)}


def test_only_new_stops_are_announced_once():
    client, shown = Client(), []
    client.items = [{'record_id': 1, 'pid': 10, 'rule_id': 'OLD'}]
    notifier = Notifier(client, runner=lambda args, **k: shown.append(args))
    assert notifier.tick() == []  # existing records are not announced at start
    client.items = [{'record_id': 2, 'pid': 253592, 'rule_id': 'SATSUMA-AI-PERSIST-MEMFD-EXEC',
                     'exe': '/home/u/İndirilenler/anydesk-8.1.0/anydesk (deleted)'}] + client.items
    assert notifier.tick() == ['anydesk (PID 253592) · SATSUMA-AI-PERSIST-MEMFD-EXEC']
    assert notifier.tick() == []
    assert shown[0][:2] == ['/usr/bin/notify-send', '-a'] and 'critical' in shown[0]


def test_program_name_falls_back_to_pid():
    assert message({'pid': 5})[1] == 'PID 5 · kural'


def test_notifier_starts_in_the_desktop_session():
    entry = (ROOT / 'packaging/root/etc/xdg/autostart/satsuma-notify.desktop').read_text()
    assert 'Exec=/usr/bin/satsuma-notify' in entry
    launcher = (ROOT / 'packaging/root/usr/bin/satsuma-notify').read_text()
    assert '-m satsuma.user_notify' in launcher and 'id -u' in launcher
    assert '/etc/xdg/autostart/satsuma-notify.desktop' in (ROOT / 'packaging/satsuma-core.spec').read_text()
