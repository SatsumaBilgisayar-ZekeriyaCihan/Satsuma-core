"""Desktop notification when Satsuma stops a program.

Field 2026-11-04: AnyDesk could not be opened and no warning appeared.
Satsuma's services run as root outside the desktop session, so their
notify-send never reached the screen. This notifier runs in the user's
own session (started from /etc/xdg/autostart), reads the reader socket
the dashboard already uses, and shows one notification for each newly
stopped program. It never acts; it only
reads. Records that existed when it started are not announced again.

Satsuma bir programı durdurduğunda masaüstü bildirimi. Saha 2026-11-04: AnyDesk açılmadı ve hiçbir uyarı görünmedi.
Satsuma servisleri masaüstü oturumunun dışında root olarak çalışır;
notify-send çağrıları ekrana hiç ulaşmıyordu. Bu bildirici kullanıcının kendi
oturumunda (/etc/xdg/autostart ile) çalışır, panelin kullandığı okuyucu
soketini okur; her yeni durdurulan program için bir bildirim gösterir. Hiçbir işlem yapmaz, yalnızca okur.
Başladığında var olan kayıtları yeniden duyurmaz.
"""
import os
import subprocess
import time

INTERVAL = 3.0


def _program(row):
    evidence = row.get('evidence') if isinstance(row.get('evidence'), dict) else {}
    for key in ('exe', 'executable', 'process_exe'):
        value = row.get(key) or evidence.get(key)
        if value:
            return os.path.basename(str(value).removesuffix(' (deleted)')) or str(value)
    return None


def message(row):
    """(title, body, urgency) for one stopped-process row."""
    rule = str(row.get('rule_id') or 'kural')
    name, pid = _program(row), row.get('pid', '?')
    target = f'{name} (PID {pid})' if name else f'PID {pid}'
    return ('Satsuma bir programı durdurdu', f'{target} · {rule}', 'critical')


class Notifier:
    def __init__(self, client, runner=subprocess.run):
        self.client, self.runner = client, runner
        self.seen = None

    def _rows(self):
        data = self.client.call('stopped_processes', offset=0, limit=20)
        return [row for row in data.get('items', []) if isinstance(row, dict)]

    def tick(self):
        rows = self._rows()
        keys = {str(row.get('record_id')) for row in rows}
        if self.seen is None:
            self.seen = keys
            return []
        shown = []
        for row in reversed(rows):
            key = str(row.get('record_id'))
            if key in self.seen:
                continue
            self.seen.add(key)
            title, body, urgency = message(row)
            self.runner(['/usr/bin/notify-send', '-a', 'Satsuma', '-u', urgency, '-i', 'security-high', title, body],
                        capture_output=True, timeout=5)
            shown.append(body)
        if len(self.seen) > 1000:
            self.seen = keys
        return shown


def main():
    if os.geteuid() == 0:
        return 0
    from .dashboard_api_client import ReaderClient
    notifier = Notifier(ReaderClient())
    while True:
        try:
            notifier.tick()
        except Exception:
            pass  # reader restarting or not yet enrolled; try again
        time.sleep(INTERVAL)


if __name__ == '__main__':
    raise SystemExit(main())
