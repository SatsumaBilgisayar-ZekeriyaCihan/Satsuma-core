"""Flow guard: a separate watcher that makes sure the event flow keeps flowing.

User request 2026-11-04: raw events are no longer written anywhere, so a
stalled flow would be a blind spot; a separate guard watches it. Every five
seconds it reads the rule engine's flow health and the collectors' sender
counters and acts on:

- engine silent: the rule engine has not reported for 30 seconds, or its
  socket is gone -> satsuma-teams is restarted (at most once in 5 minutes);
- flow silent: nothing arrived for 60 seconds while Satsuma's process
  watcher runs (it always produces events) -> reported, engine restarted;
- loss: datagrams that could not be sent, or a full engine queue -> reported.

Like the flow itself, it writes only when something is wrong: one
'flow_guard' record per problem (repeated at most once a minute) and its
own health state.

Akış bekçisi: olay akışının akmaya devam ettiğini denetleyen ayrı izleyici.
Kullanıcı isteği 2026-11-04: ham olaylar artık hiçbir yere yazılmıyor, duran
bir akış kör nokta olurdu; onu ayrı bir bekçi izler. Beş saniyede bir kural
motorunun akış sağlığını ve toplayıcıların gönderim sayaçlarını okur: motor
30 saniyedir susarsa ya da soketi yoksa satsuma-teams yeniden başlatılır (5
dakikada en çok bir kez); süreç izleyicisi çalışırken 60 saniye hiç olay
gelmezse bildirilir ve motor yeniden başlatılır; gönderilemeyen datagram ya da
dolu kuyruk bildirilir. Akışın kendisi gibi yalnızca bir sorun olduğunda
yazar.
"""
import subprocess
import time

ENGINE_STALE = 30
FLOW_SILENT = 60
RESTART_GAP = 300
REPORT_GAP = 60


class FlowGuard:
    def __init__(self, store, runner=subprocess.run, clock=time.time, socket_path=None):
        from .flow import SOCKET
        self.store, self.runner, self.clock = store, runner, clock
        self.socket = socket_path or SOCKET
        self.last_received = None
        self.last_progress = clock()
        self.last_counts = {}
        self.last_restart = -RESTART_GAP
        self.last_report = {}

    def _report(self, code, detail):
        now = self.clock()
        if now - self.last_report.get(code, -REPORT_GAP) < REPORT_GAP:
            return False
        self.last_report[code] = now
        self.store.add('flow_guard', {'timestamp': now, 'code': code, 'detail': detail})
        return True

    def _restart_engine(self, reason):
        now = self.clock()
        if now - self.last_restart < RESTART_GAP:
            return False
        from .repair_budget import claim
        granted, why = claim(['satsuma-teams.service'], 'flow-guard', ledger=getattr(self, 'ledger', None))
        if not granted:
            self.store.add('flow_guard', {'timestamp': now, 'code': 'engine_restart_deferred', 'detail': why})
            return False
        self.last_restart = now
        result = self.runner(['/usr/bin/systemctl', 'restart', 'satsuma-teams.service'],
                             capture_output=True, text=True, timeout=60)
        self.store.add('flow_guard', {'timestamp': now, 'code': 'engine_restarted', 'detail': reason,
                                      'ok': result.returncode == 0})
        return True

    def check(self):
        now = self.clock()
        problems = []
        engine = self.store.get('flow.health', {}) or {}
        core = (self.store.get('health', {}) or {}).get('flow') or {}
        age = now - float(engine.get('updated_at') or 0)
        from pathlib import Path
        socket_ok = Path(self.socket).exists()
        if age > ENGINE_STALE or not socket_ok:
            reason = 'akış motoru ' + (str(int(age)) + ' sn sessiz' if age > ENGINE_STALE else 'soketi yok')
            problems.append('engine_silent')
            self._report('engine_silent', reason)
            self._restart_engine(reason)
        receiver = engine.get('receiver') or {}
        received = receiver.get('received')
        if received is not None:
            if self.last_received is None or received != self.last_received:
                self.last_progress = now
            self.last_received = received
            if now - self.last_progress > FLOW_SILENT and age <= ENGINE_STALE:
                problems.append('flow_silent')
                self._report('flow_silent', f'{int(now - self.last_progress)} sn hiç olay gelmedi')
                self._restart_engine('akış sessiz')
        for name, value in (('receiver_dropped', receiver.get('dropped')), ('sender_failed', core.get('failed')),
                            ('sender_dropped', core.get('dropped'))):
            if value is None:
                continue
            previous = self.last_counts.get(name, value)
            self.last_counts[name] = value
            if value > previous:
                problems.append(name)
                self._report(name, f'{value - previous} olay kayboldu')
        status = {'updated_at': now, 'status': 'DEGRADED' if problems else 'RUNNING', 'problems': problems,
                  'engine_age_seconds': round(age, 1), 'received': received}
        self.store.set('flow_guard.health', status)
        return status


def main():
    from .store import Store
    store = Store()
    guard = FlowGuard(store)
    try:
        while True:
            try:
                guard.check()
            except Exception as exc:
                store.set('flow_guard.health', {'updated_at': time.time(), 'status': 'ERROR', 'error': str(exc)[:300]})
            time.sleep(5)
    finally:
        store.close()


if __name__ == '__main__':
    raise SystemExit(main())
