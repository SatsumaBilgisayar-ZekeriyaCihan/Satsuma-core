"""Continuously consume D-Bus headers; bounded queue and explicit coverage loss.

The monitor is read without pause, so the system bus is never backpressured.
When the bounded queue is full, further headers are dropped and counted
instead of ending the subscription (field log 2026-10-25: a burst cut
coverage entirely and discarded the whole tick). Each capture takes the
whole queue; ``take_dropped`` reports the loss, which the worker shows as
DEGRADED. A missing dbus-monitor is reported with its reason (dbus-tools,
2.2.31).

D-Bus başlıkları kesintisiz okunur; sistem veri yolu hiç bekletilmez. Sınırlı
kuyruk dolunca fazla başlıklar abonelik kesilmeden sayılarak düşürülür
(2026-10-25 saha kaydı: bir patlama izlemeyi tamamen kesip bütün turu
atıyordu). Her alım kuyruğun tamamını alır; ``take_dropped`` kaybı bildirir,
işçi bunu DEGRADED olarak gösterir. dbus-monitor kurulu değilse işçi bunu
nedeniyle söyler (dbus-tools paketi, 2.2.31).
"""
from collections import deque
import os
import subprocess
import threading
import time

QUEUE_LIMIT = 2048


class DbusStream:
    def __init__(self, popen=subprocess.Popen):
        if popen is subprocess.Popen and not os.path.exists('/usr/bin/dbus-monitor'):
            # Field 2026-11-04: the tool was not a dependency; say so instead of failing silently.
            raise RuntimeError('dbus-monitor yok: dbus-tools paketi gerekli (sudo dnf install dbus-tools)')
        self.process=popen(['/usr/bin/dbus-monitor','--system'],stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL,env={'PATH':'/usr/sbin:/usr/bin','LC_ALL':'C'})
        self.queue=deque();self.pending=[];self.lock=threading.Lock();self.error=None
        self.space=threading.Condition(self.lock)
        self.backpressure_events=0
        self.dropped=0;self.closed=False
        self.thread=threading.Thread(target=self._read,daemon=True,name='satsuma-dbus-headers')
        self.thread.start()

    def _read(self):
        try:
            while not self.closed:
                line=self.process.stdout.readline(8193)
                if not line:break
                if len(line)>8192:
                    raise ValueError('D-Bus header/body line exceeds bound')
                # Arguments may contain secrets. Only public message headers enter the queue.
                if line.startswith((b'signal ',b'method call ')):
                    header=line.decode('utf-8','replace').strip()
                    with self.space:
                        # Never backpressure the system bus: a blocked monitor
                        # can exhaust the shared root UID quota and disconnect
                        # logind, PID 1 and the desktop. Keep reading; drop and
                        # count what does not fit, never end the subscription.
                        if self.closed:break
                        if len(self.queue)>=QUEUE_LIMIT:
                            if not self.dropped:self.backpressure_events+=1
                            self.dropped+=1
                            continue
                        self.queue.append(header)
            if not self.closed:self.error='D-Bus stream ended; coverage interrupted'
        except (OSError,ValueError) as exc:
            self.error=str(exc)
        finally:
            if self.error and not self.closed and self.process.poll() is None:
                try:self.process.terminate()
                except ProcessLookupError:pass

    def capture(self, duration=0):
        # Initial startup has a small grace period to observe immediate permission failures.
        if duration:time.sleep(min(float(duration),0.1))
        if self.error or self.process.poll() is not None:
            raise RuntimeError(self.error or 'D-Bus monitor exited')
        with self.space:
            if not self.pending:
                self.pending=[self.queue.popleft() for _ in range(len(self.queue))]
                self.space.notify_all()
            return '\n'.join(self.pending)

    def take_dropped(self):
        """Headers lost since the last call (0 means full coverage)."""
        with self.lock:
            dropped,self.dropped=self.dropped,0
        return dropped

    def commit(self):
        self.pending=[]

    def close(self):
        with self.space:
            self.closed=True
            self.space.notify_all()
        if self.process.poll() is None:self.process.terminate()
        try:self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=3)
        self.thread.join(timeout=3)
        self.process.stdout.close()
