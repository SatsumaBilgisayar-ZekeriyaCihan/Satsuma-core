"""Bounded, non-authorizing short-window correlation for Smart Rules.

A hint, not a verdict: only minimal event identifiers are retained. This
module never authorizes process termination or changes a finding's class.
"""
from __future__ import annotations

from collections import OrderedDict, deque
import math
import time


class ShortEvidenceWindow:
    def __init__(self, window_seconds=2.0, max_processes=4096, max_events=16, clock=None):
        if not (0 < window_seconds <= 60 and 0 < max_processes <= 65536 and 0 < max_events <= 256):
            raise ValueError('invalid bounded short evidence configuration')
        self.window_seconds = float(window_seconds)
        self.max_processes = int(max_processes)
        self.max_events = int(max_events)
        self.clock = clock or time.monotonic
        self._groups = OrderedDict()
        self.evictions = 0
        self.rejected = 0

    @staticmethod
    def _identity(event):
        try:
            pid = int(event.get('pid'))
            starttime = int(event.get('starttime'))
            if pid <= 0 or starttime <= 0:
                return None
            return str(pid), str(starttime)
        except (TypeError, ValueError, OverflowError):
            return None

    def observe(self, event):
        """Return a short, bounded evidence snapshot; never an action decision."""
        if not isinstance(event, dict):
            self.rejected += 1
            return None
        key = self._identity(event)
        if key is None:
            self.rejected += 1
            return None
        now = float(self.clock())
        if not math.isfinite(now):
            self.rejected += 1
            return None
        # Expire old groups by last-seen monotonic time, not untrusted event time.
        while self._groups:
            oldest, (last_seen, _) = next(iter(self._groups.items()))
            if now - last_seen <= self.window_seconds:
                break
            self._groups.popitem(last=False)
        if key in self._groups:
            _, events = self._groups.pop(key)
        else:
            events = deque(maxlen=self.max_events)
        while events and now - events[0][0] > self.window_seconds:
            events.popleft()
        event_id = event.get('id')
        source = event.get('source')
        # Never include raw commands, paths, environment values or payloads.
        evidence = {'id': str(event_id)[:96] if isinstance(event_id, (str, int)) else '',
                    'source': str(source)[:64] if isinstance(source, str) else '',
                    'kind': str(event.get('kind') or '')[:64]}
        events.append((now, evidence))
        self._groups[key] = (now, events)
        while len(self._groups) > self.max_processes:
            self._groups.popitem(last=False)
            self.evictions += 1
        return {'pid': key[0], 'starttime': key[1],
                'window_seconds': self.window_seconds,
                'event_count': len(events),
                'independent_sources': len({row['source'] for _, row in events if row['source']}),
                'events': [dict(row) for _, row in events]}

    def health(self):
        return {'groups': len(self._groups), 'evictions': self.evictions, 'rejected': self.rejected,
                'window_seconds': self.window_seconds}
