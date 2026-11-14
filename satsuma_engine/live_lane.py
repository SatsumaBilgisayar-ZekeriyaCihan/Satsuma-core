"""Bounded, non-authoritative live evidence lane for the second Satsuma engine.

The caller never waits for correlation. This lane never issues commands, passes
findings to an action broker, or authorizes a destructive action. Overflow and
failures remain visible through health counters; a healthy state is not implied
by an empty output queue.
"""
from __future__ import annotations

import hashlib
import json
import queue
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from .engine import Engine
from .rule_model import load_rules
from .review_evidence import build_review_evidence


class DeepEvidenceLane:
    def __init__(self, rules, *, input_limit=256, output_limit=128, window=48,
                 batch=8, max_age_seconds=30, engine_factory=Engine, test_rules=()):
        if min(input_limit, output_limit, window, batch) < 1:
            raise ValueError('queue/window/batch sizes must be positive')
        self._input = queue.Queue(maxsize=input_limit)
        self._output = queue.Queue(maxsize=output_limit)
        self._window = deque(maxlen=window)
        self._batch = batch
        self._max_age = float(max_age_seconds)
        self._engine_factory = engine_factory
        self._rules = list(rules)
        self._test_rules = list(test_rules)
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._stats = {'accepted': 0, 'input_dropped': 0, 'output_dropped': 0,
                       'processed': 0, 'scans': 0, 'errors': 0, 'emitted': 0}
        self._last_error = None
        self._seen = set()
        self._seen_order = deque(maxlen=4096)

    @classmethod
    def from_bundled_rules(cls, **kwargs):
        location = Path(__file__).resolve().parent / 'rules'
        report = load_rules([location], strict=True)
        if not report.rules:
            raise ValueError('no valid deep-engine rules')
        # Rules under rules_test are loaded into an isolated, non-enforcing lane.
        # They are not part of the ordinary rule catalogue.
        test_path = Path(__file__).resolve().parent / 'rules_test'
        tests = load_rules([test_path], strict=True) if test_path.exists() else None
        return cls(report.rules, test_rules=tests.rules if tests else (), **kwargs)

    def start(self):
        if self._thread is not None:
            raise RuntimeError('lane already started')
        self._thread = threading.Thread(target=self._run, name='satsuma-deep-evidence', daemon=True)
        self._thread.start()
        return self

    def submit(self, event: dict[str, Any]) -> bool:
        """Non-blocking, bounded copy; never retains arbitrary metadata/env."""
        if self._stop.is_set() or not isinstance(event, dict):
            return False
        allowed = ('id', 'timestamp', 'source', 'kind', 'action', 'category', 'pid',
                   'starttime', 'boot_id', 'uid', 'ppid', 'cmd', 'exe', 'parent_cmd',
                   'file_path', 'path', 'operation', 'lab_test_mode', 'src_ip', 'dest_ip', 'src_port',
                   'dest_port', 'proto', 'file_sha256')
        compact = {key: value for key, value in event.items()
                   if key in allowed and isinstance(value, (str, int, float, bool))}
        compact = {key: value[:512] if isinstance(value, str) else value
                   for key, value in compact.items()}
        identity = compact.get('id')
        if identity is None:
            with self._lock:
                self._stats['input_dropped'] += 1
            return False
        lab_mode = compact.pop('lab_test_mode', False) is True
        envelope = {'lab_test_mode': lab_mode, 'id': str(identity)[:128], 'source': str(compact.get('source') or 'unknown')[:128],
                    'event': compact}
        try:
            self._input.put_nowait((time.monotonic(), envelope))
        except queue.Full:
            with self._lock:
                self._stats['input_dropped'] += 1
            return False
        with self._lock:
            self._stats['accepted'] += 1
        return True

    def _run(self):
        pending = 0
        while not self._stop.is_set():
            try:
                stamp, event = self._input.get(timeout=0.2)
            except queue.Empty:
                if pending:
                    self._scan()
                    pending = 0
                continue
            self._window.append((stamp, event))
            pending += 1
            with self._lock:
                self._stats['processed'] += 1
            if pending >= self._batch:
                self._scan()
                pending = 0

    def _scan(self):
        cutoff = time.monotonic() - self._max_age
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()
        if not self._window:
            return
        try:
            # Never mix lab-only findings with baseline scans. A lab flag on
            # one event must not enable evaluation for unrelated events.
            baseline = [(i, ev) for i, (_, ev) in enumerate(self._window, 1)]
            lab = [(i, ev) for i, (_, ev) in enumerate(self._window, 1)
                   if ev.get('lab_test_mode') is True]
            scans = [(self._rules, baseline, False)]
            if self._test_rules and lab:
                scans.append((self._test_rules, lab, True))
            for rules, events, test_rule in scans:
                engine = self._engine_factory(rules)
                result = engine.scan(events)
                with self._lock:
                    self._stats['scans'] += 1
                for record in result.reported:
                    raw = record.finding
                    fingerprint = str(raw.get('finding_id') or '')
                    dedup_id = ('lab:' if test_rule else 'base:') + fingerprint
                    if not fingerprint or dedup_id in self._seen:
                        continue
                    # A user-review request is never a capability or command.
                    if test_rule:
                        evidence = build_review_evidence(raw, window_events=len(events))
                    else:
                        evidence = {'finding_id': fingerprint[:128],
                                    'rule_id': str(raw.get('rule_id') or '')[:128],
                                    'severity': str(raw.get('severity') or 'unknown')[:20],
                                    'evidence_type': 'deep_engine_observation',
                                    'authorization': 'none', 'test_rule': False,
                                    'review_required': False, 'window_events': len(events)}
                    try:
                        self._output.put_nowait(evidence)
                    except queue.Full:
                        with self._lock:
                            self._stats['output_dropped'] += 1
                        continue
                    if len(self._seen_order) == self._seen_order.maxlen:
                        self._seen.discard(self._seen_order.popleft())
                    self._seen_order.append(dedup_id)
                    self._seen.add(dedup_id)
                    with self._lock:
                        self._stats['emitted'] += 1
        except Exception as exc:
            with self._lock:
                self._stats['errors'] += 1
                self._last_error = type(exc).__name__

    def drain(self, limit=8):
        items = []
        for _ in range(max(0, min(int(limit), 64))):
            try:
                items.append(self._output.get_nowait())
            except queue.Empty:
                break
        return items

    def health(self):
        with self._lock:
            counters = self._stats.copy()
            error = self._last_error
        return {'running': bool(self._thread and self._thread.is_alive()),
                'input_queue': self._input.qsize(), 'output_queue': self._output.qsize(),
                'rules': len(self._rules), 'lab_rules': len(self._test_rules), 'last_error_type': error, **counters}

    def close(self, timeout=1.0):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
