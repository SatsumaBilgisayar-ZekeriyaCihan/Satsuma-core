"""Bounded on-access event admission for a trusted journald consumer.

Never infer infection from an arbitrary log line. The candidate clamonacc message grammar is strict and has not been validated
on Fedora. Unrecognized events are ignored and must be reported as such.
"""
from collections import OrderedDict
import os
from pathlib import Path
import re
import time

from .onaccess_quarantine import verify_and_quarantine

# This deliberately strict grammar is an *adapter candidate*, not a claim
# about actual Fedora clamonacc output. Unexpected formats are ignored.
_FINDING = re.compile(r"^Clamonacc: (?P<path>/[^\r\n\x00]{1,4096}): (?P<signature>[^\r\n\x00]{1,256}) FOUND$")
_UNIT = 'satsuma-clamonacc.service'
_EXE = '/usr/bin/clamonacc'


class AdmissionGate:
    """Bounded in-memory replay and burst guard; not a persistence guarantee."""

    def __init__(self, *, max_seen=2048, cooldown=60, max_per_minute=30, clock=time.monotonic):
        self.max_seen = max_seen
        self.cooldown = cooldown
        self.max_per_minute = max_per_minute
        self.clock = clock
        self._seen = OrderedDict()
        self._window_start = clock()
        self._window_count = 0

    def accept(self, item):
        now = self.clock()
        if now - self._window_start >= 60:
            self._window_start, self._window_count = now, 0
        if self._window_count >= self.max_per_minute:
            return False
        old = self._seen.get(item)
        if old is not None and now - old < self.cooldown:
            return False
        self._seen.pop(item, None)
        self._seen[item] = now
        while len(self._seen) > self.max_seen:
            self._seen.popitem(last=False)
        self._window_count += 1
        return True


def candidate_from_trusted_journal_fields(record):
    """Extract a *hint* only; requires trusted fields from journald API.

    The function has no way to prove that a caller did not forge a dict.
    Never expose it to network requests or dashboard inputs. A service should
    read journal records itself and match the trusted fields in the query.
    """
    if not isinstance(record, dict):
        return None
    if (record.get('_SYSTEMD_UNIT') != _UNIT or
            record.get('_EXE') != _EXE or
            str(record.get('_UID')) != '0'):
        return None
    msg = record.get('MESSAGE')
    if not isinstance(msg, str) or len(msg) > 4608:
        return None
    match = _FINDING.fullmatch(msg)
    if not match:
        return None
    path = Path(match['path'])
    if '..' in path.parts or not path.is_absolute():
        return None
    return str(path)


def process_record(record, store, gate, *, scanner=None, mover=None, protected=('/home',)):
    """Run descriptor-bound re-scan only for admitted candidate events.

    The journald consumer is connected for testing. A log verdict is never proof:
    the scan and file-identity checks in verify_and_quarantine still apply.
    """
    path = candidate_from_trusted_journal_fields(record)
    if path is None:
        return {'status': 'ignored', 'reason': 'untrusted or unrecognized event'}
    if not gate.accept(path):
        return {'status': 'deferred', 'reason': 'duplicate or rate limited'}
    kwargs = {'protected': protected}
    if scanner is not None:
        kwargs['scanner'] = scanner
    if mover is not None:
        kwargs['mover'] = mover
    return verify_and_quarantine(path, store, **kwargs)
