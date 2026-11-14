"""Local, bounded journald consumer for ClamAV on-access events.

No textual path is sufficient evidence of infection. Journal records are read
from journalctl, then re-scanned descriptor-bound before quarantine. The
Clamonacc message grammar remains a strict candidate until Fedora validation.
"""
import json
import os
import subprocess
import sys
import time
from .onaccess_events import AdmissionGate, process_record
from .protected_storage import RootDataStore

MAX_RECORD = 12288
EXPECTED_COMMAND = ('/usr/bin/journalctl', '--no-pager', '--follow', '--lines=0',
                    '--output=json', '--unit=satsuma-clamonacc.service')

class AuditStore:
    def add(self, key, value):
        if key not in ('quarantine_actions', 'onaccess_rescan'):
            raise ValueError('Invalid audit stream')
        RootDataStore('onaccess/' + key + '.jsonl').append(value)

def fresh_journal_record(record, *, now=None):
    """Require recent journal metadata; never act on old/replayed records."""
    if not isinstance(record, dict):
        return False
    try:
        stamp = int(record.get('__REALTIME_TIMESTAMP', '0'))
        current = time.time() if now is None else now
        return stamp > 0 and 0 <= current - stamp / 1_000_000 <= 30
    except (ValueError, TypeError, OverflowError):
        return False

def process_json_line(line, store, gate, *, now=None, scanner=None, mover=None, protected=('/home',)):
    if not isinstance(line, (bytes, str)) or len(line) > MAX_RECORD:
        return {'status':'ignored','reason':'oversize journal record'}
    try:
        record=json.loads(line)
    except (ValueError, UnicodeDecodeError, TypeError):
        return {'status':'ignored','reason':'malformed journal record'}
    if not fresh_journal_record(record, now=now):
        return {'status':'ignored','reason':'stale journal record'}
    return process_record(record, store, gate, scanner=scanner, mover=mover, protected=protected)

def main():
    if os.geteuid() != 0:
        return 78
    gate=AdmissionGate(); store=AuditStore()
    # No shell, no external event ingestion, no journal replay.
    with subprocess.Popen(EXPECTED_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          bufsize=0, close_fds=True) as proc:
        for line in proc.stdout:
            outcome=process_json_line(line,store,gate)
            if outcome['status'] not in ('ignored','deferred'):
                print(json.dumps({'status':outcome['status']}, ensure_ascii=False),flush=True)
        return proc.wait() or 1  # exiting a listener is never a healthy state

if __name__ == '__main__':
    sys.exit(main())
