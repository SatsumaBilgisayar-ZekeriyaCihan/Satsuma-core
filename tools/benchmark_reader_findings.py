"""Measure legacy finding queries with synthetic SQLite databases outside the repo.

Run from the checkout: PYTHONPATH=. python tools/benchmark_reader_findings.py
Each measured query uses a fresh process, so peak RSS excludes fixture creation.
"""
import argparse
import json
from pathlib import Path
import resource
import sqlite3
import subprocess
import sys
import tempfile
import time


def measure(folder, rule, offset):
    from satsuma import dashboard_api as api
    api.DB_PATH = str(folder / 'core.db')
    api.HOST_DB_PATH = str(folder / 'host.db')
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    start = time.perf_counter()
    result = api.m_findings(rule_id=rule, limit=250, offset=offset)
    print(json.dumps({'rule': rule, 'offset': offset,
                      'seconds': round(time.perf_counter() - start, 3),
                      'total': result['total_count'], 'matched': result['filtered_count'],
                      'shown': result['shown_count'], 'state': result['data_state'],
                      'initial_peak_rss_KiB': before,
                      'peak_rss_KiB': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
    if result['data_state'] != 'OK' or result['shown_count'] != (1 if rule == 'OLD' else 250):
        raise RuntimeError('functional benchmark failed: ' + str(result.get('error')))


def prepare(folder, count):
    with sqlite3.connect(folder / 'core.db') as db:
        db.execute('CREATE TABLE records(id INTEGER PRIMARY KEY,kind TEXT,created REAL,body TEXT)')
        db.execute('CREATE INDEX records_kind ON records(kind,id)')
        db.executemany('INSERT INTO records(kind,created,body) VALUES(?,?,?)',
                       (('events', i, '{"event":{"category":"activity"}}') for i in range(100000)))
    with sqlite3.connect(folder / 'host.db') as db:
        db.execute('CREATE TABLE findings(finding_id TEXT PRIMARY KEY,last_seen REAL,body TEXT)')
        db.executemany('INSERT INTO findings VALUES(?,?,?)',
                       ((f'f-{i:08}', i, json.dumps({'last_seen': i, 'severity': 'high',
                         'rule_id': 'OLD' if i == 1 else 'NEW'})) for i in range(count)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path)
    parser.add_argument('--rule', default='OLD')
    parser.add_argument('--offset', type=int, default=0)
    args = parser.parse_args()
    if args.worker:
        measure(args.worker, args.rule, args.offset)
        return
    for count in (12903, 129030):
        with tempfile.TemporaryDirectory(prefix='satsuma-reader-benchmark-') as tmp:
            folder = Path(tmp)
            prepare(folder, count)
            for rule, offset in (('OLD', 0), ('NEW', count - 903)):
                subprocess.run([sys.executable, str(Path(__file__).resolve()), '--worker', tmp,
                                '--rule', rule, '--offset', str(offset)], check=True)


if __name__ == '__main__':
    main()
