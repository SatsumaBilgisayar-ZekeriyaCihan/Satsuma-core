"""Optional, file-only OPNsense advisory collector.

This process NEVER connects to the OPNsense API, runs nft, or applies blocks.
Enable the accompanying systemd unit only after a separate trusted syslog
receiver is configured to write /var/log/satsuma-opnsense.log.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, '/opt/satsuma-core')


def main(argv=None):
    from satsuma.store import Store
    from workers.opnsense.worker import WorkerOpnsense

    parser = argparse.ArgumentParser(description='Read-only OPNsense syslog file collector')
    parser.add_argument('--file', default='/var/log/satsuma-opnsense.log')
    parser.add_argument('--watch', action='store_true')
    parser.add_argument('--interval', type=float, default=5.0)
    args = parser.parse_args(argv)
    path = Path(args.file)
    if os.geteuid() != 0:
        parser.error('Root required for the protected Satsuma evidence store')
    if (not path.is_absolute() or not path.is_relative_to('/var/log')
            or '..' in path.parts):
        parser.error('Syslog file must be under /var/log')
    if not 1 <= args.interval <= 300:
        parser.error('Interval must be 1-300 seconds')
    store = Store()
    worker = WorkerOpnsense(store, {'opnsense_mode':'file', 'opnsense_log_path':str(path)})
    try:
        while True:
            report = worker.collect()
            print(json.dumps({'source':'OPNSENSE', 'mode':'advisory_only',
                              'status':report.get('status', 'OK'),
                              'events':report['event_count'],
                              'recommendations':report.get('recommendation_count', 0)},
                             ensure_ascii=False), flush=True)
            if report.get('status') == 'ERROR':
                return 1
            if not args.watch:
                return 0
            time.sleep(args.interval)
    finally:
        store.close()


if __name__ == '__main__':
    raise SystemExit(main())
