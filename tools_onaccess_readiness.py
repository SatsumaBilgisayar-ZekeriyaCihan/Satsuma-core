"""Read-only static review of an on-access source tree, not a host health check."""
import json
from pathlib import Path

root=Path(__file__).resolve().parent
unit=(root/'systemd/satsuma-onaccess-listener.service').read_text()
scanner=(root/'systemd/satsuma-clamonacc.service').read_text()
events=(root/'satsuma/onaccess_events.py').read_text()
issues=[]
if '--log=' not in scanner and '--log ' not in scanner:
    issues.append('ClamAV documentation recommends --log=FILE for durable on-access results; the service does not configure it. Foreground stdout must be verified independently.')
if 'candidate' in events and 'not been validated' in events:
    issues.append('Journald event grammar remains an unvalidated candidate for Fedora clamonacc output.')
if 'CapabilityBoundingSet=CAP_DAC_READ_SEARCH' in unit:
    issues.append('Listener capability bounding only includes CAP_DAC_READ_SEARCH; quarantine may require additional write/ownership privileges. Do not grant blanket capabilities without policy review.')
if 'ReadWritePaths=/var/lib/satsuma-core' in unit:
    issues.append('Quarantine source file under /home may be non-writable to the listener; SELinux and systemd sandbox deny/allow must be verified.')
result={'scope':'static_source_only','production_e2e_proven':False,'issues':issues,'recommended_next_step':'Validate ClamAV logging, fanotify denial, journal parsing, quarantine move and rollback on disposable Fedora host with audit logs.'}
print(json.dumps(result,ensure_ascii=False,indent=2))
