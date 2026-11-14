"""Bounded read-only Exec Guard event view for the dashboard.

A fanotify refusal means execution denied, NOT process terminated.
"""
import json
import os
import stat
from pathlib import Path

EVENTS = Path('/var/lib/satsuma-core/exec-guard/events.jsonl')
ALLOWED = {'build_tool_refused', 'build_tool_allowed'}


def events(path=EVENTS, *, kind=None, limit=50):
    limit = max(1, min(100, int(limit)))
    if kind not in (None, 'refused', 'allowed'):
        raise ValueError('Unknown Exec Guard event kind')
    path = Path(path)
    # The path is constant in the real API. Never follow a substituted log symlink.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {'items': [], 'count': 0, 'status': 'UNAVAILABLE', 'has_more': False}
    with os.fdopen(fd, 'rb') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError('Exec Guard event log is not a regular file')
        f.seek(0, 2)
        size=f.tell();f.seek(max(0, size-262144))
        if size>262144:f.readline()
        raw=f.read(262144)
    rows=[]
    for line in raw.splitlines():
        if len(line)>8192:continue
        try: r=json.loads(line)
        except (ValueError, UnicodeDecodeError):continue
        if not isinstance(r,dict) or r.get('kind') not in ALLOWED:continue
        if kind=='refused' and r['kind']!='build_tool_refused':continue
        if kind=='allowed' and r['kind']!='build_tool_allowed':continue
        pid=r.get('pid')
        if type(pid)!=int or not 0<pid<4194304:continue
        rows.append({'timestamp':r.get('time'), 'pid':pid,
                     'proc_dir':'/proc/%d' % pid, 'process_name':str(r.get('process_name') or '')[:128],
                     'action':'Çalıştırma engellendi' if r['kind']=='build_tool_refused' else 'Teyit Edildi: çalıştırma izni',
                     'kind':r['kind'], 'path':str(r.get('path') or '')[:512],
                     'reason':str(r.get('reason') or '')[:256]})
    return {'items':list(reversed(rows[-limit:])), 'count':len(rows),
            'status':'OK', 'has_more':len(rows)>limit or size>262144}
