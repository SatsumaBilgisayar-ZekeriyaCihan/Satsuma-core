"""System tools that re-run themselves from a temporary copy (2.2.65, field 2026-11-18).

bootc copies its own binary to /tmp/.tmpXXXXXX and executes that copy (to run under the right
SELinux label). SATSUMA-FILELESS-002 ("execution from /tmp") fired 90 times in two minutes; the
stop was authorised 76 times and failed each time because the copy was already gone.

The copy is taken as the tool only when its content is byte-for-byte the packaged binary: the
running process's /proc/<pid>/exe is hashed and compared with /usr/bin/bootc. The name, the
command line and the parent are never enough (any program can copy those). If the process has
already exited there is nothing to hash and the finding stays as it was.

Kendini geçici kopyadan yeniden çalıştıran sistem aracı, içeriği paketli ikiliyle birebir
aynıysa saldırı sayılmaz; ad ya da komut satırı yetmez.
"""
import hashlib
import os
import re

TOOLS = ('/usr/bin/bootc',)
TEMP_COPY = re.compile(r'^/tmp/\.tmp[A-Za-z0-9]{6}(?: \(deleted\))?$')
_cache = {}


def _digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for block in iter(lambda: fh.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def _tool_digests():
    out = set()
    for tool in TOOLS:
        try:
            st = os.stat(tool)
        except OSError:
            continue
        key = (tool, st.st_ino, st.st_mtime_ns, st.st_size)
        if key not in _cache:
            try:
                _cache[key] = _digest(tool)
            except OSError:
                continue
        out.add(_cache[key])
    return out


def is_tool_copy(event, proc_root='/proc'):
    exe = str(event.get('exe') or '')
    if not TEMP_COPY.match(exe):
        return False
    try:
        pid = int(event.get('pid'))
    except (TypeError, ValueError):
        return False
    try:
        running = _digest(f'{proc_root}/{pid}/exe')
    except OSError:
        return False
    return running in _tool_digests()
