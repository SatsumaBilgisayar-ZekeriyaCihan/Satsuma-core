"""Targeted Firefox/Chromium child-process evidence, not a JavaScript parser.

Normal renderers, GPU processes, native messaging and JIT are not blanket
blocked. Only an actual shell pipeline downloading and executing code is
classified here. The existing process response policy controls termination.
"""
from pathlib import Path, PurePosixPath
import shlex

BROWSER_PREFIXES = ('/usr/bin/', '/usr/lib/', '/usr/lib64/', '/opt/google/chrome/',
                    '/opt/brave.com/', '/opt/microsoft/msedge/', '/app/lib/', '/app/extra/')
FIREFOX = frozenset(('firefox', 'firefox-bin'))
CHROMIUM = frozenset(('chrome', 'chromium', 'chromium-browser', 'brave', 'brave-browser', 'msedge'))
SHELLS = frozenset(('sh', 'bash', 'dash', 'zsh'))


def family(executable):
    executable = str(executable or '')
    if not executable.startswith(BROWSER_PREFIXES):
        return None
    name = PurePosixPath(executable).name
    return 'firefox' if name in FIREFOX else 'chromium' if name in CHROMIUM else None


def _start(process):
    try:return int(process.get('starttime_jiffies') or process.get('starttime') or 0)
    except (ValueError,TypeError):return 0


def dangerous_shell(executable, command):
    if PurePosixPath(str(executable or '')).name not in SHELLS or not isinstance(command, str) or len(command) > 65536:
        return None
    try:
        argv = shlex.split(command)
        index = argv.index('-c')
        script = argv[index + 1]
    except (ValueError, IndexError):
        return None
    # Locate actual pipe operators outside quotes, not words in a document,
    # command argument or a harmless echo of a pipeline.
    quote = None
    escaped = False
    for index, character in enumerate(script):
        if escaped:
            escaped = False
            continue
        if character == '\\' and quote != "'":
            escaped = True
            continue
        if character in ('"', "'"):
            if quote is None: quote = character
            elif quote == character: quote = None
            continue
        if quote is not None or character != '|':
            continue
        try:
            left, right = shlex.split(script[:index]), shlex.split(script[index + 1:])
        except ValueError:
            continue
        if (left and right and PurePosixPath(left[0]).name in ('curl', 'wget')
                and PurePosixPath(right[0]).name in SHELLS):
            return 'browser_download_piped_to_shell'
    return None


def classify_child(child, processes):
    reason = dangerous_shell(child.get('exe'), child.get('cmd'))
    if not reason or _start(child) <= 0:
        return None
    chain, seen = [], set()
    current = child
    for _ in range(8):
        pid = current.get('ppid')
        if type(pid) is not int or pid <= 1 or pid in seen:
            return None
        seen.add(pid)
        parent = processes.get(pid)
        if not parent or not 0 < _start(parent) <= _start(current):
            return None
        chain.append({'pid': pid, 'starttime': _start(parent), 'exe': parent.get('exe')})
        browser = family(parent.get('exe'))
        if browser:
            return {'family': browser, 'reason': reason, 'chain': chain}
        current = parent
    return None


def read_command(pid):
    try:
        with Path('/proc',str(pid),'cmdline').open('rb') as stream:
            raw=stream.read(65537)
        if len(raw)>65536:return None
        return shlex.join([part.decode('utf-8','replace') for part in raw.split(b'\0') if part])
    except OSError:return None


def revalidate(pid, expected):
    """Require the still-live exact child, command and ancestry before signals."""
    from .process_identity import capture_process_identity
    if not isinstance(expected, dict) or not isinstance(expected.get('chain'), list) or not 1 <= len(expected['chain']) <= 8:
        return False
    if any(not isinstance(row,dict) or type(row.get('pid')) is not int or row['pid']<=1
           or type(row.get('starttime')) is not int or row['starttime']<=0 or not isinstance(row.get('exe'),str)
           for row in expected['chain']):
        return False
    child = capture_process_identity(pid)
    command=read_command(pid)
    if not child or not dangerous_shell(child.get('exe'),command):
        return False
    current = child
    for identity in expected['chain']:
        if current.get('ppid') != identity.get('pid'):
            return False
        parent = capture_process_identity(identity['pid'])
        if (not parent or _start(parent) != identity.get('starttime') or parent.get('exe') != identity.get('exe')
                or not 0 < _start(parent) <= _start(current)):
            return False
        current = parent
    after=capture_process_identity(pid)
    return bool(after and _start(after)==_start(child) and after.get('exe')==child.get('exe')
                and after.get('ppid')==child.get('ppid') and read_command(pid)==command
                and family(current.get('exe')) == expected.get('family'))
