"""Recognise a packaged tool that re-executes itself from a temporary copy (2.2.45).

Field 2026-11-18 (Fedora Atomic): SATSUMA-FILELESS-002 every few seconds for
/tmp/.tmpR0JZc2 running "bootc status --format=json --format-version=1". The
same PID had executed /usr/bin/bootc with the same arguments a moment before:
bootc writes itself to a temporary file (Rust tempfile name ".tmp" + six
characters) and executes that copy. Satsuma's own reader ran bootc status for
the "Sistem kökeni" page every three seconds.

The copy is recognised only with kernel audit evidence from the flow chain of
the same process: an execve of the tool and a read of its root-owned packaged
file, then the execve of the copy with exactly the same arguments. The tool
must be on a short list of programs that do this and are not launchers (no
shell, interpreter, env or sudo). Without that evidence a program run from
/tmp stays a finding, exactly as before.

Paketli bir aracın kendini geçici kopyadan yeniden çalıştırmasını tanır. Saha
2026-11-18: /tmp/.tmpR0JZc2 "bootc status" için birkaç saniyede bir bulgu. Aynı
süreç bir an önce aynı argümanlarla /usr/bin/bootc'yi çalıştırmıştı. Yalnızca
aynı sürecin çekirdek denetim kanıtıyla tanınır; kanıt yoksa bulgu kalır.
"""
import re

from .trusted_process import trusted_path

SELF_COPIERS = {'bootc': ('/usr/bin/bootc', '/usr/sbin/bootc')}
COPY_NAME = re.compile(r'^/tmp/\.tmp[A-Za-z0-9]{6}$')
RULES = ('SATSUMA-FILELESS-002',)


def _argv(cmd):
    return str(cmd or '').split()


def _event(finding):
    event = finding.get('event')
    return event if isinstance(event, dict) else {}


def _field(event, key):
    value = event.get(key)
    if value in (None, ''):
        value = (((event.get('metadata') or {}).get('extensions') or {}) if isinstance(event.get('metadata'), dict) else {}).get('host.' + key)
    return value


def recognize(finding, trusted=None):
    """{'tool', 'packaged', 'evidence'} when the finding is a verified self-copy, else None."""
    if str(finding.get('rule_id') or '') not in RULES:
        return None
    trusted = trusted or trusted_path
    event = _event(finding)
    exe, cmd, pid = str(_field(event, 'exe') or ''), _argv(_field(event, 'cmd')), str(_field(event, 'pid') or '')
    if not COPY_NAME.match(exe) or not cmd or not pid or str(_field(event, 'uid') or '') != '0':
        return None
    tool = cmd[0].rsplit('/', 1)[-1]
    packaged = SELF_COPIERS.get(tool)
    if not packaged:
        return None
    chain = ((finding.get('flow') or {}).get('chain') or []) if isinstance(finding.get('flow'), dict) else []
    entry = next((item for item in chain if str(item.get('pid')) == pid), None)
    if entry is None:
        return None
    ran = read = None
    for item in entry.get('events') or []:
        if item.get('action') == 'execve':
            args = _argv(item.get('cmd'))
            if args and args[0] in packaged and args[1:] == cmd[1:]:
                ran = args[0]
        elif item.get('action') == 'file_access' and item.get('path') in packaged:
            read = item['path']
    if not ran or read != ran or not trusted(ran):
        return None
    return {'tool': tool, 'packaged': ran,
            'evidence': 'aynı süreç önce %s dosyasını aynı argümanlarla çalıştırdı (çekirdek denetim kaydı)' % ran}


def apply(finding, trusted=None):
    """Mark a verified self-copy as a quiet indicator (not recorded); leave everything else alone."""
    found = recognize(finding, trusted)
    if not found:
        return finding
    finding['self_copy'] = found
    finding['rule_name_original'] = finding.get('rule_name')
    finding['rule_name'] = '%s kendi geçici kopyasından çalıştı (zararsız)' % found['tool']
    finding['summary'] = finding['rule_name'] + ': ' + found['evidence']
    finding.update(classification='indicator', severity='low', log_only=True,
                   original_classification=finding.get('classification'), original_severity=finding.get('severity'))
    return finding
