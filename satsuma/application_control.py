"""Default-deny host egress, authorized by non-delegated system service cgroups.

A grant covers the whole service process tree, not just an executable filename.
This is containment on a trusted kernel, not a boundary against hostile root.
"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from .package_trust import secure_read, parse_json, SAFE_ENV
from .protected_storage import RootDataStore

TABLE = 'satsuma_apps'
OWNER = 'Satsuma application egress'
POLICY = Path('/var/lib/satsuma-core/application-control/policy.json')
UNIT = re.compile(r'[A-Za-z0-9_.-]{1,128}\.service')
# 2.2.44: DNS is redirected to 169.254.53.2:53 (satsuma.dns_netns); port 53 either way.
PORTS = {'dns': [('tcp', 53), ('udp', 53)], 'https': [('tcp', 443)]}


def validate_policy(data):
    if not isinstance(data, dict) or set(data) not in ({'schema', 'grants'}, {'schema', 'grants', 'enabled'}) or type(data['schema']) is not int or data['schema'] != 1 or not isinstance(data['grants'], dict):
        raise ValueError('Invalid application policy')
    if 'enabled' in data and type(data['enabled']) is not bool:
        raise ValueError('Application enabled state must be explicit boolean')
    for unit, grant in data['grants'].items():
        if not UNIT.fullmatch(unit) or not isinstance(grant, dict) or set(grant) != {'sha256', 'access'}:
            raise ValueError('Only explicit system service units can be granted access')
        if not isinstance(grant['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', grant['sha256']):
            raise ValueError('A verified executable SHA256 is required')
        access = grant['access']
        if not isinstance(access, list) or not access or any(x not in PORTS for x in access) or len(set(access)) != len(access):
            raise ValueError('Access must explicitly name dns and/or https')
    return data


def load_policy():
    if not POLICY.exists():
        return {'schema': 1, 'grants': {}}
    from installer.integrity import read_key
    envelope = parse_json(secure_read(POLICY))
    if set(envelope) != {'policy', 'hmac'}:
        raise ValueError('Invalid signed application policy')
    encoded = json.dumps(envelope['policy'], sort_keys=True, separators=(',', ':')).encode()
    expected = hmac.new(read_key(), encoded, hashlib.sha256).hexdigest()
    if not isinstance(envelope['hmac'], str) or not hmac.compare_digest(envelope['hmac'], expected):
        raise ValueError('Application policy authentication failed')
    return validate_policy(envelope['policy'])


def save_policy(policy):
    from installer.integrity import read_key
    validate_policy(policy)
    encoded = json.dumps(policy, sort_keys=True, separators=(',', ':')).encode()
    RootDataStore('application-control/policy.json').replace({'policy': policy, 'hmac': hmac.new(read_key(), encoded, hashlib.sha256).hexdigest()})


def command(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=15, env=SAFE_ENV)


def resolve_grant(unit, grant, runner=command):
    """Resolve a currently running, non-delegated system unit; never adopt its UID."""
    result = runner(['/usr/bin/systemctl', '--system', 'show', unit, '--no-pager',
                     '--property=Id,ActiveState,MainPID,ControlGroup,Delegate'])
    if result.returncode:
        raise ValueError('Cannot inspect service')
    props = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    group = '/system.slice/' + unit
    if props.get('Id') != unit or props.get('ActiveState') != 'active' or props.get('ControlGroup') != group or props.get('Delegate') != 'no':
        raise ValueError('Service must be active, non-delegated and directly in system.slice')
    pid = int(props.get('MainPID', '0'))
    if pid <= 1:
        raise ValueError('Service has no live main process')
    if Path(f'/proc/{pid}/cgroup').read_text().strip() != '0::' + group:
        raise ValueError('Main process is outside the approved cgroup v2')
    executable = Path(os.readlink(f'/proc/{pid}/exe'))
    data = secure_read(executable, limit=128*1024*1024)
    if hashlib.sha256(data).hexdigest() != grant['sha256']:
        raise ValueError('Service executable differs from approved hash')
    running = os.stat(f'/proc/{pid}/exe')
    disk = executable.stat()
    if (running.st_dev, running.st_ino) != (disk.st_dev, disk.st_ino):
        raise ValueError('Running executable differs from protected disk inode')
    cgroup = Path('/sys/fs/cgroup' + group)
    info = cgroup.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not Path('/sys/fs/cgroup/cgroup.controllers').exists():
        raise ValueError('Unprotected cgroup v2')
    # A non-writable directory alone is insufficient: writable membership files
    # would let another process join an approved service's network group.
    from .protected_storage import open_directory
    directory = open_directory(cgroup)
    try:
        opened = os.fstat(directory)
        if opened.st_ino != info.st_ino:
            raise ValueError('Service cgroup changed during verification')
        for name in ('cgroup.procs', 'cgroup.threads'):
            member = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(member.st_mode) or member.st_uid != 0 or member.st_mode & 0o022:
                raise ValueError('Unprotected cgroup membership file')
    finally:
        os.close(directory)
    return {'unit': unit, 'path': group[1:], 'inode': info.st_ino, 'access': grant['access']}


def render(grants, present=False, enabled=True):
    lines = [f'delete table inet {TABLE}'] if present else []
    if not enabled:
        return '\n'.join(lines + [f'table inet {TABLE} {{', f' comment \"{OWNER}\"',
            ' chain output { type filter hook output priority -5; policy accept; }',
            ' chain forward { type filter hook forward priority -5; policy accept; }', '}', ''])
    lines += [f'table inet {TABLE} {{', f' comment "{OWNER}"',
              ' chain output { type filter hook output priority -5; policy drop;']
    for grant in grants:
        path = grant['path']
        if path != '/' and not (path.startswith('system.slice/') and UNIT.fullmatch(path[len('system.slice/'):])):
            raise ValueError('Invalid service cgroup path')
        for access in grant['access']:
            for protocol, port in PORTS[access]:
                lines.append(f'  socket cgroupv2 level 2 {json.dumps(path)} {protocol} dport {port} counter accept')
    return '\n'.join(lines + ['  counter drop', ' }',
        ' chain forward { type filter hook forward priority -5; policy drop;'] + dns_namespace_forward() + ['  counter drop', ' }', '}', ''])


def dns_namespace_forward():
    """2.2.44: the DNS filter's own namespace still reaches the pinned resolver.

    Accept here does not skip satsuma_core, whose forward chain queues the same
    packets to Suricata. Kabul satsuma_core'u atlatmaz; orada Suricata kuyruğuna girer.
    """
    from .dns_netns import HOST_IF, DNS_ADDR, OPENDNS
    lines = []
    for server in OPENDNS:
        for protocol in ('udp', 'tcp'):
            lines.append(f'  iifname "{HOST_IF}" ip saddr {DNS_ADDR} ip daddr {server} {protocol} dport 53 counter accept')
            lines.append(f'  oifname "{HOST_IF}" ip saddr {server} ip daddr {DNS_ADDR} {protocol} sport 53 counter accept')
    return lines


def valid_layout(text, grants, enabled=True):
    # nft 1.1.6 JSON input lacks cgroupv2 socket support. Validate the complete
    # canonical text readback, including socket level, ID/path, verdict and ports.
    import shlex
    def tokens(value):
        lexer = shlex.shlex(value, posix=True, punctuation_chars='{};')
        lexer.whitespace_split = True
        lexer.commenters = ''
        raw = [token for token in lexer if token != ';']
        result = []
        i = 0
        while i < len(raw):
            if raw[i:i+2] == ['ct', 'direction'] and i+2 < len(raw):
                result.extend(['ct', 'direction', {'original':'0', 'reply':'1'}.get(raw[i+2], raw[i+2])])
                i += 3
                continue
            if (raw[i:i+2] == ['counter', 'packets'] and i+4 < len(raw)
                    and raw[i+2].isdigit() and raw[i+3] == 'bytes' and raw[i+4].isdigit()):
                result.append('counter'); i += 5; continue
            if raw[i:i+4] == ['socket', 'cgroupv2', 'level', '2'] and i+4 < len(raw):
                value = raw[i+4]
                for grant in grants:
                    if value.strip('/') == grant['path'].strip('/') or value == str(grant['inode']):
                        value = str(grant['inode']); break
                result.extend(raw[i:i+4] + [value]); i += 5; continue
            result.append(raw[i]); i += 1
        return result
    try:
        return tokens(text) == tokens(render(grants, enabled=enabled))
    except (ValueError, TypeError):
        return False


def apply(grants, runner=command, enabled=True):
    def nft(*args, script=None):
        if script is None:
            return runner(['/usr/sbin/nft', *args])
        # runner injection keeps real subprocess input explicit and tests deterministic.
        if runner is command:
            return subprocess.run(['/usr/sbin/nft', *args], input=script, capture_output=True,
                                  text=True, timeout=15, env=SAFE_ENV)
        return runner(['/usr/sbin/nft', *args], input=script)
    listed = nft('-j', 'list', 'tables')
    if listed.returncode:
        raise RuntimeError('Cannot inspect application firewall')
    present = any(e.get('table', {}).get('family') == 'inet' and e['table'].get('name') == TABLE
                  for e in json.loads(listed.stdout).get('nftables', []))
    script = render(grants, present=present, enabled=enabled)
    checked = nft('--check', '-f', '-', script=script)
    if checked.returncode:
        raise RuntimeError('Application firewall validation failed: ' + checked.stderr[:200])
    applied = nft('-f', '-', script=script)
    if applied.returncode:
        raise RuntimeError('Application firewall transaction failed: ' + applied.stderr[:200])
    actual = nft('-nnn', '-y', 'list', 'table', 'inet', TABLE)
    for grant in grants:
        # Recheck identity after userspace path resolution and the atomic commit.
        path = Path('/sys/fs/cgroup') / grant['path'].lstrip('/')
        if path.lstat().st_ino != grant['inode']:
            raise RuntimeError('Service cgroup changed during firewall installation')
    if actual.returncode or not valid_layout(actual.stdout, grants, enabled=enabled):
        raise RuntimeError('Application firewall readback failed; expected=' + render(grants, enabled=enabled)
                           + '; actual=' + actual.stdout + actual.stderr)


def sync(deny=False):
    grants, errors = [], {}
    try:
        policy = {'schema':1, 'grants':{}} if deny else load_policy()
        enabled = deny or policy.get('enabled', False)
        for unit, grant in (sorted(policy['grants'].items()) if enabled else []):
            try:
                grants.append(resolve_grant(unit, grant))
            except Exception as exc:
                errors[unit] = str(exc)[:200]
        if enabled:
            apply(grants)
        else:
            apply([], enabled=False)
    except Exception:
        # A damaged allow policy must remove any previously accepted grants.
        try:
            apply([])
        except Exception:
            from .network_control import lockdown
            lockdown()
        raise
    report = {'enabled':enabled, 'active_grants':grants, 'denied_grants':errors, 'external_default':'drop' if enabled else 'main_firewall',
              'loopback':'explicit_service_grants' if enabled else 'main_loopback_validation', 'forward':'drop' if enabled else 'main_firewall', 'root_compromise_resistant':False}
    RootDataStore('application-control/status.json').replace(report)
    return report


def main():
    parser = argparse.ArgumentParser(description='Satsuma system-service internet permissions')
    parser.add_argument('action', choices=['allow','revoke','sync','deny-all','status','enable','disable'])
    parser.add_argument('--unit')
    parser.add_argument('--sha256', help='Independently verified main executable SHA256')
    parser.add_argument('--access', action='append', choices=sorted(PORTS))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Root required')
    from .self_guard import verify
    try:
        verify()
    except Exception:
        try:
            apply([])
        except Exception:
            from .network_control import lockdown
            lockdown()
        raise
    # Serialize both policy edits and refreshes; no lost grants or late stale sync.
    import fcntl
    from .protected_storage import open_directory
    directory = open_directory(POLICY.parent)
    try:
        fd = os.open('.lock', os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            from .protected_storage import check
            check(os.fstat(fd));fcntl.flock(fd, fcntl.LOCK_EX)
            if args.action in ('allow', 'revoke'):
                if not args.unit or not UNIT.fullmatch(args.unit):
                    parser.error('Explicit system .service unit required')
                policy = load_policy()
                if args.action == 'allow':
                    policy['grants'][args.unit] = {'sha256':args.sha256, 'access':args.access}
                    validate_policy(policy)
                    resolve_grant(args.unit, policy['grants'][args.unit])
                else:
                    policy['grants'].pop(args.unit, None)
                save_policy(policy)
            if args.action in ('enable', 'disable'):
                policy = load_policy()
                if args.action == 'enable':
                    if not policy['grants']:
                        raise ValueError('Prepare application grants before enabling enforcement')
                    for unit, grant in policy['grants'].items():
                        resolve_grant(unit, grant)
                policy['enabled'] = args.action == 'enable'
                save_policy(policy)
            if args.action == 'deny-all':
                save_policy({'schema':1, 'grants':{}, 'enabled':True})
            if args.action == 'status':
                result = {'policy':load_policy(), 'note':'Stored grants; use sync to revalidate live state'}
            else:
                result = sync(deny=args.action == 'deny-all')
            RootDataStore('application-control/audit.jsonl').append({'action':args.action,'unit':args.unit,'result':result})
            print(json.dumps(result))
        finally:
            os.close(fd)
    finally:
        os.close(directory)


if __name__ == '__main__':
    main()
