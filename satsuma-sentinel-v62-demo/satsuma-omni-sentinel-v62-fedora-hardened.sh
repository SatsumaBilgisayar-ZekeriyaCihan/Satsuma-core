#!/bin/bash -p
# SATSUMA OMNI-SENTINEL V62 SECURE-STATE | V61 + state-file, secret-leak and whitelist hardening
# Embedded Python uses python3 -I -S and the standard library. External distro tools keep their own dependencies.
# Existing security rules and external signature databases are not bundled.
# V62: root olarak çalışırken ortamdan gelen PATH/LD_* değerlerine güvenme.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT BASH_ENV ENV CDPATH 2>/dev/null || true
unset IFS
umask 077
# Bash privileged mode ignores inherited shell functions. Use bash -p to protect startup too.
set -p
while IFS= read -r _sf; do unset -f -- "$_sf"; done < <(compgen -A function)
unset _sf
unset PYTHONPATH PYTHONHOME GIT_CONFIG GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM
unset CURL_HOME WGETRC TMPDIR TMP TEMP

satsuma_selinux_guard() {
    /usr/bin/python3 -I -S - "$@" <<'SATSUMA_SELINUX_GUARD_PY'
"""Scoped SELinux diagnostics/enforcement. Never enables broad permission booleans."""
import datetime, fcntl, json, os, re, selectors, shutil, signal, stat, subprocess, sys, tempfile, time
from pathlib import Path
CONFIG=Path('/etc/selinux/config')
LOGROOT=Path('/var/log/satsuma/selinux')
CORE=('/etc/ld.so.cache','/etc/selinux/config')
LABEL_TARGETS=(*CORE,'/etc/suricata','/etc/suricata/suricata.yaml','/etc/clamd.d/scan.conf','/etc/clamav/clamd.conf','/etc/freshclam.conf','/etc/clamav/freshclam.conf','/usr/local/bin/satsuma-mini','/var/lib/satsuma-rules')
BOOLEAN='domain_can_mmap_files'

class Session:
    def __init__(self): self.records=[]
    def run(self,args,check=True,timeout=30):
        child=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,
                               env={**os.environ,'LC_ALL':'C'},start_new_session=True)
        out=bytearray();truncated=False;deadline=time.monotonic()+timeout
        sel=selectors.DefaultSelector();sel.register(child.stdout,selectors.EVENT_READ)
        try:
            while sel.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0:raise TimeoutError('command deadline exceeded')
                for key,_ in sel.select(min(remaining,.25)):
                    data=os.read(key.fileobj.fileno(),4096)
                    if not data:sel.unregister(key.fileobj);continue
                    room=65536-len(out);out.extend(data[:max(0,room)]);truncated|=len(data)>room
            rc=child.wait(timeout=max(.1,deadline-time.monotonic()))
        finally:
            sel.close()
            if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
            child.wait();child.stdout.close()
        row={'argv':args,'returncode':rc,'output':out.decode('utf-8','replace'),'truncated':truncated}
        self.records.append(row)
        if check and rc:raise RuntimeError('%s failed: %s'%(args[0],row['output'][-400:]))
        return row


def secure_dir(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            try:os.mkdir(part,0o700,dir_fd=fd)
            except FileExistsError:pass
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=nxt;st=os.fstat(fd)
            if st.st_uid!=0 or st.st_mode&0o022:raise RuntimeError('Untrusted evidence directory')
    finally:os.close(fd)


def save_json(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:json.dump(value,f,ensure_ascii=True,indent=2);f.flush();os.fsync(f.fileno())


def collect(session):
    cmdline=Path('/proc/cmdline').read_text().split()
    result={'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'selinux_disabled_bootarg':'selinux=0' in cmdline,
            'permissive_bootarg':'enforcing=0' in cmdline,
            'changes_made':False,'policy_modules_generated':False,'permissions_expanded':False,
            'persistence_scope':'current root filesystem; live ISO reboot persistence is not guaranteed'}
    commands=[['getenforce'],['sestatus'],['getsebool',BOOLEAN],['semanage','permissive','-l'],
              ['findmnt','-n','-T','/etc/selinux/config','-o','TARGET,FSTYPE,OPTIONS'],
              ['ausearch','-m','AVC,USER_AVC','-ts','recent','--raw']]
    existing=[p for p in LABEL_TARGETS if os.path.lexists(p)]
    if existing:commands+=[['ls','-ldZ','--',*existing],['matchpathcon','-V',*existing]]
    for args in commands:
        if shutil.which(args[0]):session.run(args,False,timeout=15)
        else:session.records.append({'argv':args,'unavailable':True})
    if shutil.which('rpm'):
        for p in CORE:
            if os.path.exists(p):session.run(['rpm','-Vf','--noscripts','--',p],False,timeout=15)
    result['runtime_state']=next((r['output'].strip() for r in session.records if r.get('argv')==['getenforce'] and r.get('returncode')==0),'Unavailable')
    return result


def boolean_off(session):
    row=session.run(['getsebool',BOOLEAN],False)
    if row['returncode']:
        all_row=session.run(['getsebool','-a'])
        if all_row['truncated']:raise RuntimeError('Boolean inventory incomplete')
        all_values=all_row['output']
        if re.search(r'^'+BOOLEAN+r'\s',all_values,re.M):raise RuntimeError('Cannot read required boolean')
        return 'not_defined_by_loaded_policy'
    if not re.fullmatch(BOOLEAN+r'\s+-->\s+(on|off)',row['output'].strip()):raise RuntimeError('Unrecognized boolean state')
    # -P also persists off when runtime was already off; never use value1.
    session.run(['setsebool','-P',BOOLEAN,'off'],timeout=180)
    if not re.fullmatch(BOOLEAN+r'\s+-->\s+off',session.run(['getsebool',BOOLEAN])['output'].strip()):
        raise RuntimeError('General mmap permission is not off')
    return 'off'


def persist_enforcing(session,backup_dir):
    secure_dir(CONFIG.parent)
    fd=os.open(CONFIG,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or st.st_nlink!=1 or st.st_size>1048576:
            raise RuntimeError('Unsafe SELinux configuration')
        raw=os.read(fd,1048577)
    finally:os.close(fd)
    text=raw.decode('utf-8');found=False;lines=[]
    for line in text.splitlines():
        if re.match(r'^\s*SELINUX\s*=',line):
            if not found:lines.append('SELINUX=enforcing');found=True
        else:lines.append(line)
    if not found:lines.append('SELINUX=enforcing')
    data=('\n'.join(lines)+'\n').encode()
    if data!=raw:
        backup=backup_dir/'selinux-config.before'
        fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        fd,name=tempfile.mkstemp(prefix='.satsuma-selinux-',dir=CONFIG.parent)
        try:
            with os.fdopen(fd,'wb') as f:
                os.fchmod(f.fileno(),stat.S_IMODE(st.st_mode));os.fchown(f.fileno(),st.st_uid,st.st_gid)
                f.write(data);f.flush();os.fsync(f.fileno())
            os.replace(name,CONFIG)
        finally:
            if os.path.exists(name):os.unlink(name)
    session.run(['restorecon','-Fv',str(CONFIG)])
    session.run(['matchpathcon','-V',str(CONFIG)])


def enforce(session,result,backup_dir):
    if result['runtime_state'] not in ('Enforcing','Permissive'):
        result['reboot_required']=True
        raise RuntimeError('SELinux is unavailable/disabled: cannot activate it in the running kernel; reboot/policy setup required')
    for tool in ('setenforce','getsebool','setsebool','restorecon','matchpathcon'):
        if not shutil.which(tool):raise RuntimeError('Required SELinux utility missing: '+tool)
    # Preserve evidence first. Repair only confirmed fixed core labels.
    secure_dir(CONFIG.parent)
    result['changes_made']=True
    result['phase']='core_label_repair'
    for p in CORE:
        if os.path.islink(p) or not os.path.isfile(p):raise RuntimeError('Unsupported core label target: '+p)
        st=os.stat(p)
        if st.st_uid!=0 or st.st_mode&0o022 or st.st_nlink!=1:raise RuntimeError('Untrusted core label target: '+p)
        session.run(['restorecon','-Fv',p]);session.run(['matchpathcon','-V',p])
    result['mmap_boolean']=boolean_off(session)
    result['phase']='persistent_enforcing_configuration'
    persist_enforcing(session,backup_dir)
    session.run(['setenforce','1'])
    if session.run(['getenforce'])['output'].strip()!='Enforcing':raise RuntimeError('SELinux enforcing readback failed')
    result.update(changes_made=True,runtime_state='Enforcing',enforcing_verified=True,phase='verified')
    return result


def main():
    mode=sys.argv[1] if len(sys.argv)>1 else 'audit'
    if mode not in ('audit','enforce'):raise ValueError('Unknown SELinux operation')
    if os.geteuid()!=0:raise RuntimeError('Root required for protected SELinux evidence')
    secure_dir(LOGROOT)
    evidence=Path(tempfile.mkdtemp(prefix='check-',dir=LOGROOT));os.chmod(evidence,0o700)
    session=Session();result={'enforcing_verified':False};rc=0
    print('SELinux: '+mode+'; önce kanıt kaydı: '+str(evidence),flush=True)
    try:
        result=collect(session);save_json(evidence/'before.json',{'summary':result,'commands':session.records})
        if mode=='enforce':result=enforce(session,result,evidence)
    except (OSError,ValueError,RuntimeError,TimeoutError,subprocess.SubprocessError) as exc:
        result.update(enforcing_verified=False,error=str(exc));rc=2
    finally:
        result['evidence_directory']=str(evidence)
        save_json(evidence/'result.json',{'summary':result,'commands':session.records})
    print(json.dumps(result,ensure_ascii=False,indent=2))
    return rc

if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,RuntimeError) as exc:print('SELINUX: '+str(exc),file=sys.stderr);sys.exit(2)
SATSUMA_SELINUX_GUARD_PY
}

satsuma_ram35() {
    /usr/bin/python3 -I -S - "$@" <<'SATSUMA_RAM_MODULE_PY'
# Ported with adaptations from SatsumaSecurity2.2.35, commit b6ee6d3d37355badc8dca6f16ff4433ac0cff64d.
# Source license: Unlicense. No automatic signal response or SELinux permission widening.

# Original module: satsuma/ram/proc.py
"""Read-only process access. No dump files, ptrace calls or policy mutation.

Sınırlı süreç belleği taraması; kapsam ve erişim eksikleri açıkça raporlanır.
"""
import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
MAX_MAPS = 1024 * 1024

@dataclass(frozen=True)
class Region:
    start: int
    end: int
    perms: str
    offset: int
    device: tuple
    inode: int
    path: str

def parse_maps(text):
    regions = []
    last_end = 0
    for line in text.splitlines():
        fields = line.split(None, 5)
        if len(fields) < 5:
            raise ValueError('malformed_maps')
        start, end = [int(x, 16) for x in fields[0].split('-')]
        perms = fields[1]
        if start < last_end or end <= start or (not re.fullmatch('[r-][w-][x-][ps]', perms)):
            raise ValueError('invalid_mapping_range_or_permissions')
        dev = tuple((int(x, 16) for x in fields[3].split(':')))
        if len(dev) != 2:
            raise ValueError('invalid_mapping_device')
        path = fields[5] if len(fields) == 6 else ''
        path = re.sub('\\\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), path)
        regions.append(Region(start, end, perms, int(fields[2], 16), dev, int(fields[4]), path))
        last_end = end
    return regions

class Process:

    def __init__(self, pid, root=Path('/proc')):
        self.pid = int(pid)
        if self.pid <= 0:
            raise ValueError('invalid_pid')
        self.fd = os.open(str(Path(root) / str(self.pid)), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.mem = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self.mem is not None:
            os.close(self.mem)
        os.close(self.fd)

    def _read(self, name, limit):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                value = stream.read(limit + 1)
            if len(value) > limit:
                raise ValueError(name + '_limit_exceeded')
            return value.decode('utf-8', 'strict')
        finally:
            os.close(fd)

    def snapshot(self):
        raw = self._read('stat', 16384)
        tail = raw[raw.rindex(')') + 1:].split()
        start = int(tail[19])
        exe = os.readlink('exe', dir_fd=self.fd)
        info = os.stat('exe', dir_fd=self.fd)
        maps = self._read('maps', MAX_MAPS)
        identity = (self.pid, start, exe, info.st_dev, info.st_ino)
        return (identity, maps)

    def read(self, address, size):
        if self.mem is None:
            self.mem = os.open('mem', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        return os.pread(self.mem, size, address)

    def eligible(self, region):
        if 'r' not in region.perms:
            return (False, 'not_readable')
        if region.path in ('[vvar]', '[vvar_vclock]', '[vdso]', '[vsyscall]'):
            return (False, 'kernel_special_mapping')
        if region.path.startswith('/dev/') and (not region.path.startswith('/dev/shm/')):
            return (False, 'device_mapping')
        if region.inode:
            try:
                info = os.stat('map_files/%x-%x' % (region.start, region.end), dir_fd=self.fd)
            except OSError:
                return (False, 'backing_type_unverified')
            if not stat.S_ISREG(info.st_mode) or info.st_ino != region.inode or (os.major(info.st_dev), os.minor(info.st_dev)) != region.device:
                return (False, 'nonregular_or_changed_backing')
        return (True, None)

def maps_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

# Original module: satsuma/ram/clamd.py
"""Authenticated local clamd INSTREAM; one absolute protocol deadline.

Sınırlı süreç belleği taraması; kapsam ve erişim eksikleri açıkça raporlanır.
"""
from pathlib import Path
import pwd
import grp
import re
import socket
import stat
import struct
import time
MAX_CHUNK = 4 * 1024 * 1024
SOCKET = Path('/run/satsuma-ram-clamd/clamd.sock')

class Clamd:

    def __init__(self, path=SOCKET, account='clamscan', client_group='satsuma-core'):
        self.path = Path(path)
        self.account = account
        self.client_group = client_group

    def scan(self, payload, deadline):
        if not 0 < len(payload) <= MAX_CHUNK:
            raise ValueError('invalid_payload_size')
        scanner_uid = pwd.getpwnam(self.account).pw_uid
        for ancestor in reversed(self.path.parents):
            info = ancestor.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, scanner_uid) or info.st_mode & 18:
                raise PermissionError('untrusted_socket_directory')
        info = self.path.lstat()
        client_gid = grp.getgrnam(self.client_group).gr_gid
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != scanner_uid or info.st_gid != client_gid or (stat.S_IMODE(info.st_mode) != 432):
            raise PermissionError('untrusted_socket')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:

            def budget():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('clamd_deadline')
                client.settimeout(remaining)
            budget()
            client.connect(str(self.path))
            _, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != scanner_uid:
                raise PermissionError('untrusted_scanner_peer')
            budget()
            client.sendall(b'zINSTREAM\x00')
            for offset in range(0, len(payload), 65536):
                chunk = payload[offset:offset + 65536]
                budget()
                client.sendall(struct.pack('>I', len(chunk)) + chunk)
            budget()
            client.sendall(b'\x00\x00\x00\x00')
            answer = bytearray()
            while b'\x00' not in answer:
                budget()
                block = client.recv(min(1024, 4097 - len(answer)))
                if not block:
                    raise RuntimeError('scanner_disconnected')
                answer.extend(block)
                if len(answer) > 4096:
                    raise ValueError('scanner_reply_limit')
        return parse_reply(bytes(answer).split(b'\x00', 1)[0])

def parse_reply(reply):
    text = reply.decode('utf-8', 'strict')
    if text == 'stream: OK':
        return {'status': 'NO_MATCH'}
    match = re.fullmatch('stream: ([^\\x00-\\x1f\\x7f]{1,256}) FOUND', text)
    if match:
        signature = match[1]
        return {'status': 'REVIEW_REQUIRED' if signature.startswith(('Heuristics.', 'PUA.')) else 'SIGNATURE_MATCH', 'signature': signature}
    raise RuntimeError('scanner_error_or_unsupported_reply')

# Original module: satsuma/ram/engine.py
"""Bounded scanning and exact-byte confirmation. Never terminates processes.

Sınırlı süreç belleği taraması; kapsam ve erişim eksikleri açıkça raporlanır.
"""
import hashlib
import time
from dataclasses import dataclass
CHUNK = 1024 * 1024
OVERLAP = 64 * 1024
TURN_BYTES = 4 * 1024 * 1024
TURN_SECONDS = 2.0

@dataclass
class Progress:
    identity: tuple = ()
    maps_digest: str = ''
    offset: int = 0
    cycle_scanned_bytes: int = 0
    cycle_unreadable_bytes: int = 0
    resets: int = 0
    cycles: int = 0

def confirm(process, evidence, scanner, deadline):
    identity, maps = process.snapshot()
    if identity != evidence['identity'] or maps_hash(maps) != evidence['maps_sha256']:
        return False
    address, size = (evidence['address'], evidence['bytes'])
    if type(address) is not int or type(size) is not int or (not 0 < size <= CHUNK):
        return False
    region = next((r for r in parse_maps(maps) if r.start <= address and address + size <= r.end), None)
    if region is None or not process.eligible(region)[0]:
        return False
    payload = process.read(address, size)
    if len(payload) != size or hashlib.sha256(payload).hexdigest() != evidence['sha256']:
        return False
    reply = scanner.scan(payload, deadline)
    return reply.get('status') == 'SIGNATURE_MATCH' and reply.get('signature') == evidence['signature'] and (process.snapshot() == (identity, maps))

def scan_turn(process, scanner, progress, *, clock=time.monotonic):
    deadline = clock() + TURN_SECONDS
    identity, maps = process.snapshot()
    digest = maps_hash(maps)
    changed = (identity, digest) != (progress.identity, progress.maps_digest)
    if changed:
        progress.resets += bool(progress.identity)
        progress.identity, progress.maps_digest = (identity, digest)
        progress.offset = progress.cycle_scanned_bytes = progress.cycle_unreadable_bytes = 0
    if progress.offset == 0:
        progress.cycle_scanned_bytes = progress.cycle_unreadable_bytes = 0
    selected = []
    excluded = {}
    mapped = 0
    signals = {'writable_executable_regions': 0, 'memfd_executable_regions': 0, 'deleted_executable_regions': 0}
    for region in parse_maps(maps):
        size = region.end - region.start
        mapped += size
        if 'x' in region.perms:
            signals['writable_executable_regions'] += int('w' in region.perms)
            signals['memfd_executable_regions'] += int('memfd:' in region.path)
            signals['deleted_executable_regions'] += int(region.path.endswith(' (deleted)'))
        ok, reason = process.eligible(region)
        if ok:
            selected.append(region)
        else:
            excluded[reason] = excluded.get(reason, 0) + size
    total = sum((r.end - r.start for r in selected))
    report = {'pid': identity[0], 'starttime': identity[1], 'maps_sha256': digest, 'scope': 'eligible readable private and shared user-process mappings', 'mapped_bytes': mapped, 'candidate_bytes': total, 'excluded_bytes_by_reason': excluded, 'read_bytes_this_turn': 0, 'scanner_bytes_this_turn': 0, 'signals': signals, 'signals_are_observations_only': True, 'findings': [], 'errors': {}, 'cycle_complete': False, 'layout_resets': progress.resets, 'clean_verdict': False}
    if not total:
        return {**report, 'status': 'NO_ELIGIBLE_MEMORY'}
    position = 0
    for region in selected:
        length = region.end - region.start
        if position + length <= progress.offset:
            position += length
            continue
        delta = max(0, progress.offset - position)
        while delta < length and clock() < deadline:
            remaining = TURN_BYTES - report['read_bytes_this_turn']
            overlap = min(OVERLAP, delta)
            if remaining <= overlap:
                break
            start = delta - overlap
            size = min(CHUNK, length - start, remaining)
            address = region.start + start
            unique = size - overlap
            try:
                payload = process.read(address, size)
                report['read_bytes_this_turn'] += len(payload)
                if len(payload) != size:
                    raise OSError('short_read')
            except OSError as exc:
                key = 'access_denied' if isinstance(exc, PermissionError) else 'memory_read_error'
                report['errors'][key] = report['errors'].get(key, 0) + 1
                progress.cycle_unreadable_bytes += length - delta
                delta = length
                progress.offset = position + delta
                break
            try:
                answer = scanner.scan(payload, deadline)
                report['scanner_bytes_this_turn'] += size
                if answer.get('status') not in ('NO_MATCH', 'SIGNATURE_MATCH', 'REVIEW_REQUIRED'):
                    raise RuntimeError('unsupported_scanner_status')
                progress.cycle_scanned_bytes += unique
            except (OSError, RuntimeError, ValueError, KeyError) as exc:
                report['errors'][type(exc).__name__] = report['errors'].get(type(exc).__name__, 0) + 1
                report['scanner_error'] = {'type': type(exc).__name__, 'errno': getattr(exc, 'errno', None), 'detail': str(exc)[:200]}
                report['status'] = 'SCANNER_UNAVAILABLE'
                return finish(process, identity, maps, progress, report)
            if answer['status'] in ('SIGNATURE_MATCH', 'REVIEW_REQUIRED'):
                evidence = {'identity': identity, 'maps_sha256': digest, 'address': address, 'bytes': size, 'sha256': hashlib.sha256(payload).hexdigest(), 'signature': answer['signature']}
                verified = False
                if answer['status'] == 'SIGNATURE_MATCH':
                    try:
                        verified = confirm(process, evidence, scanner, deadline)
                    except (OSError, ValueError, RuntimeError, IndexError):
                        pass
                report['findings'].append({**evidence, 'status': 'REPRODUCED_SIGNATURE' if verified else 'REVIEW_REQUIRED', 'automatic_action_authorized': False})
            delta += unique
            progress.offset = position + delta
            del payload
            if report['findings']:
                break
        position += length
        if report['findings'] or clock() >= deadline or TURN_BYTES - report['read_bytes_this_turn'] <= OVERLAP:
            break
    report['cycle_complete'] = progress.offset >= total
    report['status'] = 'FINDING' if report['findings'] else 'CYCLE_FINISHED_NO_SIGNATURE' if report['cycle_complete'] else 'PARTIAL_NO_SIGNATURE'
    report = finish(process, identity, maps, progress, report)
    if report['status'] != 'PROCESS_CHANGED' and report['cycle_complete']:
        progress.cycles += 1
        progress.offset = 0
    return report

def finish(process, identity, maps, progress, report):
    if process.snapshot() != (identity, maps):
        progress.offset = progress.cycle_scanned_bytes = progress.cycle_unreadable_bytes = 0
        progress.maps_digest = ''
        report.update(status='PROCESS_CHANGED', findings=[], cycle_complete=False)
    incomplete = bool(progress.cycle_unreadable_bytes or report.get('errors'))
    report['coverage_state'] = 'INCOMPLETE' if incomplete or not report.get('cycle_complete') else 'ELIGIBLE_CYCLE_FINISHED'
    if report.get('status') == 'CYCLE_FINISHED_NO_SIGNATURE' and incomplete:
        report['status'] = 'CYCLE_FINISHED_INCOMPLETE'
    report.update(next_offset=progress.offset, cycle_scanned_unique_bytes=progress.cycle_scanned_bytes, cycle_unreadable_bytes=progress.cycle_unreadable_bytes, prior_completed_cycles=progress.cycles)
    return report

# Original module: satsuma/memory_validation.py
"""Bounded executable-page integrity checks. Never persist memory contents.

Regions are compared in file-offset order, so which part of a large
program fits the 1 MiB budget is deterministic, and every result says
whether the comparison was complete, how many candidate bytes there were
and which regions were skipped. The maps budget is 1 MiB so that large
programs (browsers, JVMs) are compared instead of reported unverified.

Sınırlı çalıştırılabilir sayfa bütünlüğü denetimi. Bellek içeriği asla
saklanmaz.

Bölgeler dosya ofseti sırasıyla karşılaştırılır; böylece büyük bir
programın hangi kısmının 1 MiB bütçeye sığdığı belirlidir ve her sonuç
karşılaştırmanın tam olup olmadığını, kaç aday bayt olduğunu ve hangi
bölgelerin atlandığını söyler. Harita bütçesi 1 MiB'tır; büyük programlar
(tarayıcılar, JVM'ler) doğrulanamadı denmek yerine karşılaştırılır.
"""
import hashlib
import os
from pathlib import Path
MAP_LIMIT = 1024 * 1024
CODE_BYTE_LIMIT = 1024 * 1024

def validate_executable(directory, byte_limit=CODE_BYTE_LIMIT):
    """Compare main-image private executable mappings to backing.

    A mismatch verifies a code difference, not malware attribution. JIT and
    anonymous regions have no trusted backing and are never reported clean.
    """
    directory = Path(directory)
    result = {'status': 'UNVERIFIED', 'checked_bytes': 0, 'regions': [], 'complete': False, 'total_candidate_bytes': 0, 'skipped_regions': [], 'byte_limit': CODE_BYTE_LIMIT, 'scan_order': 'file_offset_then_virtual_address', 'scope': 'main executable private code only'}
    try:
        before = (directory / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        exe = os.readlink(directory / 'exe')
        with (directory / 'maps').open() as stream:
            maps = stream.read(MAP_LIMIT + 1)
        if len(maps) > MAP_LIMIT:
            return {**result, 'reason': 'mapping_list_truncated'}
        with (directory / 'exe').open('rb') as backing:
            original = os.fstat(backing.fileno())
            candidates = []
            for line in maps.splitlines():
                fields = line.split(None, 5)
                if len(fields) < 5:
                    continue
                perms = fields[1]
                if 'x' not in perms or not perms.endswith('p'):
                    continue
                if int(fields[4]) != original.st_ino:
                    continue
                major, minor = (int(x, 16) for x in fields[3].split(':'))
                if (major, minor) != (os.major(original.st_dev), os.minor(original.st_dev)):
                    continue
                start, end = (int(x, 16) for x in fields[0].split('-'))
                offset = int(fields[2], 16)
                if end <= start or offset >= original.st_size:
                    continue
                candidates.append((start, end, offset))
            if not candidates:
                return {**result, 'reason': 'no_comparable_code_mapping'}
            candidates.sort(key=lambda region: (region[2], region[0]))
            remaining = max(0, min(int(byte_limit), CODE_BYTE_LIMIT))
            result['byte_limit'] = remaining
            total = sum((min(end - start, original.st_size - offset) for start, end, offset in candidates))
            result['total_candidate_bytes'] = total
            mismatch = False
            with (directory / 'mem').open('rb', buffering=0) as memory:
                for start, end, offset in candidates:
                    size = min(end - start, original.st_size - offset, remaining)
                    if size <= 0:
                        result['skipped_regions'].append({'address': start, 'bytes': end - start, 'reason': 'byte_limit_exhausted'})
                        continue
                    actual = os.pread(memory.fileno(), size, start)
                    expected = os.pread(backing.fileno(), size, offset)
                    if len(actual) != size or len(expected) != size:
                        return {**result, 'status': 'UNVERIFIED', 'reason': 'short_code_read'}
                    equal = actual == expected
                    mismatch |= not equal
                    result['regions'].append({'address': start, 'bytes': size, 'matches': equal, 'memory_sha256': hashlib.sha256(actual).hexdigest(), 'backing_sha256': hashlib.sha256(expected).hexdigest()})
                    result['checked_bytes'] += size
                    remaining -= size
            current = os.fstat(backing.fileno())
        after = (directory / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        if before != after or exe != os.readlink(directory / 'exe'):
            return {**result, 'status': 'UNVERIFIED', 'reason': 'process_identity_changed'}
        with (directory / 'maps').open() as stream:
            if maps != stream.read(MAP_LIMIT + 1):
                return {**result, 'status': 'UNVERIFIED', 'reason': 'mapping_changed'}
        if (original.st_size, original.st_mtime_ns, original.st_ctime_ns) != (current.st_size, current.st_mtime_ns, current.st_ctime_ns):
            return {**result, 'status': 'UNVERIFIED', 'reason': 'backing_changed'}
        if not result['checked_bytes']:
            return {**result, 'reason': 'empty_check_budget'}
        return {**result, 'status': 'CODE_MISMATCH' if mismatch else 'CODE_MATCH', 'complete': result['checked_bytes'] == total, 'reason': 'executable_bytes_differ' if mismatch else 'checked_code_matches_backing'}
    except PermissionError:
        return {**result, 'status': 'ACCESS_DENIED', 'reason': 'process_memory_access_denied'}
    except (OSError, ValueError, IndexError) as exc:
        return {**result, 'status': 'UNVERIFIED', 'reason': type(exc).__name__}

# Original module: satsuma/memory_mounts.py
"""Early-boot execution restrictions for device and shared-memory mounts."""
from pathlib import Path
import subprocess
MOUNT_POLICY = {'/dev': ('devtmpfs', {'nosuid', 'noexec'}), '/dev/shm': ('tmpfs', {'nosuid', 'nodev', 'noexec'})}

def mount_table(path=Path('/proc/self/mountinfo')):
    result = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        separator = fields.index('-')
        target = fields[4].replace('\\040', ' ').replace('\\134', '\\')
        result[target] = {'fstype': fields[separator + 1], 'options': set(fields[5].split(','))}
    return result

def check_mount_policy(reader=mount_table):
    mounts = reader()
    rows = {}
    for target, (fstype, required) in MOUNT_POLICY.items():
        observed = mounts.get(target, {})
        options = observed.get('options', set())
        rows[target] = {'ok': observed.get('fstype') == fstype and required <= options, 'fstype': observed.get('fstype'), 'missing_options': sorted(required - options)}
    return {'ok': all((row['ok'] for row in rows.values())), 'mounts': rows}

def harden_mount_policy(reader=mount_table, runner=subprocess.run):
    mounts = reader()
    for target, (fstype, _) in MOUNT_POLICY.items():
        if mounts.get(target, {}).get('fstype') != fstype:
            raise RuntimeError('Unexpected memory mount type: ' + target)
    for target, (_, required) in MOUNT_POLICY.items():
        options = mounts[target]['options']
        if not required <= options:
            runner(['/usr/bin/mount', '-o', 'remount,' + ','.join(sorted(options | required)), target], check=True, capture_output=True, text=True, timeout=15)
    result = check_mount_policy(reader)
    if not result['ok']:
        raise RuntimeError('Memory mount hardening readback failed: ' + str(result))
    return result

# Original module: satsuma/memory_access.py
"""Early-boot limits on cross-process memory access and memory disclosure."""
import ctypes
from pathlib import Path
ACCESS_POLICY = {'kernel/yama/ptrace_scope': '2', 'kernel/kptr_restrict': '2', 'kernel/dmesg_restrict': '1', 'fs/suid_dumpable': '0', 'kernel/core_pattern': '|/usr/bin/false'}

def check_access_policy(root=Path('/proc/sys')):
    rows = {}
    for name, expected in ACCESS_POLICY.items():
        try:
            actual = (root / name).read_text().strip()
            ok = actual == expected or (name == 'kernel/yama/ptrace_scope' and actual == '3')
            rows[name] = {'ok': ok, 'actual': actual, 'required': expected}
        except OSError as exc:
            rows[name] = {'ok': False, 'error': type(exc).__name__}
    return {'ok': all((row['ok'] for row in rows.values())), 'controls': rows}

def harden_access_policy(root=Path('/proc/sys')):
    values = {name: (root / name).read_text().strip() for name in ACCESS_POLICY}
    for name, expected in ACCESS_POLICY.items():
        if name == 'kernel/yama/ptrace_scope' and values[name] == '3':
            continue
        if values[name] != expected:
            (root / name).write_text(expected + '\n')
    result = check_access_policy(root)
    if not result['ok']:
        raise RuntimeError('Memory access policy readback failed')
    return result

def protect_self():
    """Make the Satsuma daemon non-dumpable; do not alter other processes."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'Cannot disable process dumpability')
    if libc.prctl(3, 0, 0, 0, 0) != 0:
        raise RuntimeError('Process remains dumpable')

# Adaptation of SatsumaSecurity2.2.35 primitives. No Core privilege broker or kill policy is imported.
import collections, ctypes, grp, json, os, pwd, resource, signal, stat, subprocess, sys, tempfile, time
from pathlib import Path
SOURCE_REF='b6ee6d3d37355badc8dca6f16ff4433ac0cff64d'
STATE_DIR=Path('/var/lib/satsuma-sentinel/state')
LOG_DIR=Path('/var/log/satsuma')


def safe_directory(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            try:os.mkdir(part,0o700,dir_fd=fd)
            except FileExistsError:pass
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
            st=os.fstat(fd)
            if st.st_uid!=0 or st.st_mode&0o022:raise RuntimeError('Untrusted RAM state directory')
    finally:os.close(fd)


def write_private(path,value):
    fd,name=tempfile.mkstemp(prefix='.ram35-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600);json.dump(value,f,ensure_ascii=True);f.flush();os.fsync(f.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)


def access_without_relaxation(root=Path('/proc/sys')):
    current={key:(root/key).read_text().strip() for key in ACCESS_POLICY}
    for key,desired in ACCESS_POLICY.items():
        if key=='kernel/yama/ptrace_scope' and current[key]=='3':continue
        if key=='kernel/kptr_restrict' and current[key].isdecimal() and int(current[key])>=2:continue
        if current[key]!=desired:(root/key).write_text(desired+'\n')
    result=check_access_policy(root)
    if not result['ok']:raise RuntimeError('Memory access policy readback failed')
    return result


def hardening():
    safe_directory(STATE_DIR)
    safe_directory(Path('/etc/sysctl.d'))
    # Verify prerequisites before mounts; retain metadata for operator review.
    values={key:(Path('/proc/sys')/key).read_text().strip() for key in ACCESS_POLICY}
    mounts=mount_table()
    for target,(kind,flags) in MOUNT_POLICY.items():
        if mounts.get(target,{}).get('fstype')!=kind:raise RuntimeError('Unexpected RAM mount: '+target)
    original={'source_ref':SOURCE_REF,'time':time.time(),'sysctls':values,
              'mounts':{p:{'fstype':r.get('fstype'),'options':sorted(r.get('options',()))} for p,r in mounts.items() if p in MOUNT_POLICY}}
    backup=STATE_DIR/('memory35-before-'+str(time.time_ns())+'.json');write_private(backup,original)
    # Deliberately no automatic rollback to weaker access/exec settings.
    mount_result=harden_mount_policy()
    access_result=access_without_relaxation()
    config=Path('/etc/sysctl.d/90-satsuma-memory.conf')
    lines=[]
    for key,value in ACCESS_POLICY.items():
        if key=='kernel/yama/ptrace_scope' and values[key]=='3':value='3'
        lines.append(key.replace('/','.')+' = '+value)
    fd,name=tempfile.mkstemp(prefix='.satsuma-memory-',dir=config.parent)
    try:
        with os.fdopen(fd,'w') as f:os.fchmod(f.fileno(),0o644);f.write('\n'.join(lines)+'\n');f.flush();os.fsync(f.fileno())
        if config.is_symlink():raise RuntimeError('Symlink memory sysctl config')
        os.replace(name,config)
    finally:
        if os.path.exists(name):os.unlink(name)
    if Path('/sys/fs/selinux/enforce').exists():
        subprocess.run(['restorecon','-v',str(config)],check=True,timeout=30)
    return {'ok':True,'access':access_result,'mounts':mount_result,'backup':str(backup),'permissions_expanded':False}


def configured_scanner():
    fedora='fedora' in [line.split('=',1)[1].strip('\"\'') for line in Path('/etc/os-release').read_text().splitlines() if line.startswith('ID=')]
    account='clamscan' if fedora else 'clamav'
    group=grp.getgrgid(pwd.getpwnam(account).pw_gid).gr_name
    return Clamd('/run/satsuma-ram-clamd/clamd.sock',account=account,client_group=group)


def preflight():
    if Path('/proc/sys/kernel/yama/ptrace_scope').read_text().strip()=='3':
        raise RuntimeError('RAM35 BLOCKED: ptrace_scope=3 korunuyor; modül kilidi uygulanmadı')
    # A harmless payload tests the authenticated local protocol, not AV efficacy.
    probe=configured_scanner().scan(b'Satsuma bounded memory protocol probe',time.monotonic()+3)
    if probe.get('status')!='NO_MATCH':raise RuntimeError('RAM35 scanner protocol probe failed')
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        try:
            fd=os.open(STATE_DIR/'memory35-status.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as f:
                st=os.fstat(f.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o077:
                    raise RuntimeError('Unsafe RAM35 service status')
                raw=f.read(2097153)
            if len(raw)>2097152:raise RuntimeError('RAM35 service status limit')
            data=json.loads(raw)
            if 0<=time.time()-float(data['updated_at'])<=30 and data.get('ptrace_scope')!='3':
                if any(0<=time.time()-float(r.get('observed_at',0))<=30 and r.get('scanner_bytes_this_turn',0)>0 for r in data.get('last_reports',[])):
                    return {'ok':True,'authenticated_scanner_replied':True,'service_process_memory_bytes_submitted':True,
                            'full_ram_coverage':False,'permissions_expanded':False}
        except (FileNotFoundError,ValueError,KeyError,TypeError):pass
        time.sleep(.5)
    raise RuntimeError('RAM35 service has not demonstrated readable bytes submitted to clamd; modül kilidi uygulanmadı')


def scan_loop(once=False):
    safe_directory(STATE_DIR);safe_directory(LOG_DIR)
    protect_self();resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    scanner=configured_scanner();progress={};order=collections.deque();recent={};turns=0
    signal.signal(signal.SIGTERM,lambda *a:sys.exit(0))
    while True:
        live={int(p.name) for p in Path('/proc').iterdir() if p.name.isdecimal() and int(p.name)!=os.getpid()}
        order=collections.deque(pid for pid in order if pid in live)
        progress={pid:v for pid,v in progress.items() if pid in live}
        known=set(order)
        for pid in sorted(live-known):
            if len(order)>=4096:break
            order.append(pid);progress[pid]=Progress()
        report={'status':'NO_PROCESSES','findings':[]}
        policy=Path('/proc/sys/kernel/yama/ptrace_scope').read_text().strip()
        if policy=='3':report={'pid':0,'status':'BLOCKED','reason':'ptrace_scope=3 retained; no policy bypass','findings':[]}
        elif order:
            pid=order[0];order.rotate(-1)
            try:
                with Process(pid) as process:
                    identity,_=process.snapshot()
                    try:scanner_stat=Path('/usr/sbin/clamd').stat();is_scanner=identity[3:]==(scanner_stat.st_dev,scanner_stat.st_ino)
                    except OSError:is_scanner=False
                    if is_scanner:report={'pid':pid,'status':'SCANNER_EXCLUDED','findings':[]}
                    else:
                        report=scan_turn(process,scanner,progress[pid])
                        report['code_validation']=validate_executable('/proc/'+str(pid))
            except (OSError,ValueError,IndexError,RuntimeError) as exc:
                report={'pid':pid,'status':'PROCESS_UNAVAILABLE','error':type(exc).__name__,'findings':[]}
        report['observed_at']=time.time();recent[report.get('pid',0)]=report
        recent=dict(sorted(recent.items(),key=lambda item:item[1]['observed_at'],reverse=True)[:128])
        degraded=any(r['status'] in ('PROCESS_UNAVAILABLE','SCANNER_UNAVAILABLE','CYCLE_FINISHED_INCOMPLETE') or r.get('errors') for r in recent.values())
        snapshot={'source_version':'2.2.35','source_ref':SOURCE_REF,'updated_at':time.time(),
                  'status':'BLOCKED' if policy=='3' else 'DEGRADED' if degraded else 'OBSERVING',
                  'scope':'bounded eligible process mappings plus main executable comparison',
                  'full_ram_coverage':False,'raw_memory_persisted_by_script':False,
                  'automatic_termination_enabled':False,'permissions_expanded':False,
                  'tracked_processes':len(order),'capacity_excluded':max(0,len(live)-len(order)),
                  'last_reports':list(recent.values()),'ptrace_scope':policy}
        write_private(STATE_DIR/'memory35-status.json',snapshot)
        for finding in report.get('findings',[]):
            fd=os.open(LOG_DIR/'memory35-events.jsonl',os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1:
                os.close(fd);raise RuntimeError('Untrusted memory event log')
            with os.fdopen(fd,'a',encoding='utf-8') as f:
                os.fchmod(f.fileno(),0o600);f.write(json.dumps({'time':time.time(),'finding':finding,'action':'review_only'})+'\n')
        print(json.dumps({'memory35':snapshot['status'],'pid':report.get('pid'),'result':report['status'],'findings':len(report.get('findings',[]))}),flush=True)
        turns+=1
        if once:return 2 if snapshot['status'] in ('BLOCKED','DEGRADED') else 0
        time.sleep(.1)


def adapter_main():
    if os.geteuid()!=0:raise RuntimeError('Root required; no additional privileges are granted by this module')
    mode=sys.argv[1] if len(sys.argv)>1 else 'once'
    if mode=='harden':print(json.dumps(hardening(),ensure_ascii=False,indent=2));return 0
    if mode=='preflight':print(json.dumps(preflight(),ensure_ascii=False,indent=2));return 0
    if mode=='status':
        print((STATE_DIR/'memory35-status.json').read_text());return 0
    if mode in ('watch','once'):return scan_loop(mode=='once')
    raise ValueError('Unknown memory35 operation')

if __name__=='__main__':
    try:sys.exit(adapter_main())
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        print('RAM35: '+str(exc),file=sys.stderr);sys.exit(2)
SATSUMA_RAM_MODULE_PY
}

satsuma_selinux_label_services() {
    /usr/bin/python3 -I -S - "$SATSUMA_PLATFORM_FAMILY" <<'SATSUMA_SELINUX_LABELS_PY'
import os,re,subprocess,sys

def run(args,check=True):
    p=subprocess.run(args,text=True,capture_output=True,timeout=90,env={**os.environ,'LC_ALL':'C'})
    if check and p.returncode:raise RuntimeError(p.stderr[-500:])
    return p

if not os.path.exists('/sys/fs/selinux/enforce'):
    raise SystemExit('SELinux yüklü değil; etiketleme başarı sayılmadı')
source='/run/clamd.scan' if sys.argv[1]=='fedora' else '/run/clamav'
for reference,target in [('/var/lib/suricata/rules','/var/lib/satsuma-rules'),(source,'/run/satsuma-ram-clamd')]:
    result=run(['semanage','fcontext','-a','-e',reference,target],False)
    if result.returncode:
        listed=run(['semanage','fcontext','-l','-C']).stdout
        pattern=r'^'+re.escape(target)+r'\s*=\s*'+re.escape(reference)+r'\s*$'
        if not re.search(pattern,listed,re.M):
            raise RuntimeError('Mevcut etiket eşlemesi korunarak işlem durdu: '+target+'; '+result.stderr[-300:])
    if os.path.exists(target):run(['restorecon','-Rv',target])
print('Yalnızca yönetilen kural dizini ve özel RAM soketi için dağıtım etiket eşlemesi doğrulandı; allow politikası üretilmedi.')
SATSUMA_SELINUX_LABELS_PY
}

satsuma_ram35_setup() {
    satsuma_platform_config || return 1
    /usr/bin/python3 -I -S - "$SATSUMA_PLATFORM_FAMILY" <<'SATSUMA_RAM35_SETUP_PY'
import grp,os,pwd,stat,tempfile,subprocess,sys
from pathlib import Path
fedora=sys.argv[1]=='fedora'
account='clamscan' if fedora else 'clamav'
user=pwd.getpwnam(account);group=grp.getgrgid(user.pw_gid).gr_name
conf=Path('/etc/clamd.d/satsuma-ram.conf') if fedora else Path('/etc/clamav/satsuma-ram.conf')
binary='/usr/sbin/clamd'
if not Path(binary).is_file():raise RuntimeError('Clamd binary missing')
body='\n'.join(['Foreground yes','LocalSocket /run/satsuma-ram-clamd/clamd.sock','LocalSocketMode 660',
 'LocalSocketGroup '+group,'DatabaseDirectory /var/lib/clamav','TemporaryDirectory /run/satsuma-ram-clamd',
 'StreamMaxLength 4M','MaxScanSize 4M','MaxFileSize 4M','MaxScanTime 1500','MaxThreads 2','MaxQueue 8',
 'ScanArchive no','ScanMail no','LeaveTemporaryFiles no','LogTime yes','FixStaleSocket yes'])+'\n'
unit='''[Unit]
Description=Satsuma2.2.35 private local RAM signature scanner
After=local-fs.target satsuma-selinux-guard.service
Requires=satsuma-selinux-guard.service
RequiresMountsFor=/var/lib/clamav
[Service]
Type=simple
User=ACCOUNT
Group=GROUP
ExecStart=/usr/sbin/clamd --config-file=CONF
RuntimeDirectory=satsuma-ram-clamd
RuntimeDirectoryMode=0700
UMask=0077
LimitCORE=0
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=/run/satsuma-ram-clamd
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
MemoryMax=2G
MemorySwapMax=0
CPUQuota=50%
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
'''.replace('ACCOUNT',account).replace('GROUP',group).replace('CONF',str(conf))
changed=False
for path,data,gid,mode in [(conf,body,user.pw_gid,0o640),(Path('/etc/systemd/system/satsuma-ram-clamd.service'),unit,0,0o644)]:
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parent.parts[1:]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);os.close(parent);parent=nxt
            st=os.fstat(parent)
            if st.st_uid!=0 or st.st_mode&0o022:raise RuntimeError('Unsafe RAM scanner configuration parent')
    finally:os.close(parent)
    if path.is_symlink():raise RuntimeError('Symlink RAM scanner configuration')
    if path.exists():
        st=path.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o022:
            raise RuntimeError('Unsafe existing RAM scanner configuration')
        if path.read_text()==data and st.st_gid==gid and stat.S_IMODE(st.st_mode)==mode:
            subprocess.run(['restorecon','-v',str(path)],check=True,timeout=30)
            continue
    changed=True
    fd,name=tempfile.mkstemp(prefix='.satsuma-ram-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),mode);os.fchown(f.fileno(),0,gid);f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)
    subprocess.run(['restorecon','-v',str(path)],check=True,timeout=30)
print('Özel RAM clamd yapılandırması yazıldı; sunucuya ek Linux capability verilmedi.')
if changed:
    Path('/run/satsuma/ram-clamd-restart').touch(mode=0o600,exist_ok=True)
SATSUMA_RAM35_SETUP_PY
    [[ $? -eq 0 ]] || return 1
    satsuma_selinux_label_services || return 1
    systemctl daemon-reload && systemctl enable --now satsuma-ram-clamd.service || return 1
    if [[ -f /run/satsuma/ram-clamd-restart ]]; then
        systemctl restart satsuma-ram-clamd.service || return 1
        rm -- /run/satsuma/ram-clamd-restart || return 1
    fi
    local i
    for ((i=0;i<60;i++)); do
        systemctl is-active --quiet satsuma-ram-clamd.service || return 1
        if [[ -S /run/satsuma-ram-clamd/clamd.sock ]]; then
            restorecon -Rv /run/satsuma-ram-clamd || return 1
            return 0
        fi
        sleep 2
    done
    echo "RAM imza tarayıcı soketi hazır olmadı." >&2; return 1
}

satsuma_protection_units_install() {
    [[ $EUID -eq 0 ]] || return 1
    local staged name
    for name in satsuma-selinux-guard satsuma-memory-hardening satsuma-memory-watch; do
        staged=$(mktemp /etc/systemd/system/.satsuma-protection.XXXXXXXX) || return 1
        case "$name" in
            satsuma-selinux-guard)
                cat > "$staged" <<'SATSUMA_SELINUX_UNIT'
[Unit]
Description=Satsuma SELinux enforcing and mmap boolean off verification
After=local-fs.target
Before=suricata.service satsuma-ram-clamd.service satsuma-memory-watch.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/satsuma-mini --selinux-enforce
RemainAfterExit=yes
TimeoutStartSec=300
UMask=0077
LimitCORE=0
[Install]
WantedBy=multi-user.target
SATSUMA_SELINUX_UNIT
                ;;
            satsuma-memory-hardening)
                cat > "$staged" <<'SATSUMA_MEMORY_HARDEN_UNIT'
[Unit]
Description=Satsuma device shared-memory and ptrace restrictions
After=local-fs.target satsuma-selinux-guard.service
Requires=satsuma-selinux-guard.service
Before=satsuma-memory-watch.service satsuma-file-scan.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/satsuma-mini --memory35-harden
RemainAfterExit=yes
UMask=0077
LimitCORE=0
[Install]
WantedBy=multi-user.target
SATSUMA_MEMORY_HARDEN_UNIT
                ;;
            satsuma-memory-watch)
                cat > "$staged" <<'SATSUMA_MEMORY_WATCH_UNIT'
[Unit]
Description=Satsuma 2.2.35 bounded process-memory observer
After=satsuma-selinux-guard.service satsuma-memory-hardening.service satsuma-ram-clamd.service
Requires=satsuma-selinux-guard.service satsuma-memory-hardening.service satsuma-ram-clamd.service
[Service]
Type=simple
ExecStart=/usr/local/bin/satsuma-mini --memory35-watch
Restart=on-failure
RestartSec=15
UMask=0077
LimitCORE=0
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/satsuma-sentinel/state /var/log/satsuma
RestrictAddressFamilies=AF_UNIX
MemoryMax=384M
MemorySwapMax=0
CPUQuota=25%
KillMode=control-group
[Install]
WantedBy=multi-user.target
SATSUMA_MEMORY_WATCH_UNIT
                ;;
        esac
        if [[ $? -ne 0 ]] || ! chmod 0644 "$staged" || ! mv -f -- "$staged" "/etc/systemd/system/$name.service"; then
            rm -f -- "$staged"; return 1
        fi
        restorecon -v "/etc/systemd/system/$name.service" || return 1
    done
    systemctl daemon-reload || return 1
    systemctl enable satsuma-selinux-guard.service satsuma-memory-hardening.service satsuma-memory-watch.service || return 1
    systemctl start satsuma-selinux-guard.service
}

satsuma_verify_ips() {
    /usr/bin/python3 -I -S - "${1:-0}" <<'SATSUMA_IPS_VERIFY_PY'
import json, os, pathlib, subprocess, sys

def verify_ips(q):
    checks = {}; details = {}
    def run(args):
        return subprocess.run(args, capture_output=True, text=True, timeout=15, check=True).stdout
    try:
        pid = int(run(['systemctl','show','-p','MainPID','--value','suricata']))
        checks['service_active'] = run(['systemctl','is-active','suricata']).strip() == 'active'
        argv = pathlib.Path('/proc/%d/cmdline' % pid).read_bytes().split(b'\0')
        checks['process_queue_argument'] = any(argv[i] == b'-q' and argv[i+1] == str(q).encode() for i in range(len(argv)-1))
        peers = [int(line.split()[1]) for line in pathlib.Path('/proc/net/netfilter/nfnetlink_queue').read_text().splitlines() if line.split() and int(line.split()[0]) == q]
        checks['queue_bound'] = len(peers) == 1
        inodes = set()
        for line in pathlib.Path('/proc/net/netlink').read_text().splitlines()[1:]:
            cols = line.split()
            if len(cols) >= 10 and cols[1] == '12' and int(cols[2]) in peers:
                inodes.add('socket:[%s]' % cols[-1])
        fds = pathlib.Path('/proc/%d/fd' % pid)
        targets = set()
        for fd in fds.iterdir():
            try: targets.add(os.readlink(fd))
            except FileNotFoundError: pass
        checks['queue_owned_by_suricata'] = bool(inodes & targets)
        data = json.loads(run(['nft','-j','list','table','inet','satsuma_filter']))['nftables']
        whole = json.loads(run(['nft','-j','list','ruleset']))['nftables']
        checks['no_ruleset_flow_offload'] = not any('flow' in e or 'flowtable' in e for row in whole if 'rule' in row for e in row['rule'].get('expr',[]))
        chains = {r['chain']['name']:r['chain'] for r in data if 'chain' in r}
        rules = {}
        for row in data:
            if 'rule' in row: rules.setdefault(row['rule']['chain'],[]).append(row['rule'])
        for hook in ('input','forward','output'):
            base = chains.get(hook,{}); ips = chains.get('ips_'+hook,{})
            checks[hook+'_policy'] = base.get('hook') == hook and base.get('prio') == 0 and base.get('policy') == 'drop'
            checks[hook+'_queue_after_firewall'] = ips.get('hook') == hook and ips.get('prio') == 10 and ips.get('policy') == 'accept'
            rr = rules.get('ips_'+hook,[])
            expr = rr[0].get('expr',[]) if len(rr) == 1 else []
            queues = [e['queue'] for e in expr if 'queue' in e]
            checks[hook+'_queue_fail_closed'] = len(queues) == 1 and queues[0].get('num') == q and not queues[0].get('flags') and all(set(e) <= {'counter','queue'} for e in expr)
            counters = [e['counter'] for e in expr if 'counter' in e]
            details[hook+'_queued_packets'] = counters[0].get('packets',0) if counters else None
        checks['no_early_queue_or_flow_offload'] = not any(('queue' in e or 'flow' in e or 'flowtable' in e) for row in data if 'rule' in row for e in row['rule'].get('expr',[]) if row['rule']['chain'] in ('input','forward','output'))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        checks['inspection_complete'] = False; details['error'] = str(exc)
    return {'ok':bool(checks) and all(checks.values()), 'checks':checks, 'details':details, 'packet_drop_proven':False}

q=int(sys.argv[1]) if len(sys.argv)>1 else 0
if not 0 <= q <= 65535: raise SystemExit(2)
result=verify_ips(q)
print(json.dumps(result,ensure_ascii=False,indent=2))
sys.exit(0 if result['ok'] else 2)
SATSUMA_IPS_VERIFY_PY
}

satsuma_browser_harden() {
    /usr/bin/python3 -I -S - "$@" <<'SATSUMA_BROWSER_PY'
import datetime, json, os, pathlib, re, stat, sys, tempfile

# Required stable Gecko extension ID, not a moz-extension internal UUID.
ALLOWED_FIREFOX_EXTENSION_ID = "armut-bildirici@satsuma.local"

def trusted_parent(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in pathlib.Path(path).parent.parts[1:]:
            created=False
            try:
                os.mkdir(part,0o755,dir_fd=fd); created=True
            except FileExistsError: pass
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd); fd=nxt
            st=os.fstat(fd)
            if st.st_uid!=0 or st.st_mode & 0o022: raise RuntimeError('Untrusted policy directory')
            if created: os.fchmod(fd,0o755)
        return fd
    except BaseException:
        os.close(fd); raise

def apply_browser_policies():
    if os.geteuid()!=0: raise RuntimeError('Root required')
    addon_id=ALLOWED_FIREFOX_EXTENSION_ID
    if not addon_id or len(addon_id)>255 or not re.fullmatch(r'[A-Za-z0-9{}@._+\-]+',addon_id):
        raise RuntimeError('İzinli Firefox eklentisinin sabit ID değeri henüz girilmedi; tarayıcı politikaları değiştirilmedi')
    if '--check' in sys.argv:
        print('Browser policy configuration ready')
        return
    firefox={
        'HttpsOnlyMode':'force_enabled',
        'IPProtectionAvailable':False,
        'Proxy':{'Mode':'none','Locked':True},
        'WebsiteFilter':{'Block':['http://*/*']},
        'ExtensionSettings':{
            '*':{'installation_mode':'blocked','blocked_permissions':['nativeMessaging']},
            addon_id:{'installation_mode':'allowed','blocked_permissions':['nativeMessaging']},
            'chrome-gnome-shell@gnome.org':{'installation_mode':'blocked'},
        },
        'DisableSecurityBypass':{'InvalidCertificate':True,'SafeBrowsing':True},
        'EnableTrackingProtection':{'Value':True,'Locked':True,'Cryptomining':True,'Fingerprinting':True},
        'Preferences':{
            'extensions.enabledScopes':{'Value':5,'Status':'locked'},
            'xpinstall.signatures.required':{'Value':True,'Status':'locked'},
            'extensions.langpacks.signatures.required':{'Value':True,'Status':'locked'},
            'browser.safebrowsing.malware.enabled':{'Value':True,'Status':'locked'},
            'browser.safebrowsing.phishing.enabled':{'Value':True,'Status':'locked'},
            'browser.safebrowsing.downloads.enabled':{'Value':True,'Status':'locked'},
            'security.sandbox.content.level':{'Value':6,'Status':'locked'},
        },
    }
    chromium={'ProxyMode':'direct','HttpsOnlyMode':'force_enabled','URLBlocklist':['http://*'],
        'ExtensionSettings':{'*':{'installation_mode':'blocked'},
                             'gphhapmejobijbbhgpjhcjognlahblep':{'installation_mode':'blocked'}},
        'BlockExternalExtensions':True,
        'NativeMessagingBlocklist':['*'],
        'NativeMessagingAllowlist':[],
        'NativeMessagingUserLevelHosts':False,
        'SafeBrowsingProtectionLevel':1,'DisableSafeBrowsingProceedAnyway':True,
        'BlockThirdPartyCookies':True,'DefaultNotificationsSetting':2}
    paths={
        '/etc/firefox/policies/policies.json':{'policies':firefox},
        '/etc/opt/chrome/policies/managed/satsuma-security.json':chromium,
        '/etc/chromium/policies/managed/satsuma-security.json':chromium,
    }
    outputs=[]
    for path,new in paths.items():
        parent=trusted_parent(path); name=os.path.basename(path); fd=None
        try:
            try:
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
                st=os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or st.st_nlink!=1:
                    raise RuntimeError('Untrusted existing policy: '+path)
                if st.st_size>1048576: raise RuntimeError('Policy file too large')
                raw=os.read(fd,1048577); old=json.loads(raw)
                # Keep unrelated policy keys. Satsuma security settings win.
                if 'policies' in new:
                    existing_policies=old.setdefault('policies',{})
                    existing_prefs=existing_policies.get('Preferences',{})
                    if not isinstance(existing_prefs,dict): raise ValueError('Preferences must be an object')
                    new['policies']['Preferences']={**existing_prefs,**new['policies']['Preferences']}
                    existing_policies.update(new['policies']); new=old
                else:
                    old.update(new); new=old
                backup=name+'.satsuma-backup-'+datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
                bf=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                try:
                    with os.fdopen(bf,'wb') as out: out.write(raw); out.flush(); os.fsync(out.fileno())
                finally: pass
            except FileNotFoundError: pass
            # All temporary names are created atomically under a trusted parent.
            tmp='.satsuma-'+os.urandom(12).hex()
            wf=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644,dir_fd=parent)
            try:
                with os.fdopen(wf,'w') as out:
                    json.dump(new,out,ensure_ascii=False,indent=2); out.write('\n'); out.flush(); os.fsync(out.fileno())
                    os.fchmod(out.fileno(),0o644)
                os.replace(tmp,name,src_dir_fd=parent,dst_dir_fd=parent); os.fsync(parent)
            finally:
                try: os.unlink(tmp,dir_fd=parent)
                except FileNotFoundError: pass
            outputs.append(path)
        finally:
            if fd is not None: os.close(fd)
            os.close(parent)
    print(json.dumps({'written':outputs,'requires_browser_restart':True,
        'extension_policy':'only approved Firefox profile extension allowed; system builtins retained',
        'native_messaging':'denied including approved extension; GNOME connector browser integration blocked',
        'directory_scope':'Firefox user/system external addon locations disabled; application builtins retained',
        'runtime_policy_acceptance':'verify in about:policies or chrome://policy'},ensure_ascii=False,indent=2))

try: apply_browser_policies()
except (OSError,RuntimeError,ValueError,TypeError) as exc:
    print('Browser policy error: '+str(exc),file=sys.stderr); sys.exit(2)
SATSUMA_BROWSER_PY
}

# Live session DNS (user decision 2026-11-10): systemd-resolved is stopped and
# masked, NetworkManager no longer writes DNS (the modem's DHCP DNS is not
# used), and /etc/resolv.conf becomes a plain root-owned file with the trusted
# OpenDNS servers. Plain DNS needs no port 853, so 853 can stay closed.
# Name resolution is tested; setup stops if it does not work.
# Canlı oturum DNS'i: systemd-resolved durdurulur ve maskelenir,
# NetworkManager DNS yazmaz (modemin DHCP DNS'i kullanılmaz), /etc/resolv.conf
# güvenilir OpenDNS sunucularıyla düz bir root dosyası olur. Düz DNS 853
# istemez; 853 kapalı kalabilir. Ad çözümlemesi sınanır; çalışmazsa kurulum durur.
SATSUMA_DNS_SERVERS=(208.67.222.222 208.67.220.220)
satsuma_plain_dns() {
    local conf=/etc/NetworkManager/conf.d/90-satsuma-dns.conf staged unit server
    install -d -m 0755 /etc/NetworkManager/conf.d || return 1
    staged=$(mktemp /etc/NetworkManager/conf.d/.satsuma-dns.XXXXXX) || return 1
    printf '[main]\ndns=none\nsystemd-resolved=false\nrc-manager=unmanaged\n' > "$staged" &&
        chmod 0644 "$staged" && mv -f -- "$staged" "$conf" || { rm -f -- "$staged"; return 1; }
    restorecon "$conf" >/dev/null 2>&1 || true
    for unit in systemd-resolved.service systemd-resolved-monitor.socket systemd-resolved-varlink.socket; do
        systemctl cat "$unit" >/dev/null 2>&1 || continue
        systemctl mask --now "$unit" || { echo "$unit durdurulamadı" >&2; return 1; }
    done
    staged=$(mktemp /etc/.satsuma-resolv.XXXXXX) || return 1
    {
        echo "# Satsuma Mini: plain DNS for this live session (systemd-resolved masked)."
        for server in "${SATSUMA_DNS_SERVERS[@]}"; do echo "nameserver $server"; done
        echo "options edns0"
    } > "$staged" && chmod 0644 "$staged" || { rm -f -- "$staged"; return 1; }
    chattr -i /etc/resolv.conf >/dev/null 2>&1 || true
    mv -f -T -- "$staged" /etc/resolv.conf || { rm -f -- "$staged"; return 1; }
    restorecon /etc/resolv.conf >/dev/null 2>&1 || true
    if systemctl is-active --quiet NetworkManager; then
        systemctl reload NetworkManager || systemctl restart NetworkManager || return 1
    fi
    [[ ! -L /etc/resolv.conf ]] || { echo "/etc/resolv.conf hâlâ bir bağlantı" >&2; return 1; }
    local tries=0
    until getent ahostsv4 fedoraproject.org >/dev/null; do
        (( ++tries < 10 )) && { sleep 1; continue; }
        echo "DNS çalışmıyor: ${SATSUMA_DNS_SERVERS[*]} yanıt vermedi. Kurulum durdu; ağ bağlantısını kontrol edin." >&2
        return 1
    done
    echo -e " ${C_GREEN}[✓] DNS: systemd-resolved kapalı; düz DNS ${SATSUMA_DNS_SERVERS[*]} (853 gerekmez)${C_RESET}"
}

satsuma_disable_tor() {
    local unit
    for unit in tor.service tor@.service tor@default.service; do
        systemctl mask --now "$unit" || return 1
    done
    echo "Standart Tor servisleri maskelendi. HTTPS üzerindeki gizli Tor köprüleri için mutlak engel garantisi yok."
}

satsuma_python_audit() {
    /usr/bin/python3 -I -S - <<'SATSUMA_PYTHON_AUDIT_PY'
"""Read-only Python startup-hook inventory. Run with python3 -I -S.

No audited file is imported or executed. Package names alone cannot identify
malware. RPM verification disables package verification scriptlets.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time

MAX_FILE = 1048576
MAX_FILES = 256
MAX_OUTPUT = 65536


def _trust_directory(path, trusted_uid=0, trust_anchor=Path('/')):
    path = Path(path)
    anchor = Path(trust_anchor).resolve(strict=True)
    # /lib -> /usr/lib aliases are normal on merged-/usr systems.
    canonical = path.resolve(strict=True)
    if canonical != anchor and anchor not in canonical.parents:
        raise RuntimeError('Directory escapes trust anchor')
    current = anchor
    for part in ((), canonical.relative_to(anchor).parts):
        if not part:
            st = current.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != trusted_uid or st.st_mode & 0o022:
                raise RuntimeError('Untrusted directory ancestor')
            continue
        for name in part:
            current /= name
            st = current.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != trusted_uid or st.st_mode & 0o022:
                raise RuntimeError('Untrusted directory ancestor')
    # Reject an untrusted last symlink even if it points to a trusted target.
    original = path.lstat()
    if original.st_uid != trusted_uid:
        raise RuntimeError('Untrusted directory owner')
    return canonical


def _read_regular(path):
    """Pin before opening; never invoke a device's open handler."""
    pin = fd = None
    try:
        pin = os.open(path, os.O_PATH | os.O_NOFOLLOW)
        st = os.fstat(pin)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise RuntimeError('Refusing symlink, non-regular or hard-linked startup file')
        if st.st_size > MAX_FILE:
            raise RuntimeError('Startup file exceeds 1 MiB inspection limit')
        fd = os.open('/proc/self/fd/%d' % pin, os.O_RDONLY | os.O_NONBLOCK)
        data = bytearray()
        while len(data) <= MAX_FILE:
            chunk = os.read(fd, min(65536, MAX_FILE + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        end = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        if len(data) > MAX_FILE or identity(st) != identity(end):
            raise RuntimeError('Startup file changed or exceeded inspection limit')
        return bytes(data), st
    finally:
        for number in (fd, pin):
            if number is not None:
                os.close(number)


def _bounded_command(args, timeout):
    """Capture at most 64 KiB without writing temporary files."""
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL, start_new_session=True)
    output = bytearray()
    truncated = False
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        for pipe in (child.stdout, child.stderr):
            selector.register(pipe, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(args, timeout)
            for key, _ in selector.select(min(remaining, .25)):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(chunk) > MAX_OUTPUT:
                    output.extend(chunk[:MAX_OUTPUT - len(output)])
                    truncated = True
                    raise RuntimeError('RPM output limit reached')
                output.extend(chunk)
        child.wait(timeout=max(.01, deadline - time.monotonic()))
        return child.returncode, bytes(output).decode('utf-8', 'replace'), truncated
    finally:
        selector.close()
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()
        child.stderr.close()


def _inspect_startup_file(path, trusted_uid=0):
    data, st = _read_regular(path)
    result = {'path':str(path), 'size':st.st_size, 'uid':st.st_uid,
              'mode':oct(stat.S_IMODE(st.st_mode)),
              'sha256':hashlib.sha256(data).hexdigest(),
              'trusted_owner_and_mode':st.st_uid == trusted_uid and not st.st_mode & 0o022,
              'executable_import_lines':[], 'path_additions':[]}
    if path.suffix == '.pth':
        for number, line in enumerate(data.decode('utf-8', 'replace').splitlines(), 1):
            line = line.rstrip()
            if not line or line.startswith('#'):
                continue
            if line.startswith(('import ', 'import\t')):
                # Report names, never the executable source line.
                imports = re.findall(r'\b(?:import|from)\s+([A-Za-z_][A-Za-z0-9_.]*)', line)
                result['executable_import_lines'].append({'line':number, 'module_names':imports[:32]})
            else:
                # Do not expose arbitrary .pth contents or probe path contents.
                resolved = os.path.abspath(os.path.join(str(path.parent), line))
                outside = os.path.commonpath((str(path.parent), resolved)) != str(path.parent)
                result['path_additions'].append({'line':number,
                    'kind':'absolute' if os.path.isabs(line) else 'relative',
                    'outside_site_packages':outside,
                    'value_sha256':hashlib.sha256(line.encode('utf-8')).hexdigest()})
    else:
        result['startup_module'] = path.name
    result['needs_review'] = bool(result.get('startup_module') or result['executable_import_lines']
                                  or any(p['outside_site_packages'] for p in result['path_additions'])
                                  or not result['trusted_owner_and_mode'])
    return result


def _same_root_import_target(root, module_name, trusted_uid=0):
    """Find only a local .py/package file; never use importlib resolution."""
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*', module_name):
        return None
    names = module_name.split('.')
    # Python prefers a package directory to a same-name ordinary module.
    candidates = [names + ['__init__.py'], names[:-1] + [names[-1] + '.py']]
    for parts in candidates:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        missing = False
        try:
            for name in parts[:-1]:
                try:
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    missing = True; break
                if stat.S_ISLNK(st.st_mode):
                    raise RuntimeError('Symlink in same-root imported module ancestor')
                if not stat.S_ISDIR(st.st_mode):
                    missing = True; break
                nxt = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = nxt
                st = os.fstat(fd)
                if st.st_uid != trusted_uid or st.st_mode & 0o022:
                    raise RuntimeError('Untrusted same-root imported module ancestor')
            if missing:
                continue
            try:
                st = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(st.st_mode):
                raise RuntimeError('Symlink at same-root imported module target')
            if not stat.S_ISREG(st.st_mode):
                raise RuntimeError('Non-regular same-root imported module target')
            return root.joinpath(*parts)
        finally:
            os.close(fd)
    return None


def audit(roots=None, trusted_uid=0, trust_anchor=Path('/'), run_rpm=True,
          deadline_seconds=30):
    deadline = time.monotonic() + min(max(deadline_seconds, 1), 30)
    result = {'scope':'system Python site-packages startup hooks',
              'imports_audited_code':False, 'changes_system':False,
              'malware_classification':'not determined by this inventory',
              'python_startup_isolated':bool(sys.flags.isolated and sys.flags.no_site),
              'directories':[], 'files':[], 'issues':[], 'incomplete':False,
              'same_root_import_targets_only':True, 'unresolved_same_root_imports':[],
              'rpm_note':'RPM verifies the owning package, not just the named file; --noscripts is used'}
    if roots is None:
        roots = []
        for prefix in ('/usr/lib', '/usr/lib64', '/lib', '/lib64'):
            try:
                roots.extend(Path(prefix).glob('python*/site-packages'))
                roots.extend(Path(prefix).glob('python*/dist-packages'))
            except OSError:
                pass
    seen = set()
    count = rpm_count = 0
    import_names_seen = set()
    referenced_target_count = 0
    import_budget_reported = False
    for original in roots:
        if time.monotonic() >= deadline:
            result['issues'].append({'reason':'global inspection deadline reached'})
            result['incomplete'] = True
            break
        try:
            root = _trust_directory(original, trusted_uid, trust_anchor)
            key = (root.stat().st_dev, root.stat().st_ino)
            if key in seen:
                continue
            seen.add(key)
            result['directories'].append(str(root))
            targets = []
            # A bounded scandir avoids materializing a potentially huge tree.
            entries = 0
            with os.scandir(root) as iterator:
                for item in iterator:
                    entries += 1
                    if entries > 20000 or time.monotonic() >= deadline:
                        raise RuntimeError('Directory enumeration budget exceeded')
                    if item.name.endswith('.pth') or item.name in ('sitecustomize.py', 'usercustomize.py'):
                        targets.append(root / item.name)
                        if len(targets) > MAX_FILES:
                            raise RuntimeError('Startup file inventory limit reached')
            queue = sorted(targets)
            queued = set(queue)
            referenced_by = {}
            queue_index = 0
            while queue_index < len(queue):
                path = queue[queue_index]
                queue_index += 1
                count += 1
                if count > MAX_FILES or time.monotonic() >= deadline:
                    raise RuntimeError('Startup file/deadline inspection budget exceeded')
                try:
                    row = _inspect_startup_file(path, trusted_uid)
                    if path in referenced_by:
                        row['referenced_by_pth'] = referenced_by[path]
                        row['source_kind'] = 'same-root import target metadata only'
                    result['files'].append(row)
                    if path.suffix == '.pth':
                        for line in row['executable_import_lines']:
                            for module_name in line['module_names']:
                                import_key = (str(root), module_name)
                                if import_key in import_names_seen:
                                    continue
                                if len(import_names_seen) >= 32:
                                    if not import_budget_reported:
                                        result['issues'].append({'reason':'Same-root import target budget reached (32 names)'})
                                        result['incomplete'] = True
                                        import_budget_reported = True
                                    continue
                                import_names_seen.add(import_key)
                                try:
                                    target = _same_root_import_target(root, module_name, trusted_uid)
                                    if target is None:
                                        result['unresolved_same_root_imports'].append({'module_name':module_name,
                                            'reason':'No ordinary .py/package in the same system package root; not imported or followed elsewhere'})
                                        continue
                                    referenced_by.setdefault(target, []).append({'pth':str(path), 'line':line['line'], 'module_name':module_name})
                                    if target not in queued:
                                        if referenced_target_count >= 32:
                                            raise RuntimeError('Same-root imported file budget reached')
                                        queue.insert(queue_index, target)
                                        queued.add(target)
                                        referenced_target_count += 1
                                except (OSError, RuntimeError, ValueError) as exc:
                                    result['issues'].append({'path':str(path), 'module_name':module_name, 'reason':str(exc)[:300]})
                                    result['incomplete'] = True
                    if not row['trusted_owner_and_mode']:
                        result['incomplete'] = True
                    rpm = Path('/usr/bin/rpm')
                    if run_rpm and rpm.is_file() and rpm_count < 8:
                        rst = rpm.stat()
                        if rst.st_uid != 0 or rst.st_mode & 0o022:
                            raise RuntimeError('RPM executable is not trusted')
                        rpm_count += 1
                        remaining = deadline - time.monotonic()
                        if remaining < 1:
                            raise RuntimeError('No RPM inspection budget remaining')
                        rc, output, _ = _bounded_command([str(rpm), '-qf', '--', str(path)], min(5, remaining))
                        owner = output.strip()
                        row['rpm_owner'] = owner if rc == 0 and re.fullmatch(r'[A-Za-z0-9_.+:~\-]{1,255}', owner) else None
                        row['rpm_owned'] = rc == 0
                        if rc == 0:
                            remaining = deadline - time.monotonic()
                            if remaining < 1:
                                raise RuntimeError('No RPM verification budget remaining')
                            rc, output, _ = _bounded_command([str(rpm), '-Vf', '--noscripts', '--', str(path)], min(5, remaining))
                            row['rpm_package_verification_returncode'] = rc
                            row['rpm_package_reports_differences'] = bool(rc or output.strip())
                            row['rpm_reports_this_file'] = any(line.endswith(' '+str(path)) for line in output.splitlines())
                            if rc > 1:
                                result['incomplete'] = True
                        else:
                            row['needs_review'] = True
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                    result['issues'].append({'path':str(path), 'reason':str(exc)[:300]})
                    result['incomplete'] = True
        except (OSError, RuntimeError, ValueError) as exc:
            result['issues'].append({'path':str(original), 'reason':str(exc)[:300]})
            result['incomplete'] = True
    if not result['directories']:
        result['issues'].append({'reason':'No supported system Python package directories were inspected'})
        result['incomplete'] = True
    result['review_files'] = sum(bool(row['needs_review']) for row in result['files'])
    result['returncode'] = 2 if result['incomplete'] else 0
    return result


if __name__ == '__main__':
    report = audit()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(report['returncode'])

SATSUMA_PYTHON_AUDIT_PY
}

satsuma_browser_paths_audit() {
    /usr/bin/python3 -I -S - <<'SATSUMA_BROWSER_PATHS_PY'
#!/usr/bin/env python3
"""Bounded, read-only inventory of browser integration locations.

No referenced application is executed. Presence is not a malware verdict.
Run using: python3 -I -S work/browser_paths_audit.py
"""
import json
import os
import pwd
import re
import signal
import stat
import sys
import time

GNOME_HOSTS = frozenset(("org.gnome.browser_connector", "org.gnome.chrome_gnome_shell"))
HOST_NAME = re.compile(r"[a-z0-9_]+(?:\.[a-z0-9_]+)*\Z")
MAX_ERRORS = 100


class BudgetExhausted(RuntimeError):
    pass


def default_paths():
    paths = []
    for base in ("/usr/lib/mozilla", "/usr/lib64/mozilla"):
        for kind in ("extensions", "native-messaging-hosts", "plugins"):
            paths.append({"path": base + "/" + kind, "expected_uid": 0, "kind": kind})
    for path in ("/etc/chromium/native-messaging-hosts", "/etc/opt/chrome/native-messaging-hosts"):
        paths.append({"path": path, "expected_uid": 0, "kind": "native-messaging-hosts"})
    seen = set()
    for user in pwd.getpwall():
        if user.pw_uid < 1000 or user.pw_uid == 65534 or not user.pw_dir.startswith("/"):
            continue
        home = os.path.normpath(user.pw_dir)
        if home in seen or home == "/":
            continue
        seen.add(home)
        for suffix in (".mozilla", ".config/mozilla"):
            for kind in ("extensions", "native-messaging-hosts", "plugins"):
                paths.append({"path": os.path.join(home, suffix, kind),
                              "expected_uid": user.pw_uid, "kind": kind})
        for suffix in (".config/chromium/NativeMessagingHosts", ".config/google-chrome/NativeMessagingHosts"):
            paths.append({"path": os.path.join(home, suffix), "expected_uid": user.pw_uid,
                          "kind": "native-messaging-hosts"})
    return paths


def _metadata(st):
    if stat.S_ISREG(st.st_mode):
        kind = "regular"
    elif stat.S_ISDIR(st.st_mode):
        kind = "directory"
    elif stat.S_ISLNK(st.st_mode):
        kind = "symlink"
    else:
        kind = "special"
    return {"type": kind, "uid": st.st_uid, "gid": st.st_gid,
            "mode": oct(stat.S_IMODE(st.st_mode)), "size": st.st_size,
            "group_or_other_writable": bool(st.st_mode & 0o022)}


def inspect_paths(paths, deadline=None, max_entries=512, max_total=4096, max_json=1048576):
    """Inspect exact paths only. Dictionaries may specify expected_uid and kind.

    File symlinks and special files are never opened for reading; extensions
    subdirectories are reported without recursion. An absolute monotonic deadline
    may be supplied by a caller. The CLI also applies an OS alarm as a backstop.
    """
    if deadline is None:
        deadline = time.monotonic() + 15
    max_entries = min(512, max(0, int(max_entries)))
    max_total = min(4096, max(0, int(max_total)))
    max_json = min(1048576, max(0, int(max_json)))
    result = {"integration_present": False, "gnome_connector_manifest": False,
              "malware_assessment": "unknown", "policy_runtime_verified": False,
              "referenced_executables_launched": False, "directories": [], "entries_examined": 0, "incomplete": False,
              "errors": [], "limits": {"entries_per_directory": max_entries,
              "entries_total": max_total, "json_bytes": max_json, "seconds": 15}}

    def check():
        if time.monotonic() >= deadline:
            raise BudgetExhausted("time budget exhausted")

    def error(path, reason):
        result["incomplete"] = True
        if len(result["errors"]) < MAX_ERRORS:
            result["errors"].append({"path": path, "reason": reason})

    def open_directory(path, expected_uid, info):
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            current = ""
            for part in path.split("/"):
                if not part:
                    continue
                check()
                current += "/" + part
                # Pin before checking type: no symlink traversal or device open.
                pin = os.open(part, os.O_PATH | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    st = os.fstat(pin)
                    if stat.S_ISLNK(st.st_mode):
                        info["directory_symlink"] = current
                        info["blocked_component_metadata"] = _metadata(st)
                        raise OSError("directory symlink is not traversed")
                    if not stat.S_ISDIR(st.st_mode):
                        raise OSError("directory component is not a directory")
                    if st.st_uid not in (0, expected_uid) or st.st_mode & 0o022:
                        flags = info.setdefault("ancestor_permission_review", [])
                        if len(flags) < 16:
                            flags.append({"path": current, **_metadata(st)})
                    nxt = os.open("/proc/self/fd/%d" % pin, os.O_RDONLY | os.O_DIRECTORY)
                finally:
                    os.close(pin)
                os.close(fd)
                fd = nxt
            return fd
        except BaseException:
            os.close(fd)
            raise

    try:
        for spec in paths:
            check()
            if isinstance(spec, str):
                spec = {"path": spec, "expected_uid": os.getuid(),
                        "kind": "native-messaging-hosts" if "messaging" in spec else "integration"}
            path = spec["path"]
            if not isinstance(path, str) or not os.path.isabs(path):
                error(str(path), "absolute path required")
                continue
            expected = int(spec.get("expected_uid", 0))
            info = {"path": path, "kind": spec.get("kind", "integration"),
                    "exists": False, "entries": []}
            result["directories"].append(info)
            directory = None
            try:
                directory = open_directory(path, expected, info)
                info["exists"] = True
                info["metadata"] = _metadata(os.fstat(directory))
                # scandir(fd) yields names relative to the already pinned directory.
                with os.scandir(directory) as iterator:
                    for number, item in enumerate(iterator):
                        check()
                        if number >= max_entries:
                            info["truncated"] = True
                            error(path, "directory entry budget exhausted")
                            break
                        if result["entries_examined"] >= max_total:
                            raise BudgetExhausted("total entry budget exhausted")
                        result["entries_examined"] += 1
                        result["integration_present"] = True
                        entry = {"name": item.name, "malware_assessment": "unknown"}
                        info["entries"].append(entry)
                        pin = readfd = None
                        try:
                            pin = os.open(item.name, os.O_PATH | os.O_NOFOLLOW, dir_fd=directory)
                            before = os.fstat(pin)
                            entry.update(_metadata(before))
                            entry["ownership_review"] = before.st_uid not in (0, expected)
                            if stat.S_ISLNK(before.st_mode):
                                entry["content_read"] = False
                                continue
                            if not stat.S_ISREG(before.st_mode):
                                entry["content_read"] = False
                                continue
                            if info["kind"] != "native-messaging-hosts" or not item.name.endswith(".json"):
                                entry["content_read"] = False
                                continue
                            named_host = item.name[:-5]
                            if named_host in GNOME_HOSTS:
                                entry["known_gnome_filename"] = True
                            if before.st_size > max_json:
                                error(path + "/" + item.name, "manifest size budget exceeded")
                                entry["content_read"] = False
                                continue
                            check()
                            readfd = os.open("/proc/self/fd/%d" % pin, os.O_RDONLY | os.O_NONBLOCK)
                            opened = os.fstat(readfd)
                            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                                raise OSError("manifest changed during open")
                            chunks, size = [], 0
                            while size <= max_json:
                                check()
                                data = os.read(readfd, min(65536, max_json + 1 - size))
                                if not data:
                                    break
                                chunks.append(data)
                                size += len(data)
                            if size > max_json:
                                raise ValueError("manifest grew beyond size budget")
                            after = os.fstat(readfd)
                            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                                raise ValueError("manifest changed while reading")
                            manifest = json.loads(b"".join(chunks))
                            if not isinstance(manifest, dict):
                                raise ValueError("manifest is not an object")
                            entry["content_read"] = True
                            name = manifest.get("name")
                            if isinstance(name, str) and len(name) <= 255 and HOST_NAME.fullmatch(name):
                                entry["native_host_name"] = name
                            else:
                                entry["invalid_native_host_name"] = True
                            entry["native_host_type"] = "stdio" if manifest.get("type") == "stdio" else "other_or_missing"
                            executable = manifest.get("path")
                            if isinstance(executable, str):
                                entry["executable_basename"] = os.path.basename(executable)[:255]
                            entry["gnome_connector_manifest"] = isinstance(name, str) and name in GNOME_HOSTS
                            if entry["gnome_connector_manifest"]:
                                result["gnome_connector_manifest"] = True
                        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
                            error(path + "/" + item.name, type(exc).__name__)
                        finally:
                            for fd in (readfd, pin):
                                if fd is not None:
                                    os.close(fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                error(path, type(exc).__name__)
            finally:
                if directory is not None:
                    os.close(directory)
    except BudgetExhausted as exc:
        error("inventory", str(exc))
    return result


def main():
    def alarm(_signum, _frame):
        raise BudgetExhausted("time budget exhausted")
    old = signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, 15)
    try:
        report = inspect_paths(default_paths())
    except BudgetExhausted:
        report = {"integration_present": False, "gnome_connector_manifest": False,
                  "malware_assessment": "unknown", "policy_runtime_verified": False,
                  "incomplete": True, "errors": [{"reason": "time budget exhausted"}]}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 2 if report["incomplete"] else 0


if __name__ == "__main__":
    sys.exit(main())

SATSUMA_BROWSER_PATHS_PY
}

# Distro-native scanner bootstrap helpers. No code runs when this file is read.
# Caller must run the existing root/path trust preflight before mutations.
# All selected privileged paths are constants chosen from a platform enum.

satsuma_platform_config() {
    local platform_id
    platform_id=$(awk -F= '$1=="ID" {gsub(/["\047]/,"",$2); print $2; exit}' /etc/os-release) || return 1
    case "$platform_id" in
        debian|ubuntu)
            SATSUMA_PLATFORM_FAMILY=debian
            SATSUMA_PACKAGE_TOOL=apt-get
            SATSUMA_APT_ORIGIN=Debian
            [[ "$platform_id" != ubuntu ]] || SATSUMA_APT_ORIGIN=Ubuntu
            SATSUMA_CLAMD_UNIT=clamav-daemon.service
            SATSUMA_CLAMD_CONF=/etc/clamav/clamd.conf
            SATSUMA_CLAMD_USER=clamav
            SATSUMA_CLAMD_SOCKET=/run/clamav/clamd.ctl
            SATSUMA_FRESHCLAM_CONF=/etc/clamav/freshclam.conf
            SATSUMA_DATABASE_OWNER=clamav
            ;;
        fedora)
            SATSUMA_PLATFORM_FAMILY=fedora
            SATSUMA_PACKAGE_TOOL=dnf
            SATSUMA_CLAMD_UNIT=clamd@scan.service
            SATSUMA_CLAMD_CONF=/etc/clamd.d/scan.conf
            SATSUMA_CLAMD_USER=clamscan
            SATSUMA_CLAMD_SOCKET=/run/clamd.scan/clamd.sock
            SATSUMA_FRESHCLAM_CONF=/etc/freshclam.conf
            SATSUMA_DATABASE_OWNER=clamupdate
            ;;
        *) echo "Desteklenmeyen dağıtım: Debian/Ubuntu veya Fedora gerekli." >&2; return 1 ;;
    esac
    SATSUMA_FRESHCLAM_UNIT=clamav-freshclam.service
    SATSUMA_DATABASE_DIR=/var/lib/clamav
    SATSUMA_CLAMD_DROPIN="/etc/systemd/system/$SATSUMA_CLAMD_UNIT.d/satsuma-memory.conf"
    _CLAMD_SCAN_CONF="$SATSUMA_CLAMD_CONF"
    _CLAMD_MEM_DROPIN_DIR="/etc/systemd/system/$SATSUMA_CLAMD_UNIT.d"
    _CLAMD_MEM_DROPIN="$SATSUMA_CLAMD_DROPIN"
}

satsuma_install_platform_packages() (
    [[ $EUID -eq 0 ]] || { echo "Root gerekli" >&2; return 1; }
    satsuma_platform_config || return 1
    local -a required optional
    local stage='' package cmd
    if [[ "$SATSUMA_PLATFORM_FAMILY" == debian ]]; then
        required=(nftables suricata suricata-update clamav clamav-daemon clamav-freshclam
                  clamdscan auditd aide jq iproute2 conntrack python3 util-linux
                  wireguard-tools kmod kbd keyboard-configuration console-setup dnsutils net-tools ca-certificates procps policycoreutils policycoreutils-python-utils selinux-utils)
        # Temporarily restrict package selection to the distribution's signed
        # release origins. Do not add a third-party repository or key.
        stage=$(mktemp -d /run/satsuma-apt.XXXXXXXX) || return 1
        trap '[[ -z "$stage" ]] || rm -rf -- "$stage"' EXIT
        mkdir "$stage/empty-preferences" || return 1
        printf 'Package: *\nPin: release o=%s\nPin-Priority: 990\n\nPackage: *\nPin: version *\nPin-Priority: -1\n' "$SATSUMA_APT_ORIGIN" > "$stage/preferences" || return 1
        local -a apt_args
        apt_args=(-o "Dir::Etc::preferences=$stage/preferences"
                  -o "Dir::Etc::preferencesparts=$stage/empty-preferences"
                  -o Acquire::AllowInsecureRepositories=false
                  -o Acquire::AllowDowngradeToInsecureRepositories=false
                  -o APT::Get::AllowUnauthenticated=false)
        DEBIAN_FRONTEND=noninteractive apt-get "${apt_args[@]}" update || return 1
        DEBIAN_FRONTEND=noninteractive apt-get "${apt_args[@]}" install -y --no-install-recommends "${required[@]}" || return 1
        for package in rkhunter chkrootkit; do
            DEBIAN_FRONTEND=noninteractive apt-get "${apt_args[@]}" install -y --no-install-recommends "$package" ||
                echo "İsteğe bağlı paket kurulamadı: $package; ilgili katman kapalı bildirilecek." >&2
        done
    else
        # Fedora's suricata package already contains suricata-update. Freshclam
        # is named clamav-freshclam; it provides the older clamav-update alias.
        required=(nftables suricata clamav clamd clamav-freshclam audit aide jq iproute
                  conntrack-tools python3 util-linux wireguard-tools kmod kbd bind-utils
                  net-tools ca-certificates procps-ng policycoreutils policycoreutils-python-utils libselinux-utils)
        local -a dnf_args
        dnf_args=(--disablerepo='*' --enablerepo=fedora --enablerepo=updates --setopt=gpgcheck=True)
        dnf "${dnf_args[@]}" install -y "${required[@]}" || return 1
        for package in rkhunter chkrootkit; do
            dnf "${dnf_args[@]}" install -y "$package" ||
                echo "İsteğe bağlı paket kurulamadı: $package; ilgili katman kapalı bildirilecek." >&2
        done
    fi
    # Do not continue after a partial essential install.
    for cmd in nft suricata suricata-update clamdscan freshclam clamconf auditctl aide \
               jq ip ss conntrack python3 flock wg modprobe dig systemctl pgrep getenforce setenforce getsebool setsebool restorecon matchpathcon semanage; do
        command -v "$cmd" >/dev/null || { echo "Gerekli komut eksik: $cmd" >&2; return 1; }
    done
)

satsuma_report_optional_scanners() {
    if command -v rkhunter >/dev/null && command -v chkrootkit >/dev/null; then
        ENABLE_RKHUNTER=true
    else
        ENABLE_RKHUNTER=false
        echo "RKHunter/chkrootkit katmanı eksik paket nedeniyle devre dışı." >&2
    fi
}

satsuma_prepare_clamd_platform() {
    [[ $EUID -eq 0 ]] || return 1
    satsuma_platform_config || return 1
    # Python receives only an enum; it chooses every path and account below.
    /usr/bin/python3 -I -S - "$SATSUMA_PLATFORM_FAMILY" <<'SATSUMA_PREPARE_CLAMD_PY'
import datetime, os, pwd, stat, sys, tempfile
from pathlib import Path
platform=sys.argv[1]
if platform=='fedora':
    conf=Path('/etc/clamd.d/scan.conf'); fresh=Path('/etc/freshclam.conf')
    socket='/run/clamd.scan/clamd.sock'; user='clamscan'; owner='clamupdate'
elif platform=='debian':
    conf=Path('/etc/clamav/clamd.conf'); fresh=Path('/etc/clamav/freshclam.conf')
    socket='/run/clamav/clamd.ctl'; user=owner='clamav'
else: raise SystemExit('Unknown scanner platform')

def update(path, settings):
    # This helper deliberately does not create a missing package configuration.
    # A missing file means installation/configuration is incomplete.
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022 or st.st_nlink!=1:
        raise RuntimeError('Untrusted scanner configuration: '+str(path))
    if st.st_size>1048576: raise RuntimeError('Scanner configuration too large')
    raw=path.read_bytes(); lines=[]; seen=set()
    for line in raw.decode('utf-8').splitlines():
        stripped=line.strip()
        if stripped=='Example':
            lines.append('# Example disabled by Satsuma'); continue
        words=stripped.split()
        if path==conf and words and words[0] in ('TCPSocket','TCPAddr'):
            lines.append('# Disabled by Satsuma local-socket-only policy: '+line); continue
        if words and not stripped.startswith('#') and words[0] in settings:
            key=words[0]
            if key not in seen: lines.append(key+' '+settings[key]); seen.add(key)
        else: lines.append(line)
    for key,value in settings.items():
        if key not in seen: lines.append(key+' '+value)
    result=('\n'.join(lines)+'\n').encode()
    if result==raw: return
    stamp=datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
    # Root-only backup; do not expose a freshclam proxy password to other users.
    backup=path.with_name(path.name+'.satsuma-backup-'+stamp)
    fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out: out.write(raw); out.flush(); os.fsync(out.fileno())
    fd,name=tempfile.mkstemp(prefix='.satsuma-',dir=path.parent)
    try:
        os.fchmod(fd,stat.S_IMODE(st.st_mode)); os.fchown(fd,st.st_uid,st.st_gid)
        with os.fdopen(fd,'wb') as out: out.write(result); out.flush(); os.fsync(out.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)

pwd.getpwnam(user); pwd.getpwnam(owner)
update(conf,{'LocalSocket':socket,'LocalSocketMode':'660','User':user,
             'DatabaseDirectory':'/var/lib/clamav','FollowFileSymlinks':'no',
             'FollowDirectorySymlinks':'no','LogTime':'yes'})
update(fresh,{'DatabaseDirectory':'/var/lib/clamav','DatabaseOwner':owner,
              'TestDatabases':'yes','Bytecode':'yes'})
SATSUMA_PREPARE_CLAMD_PY
    [[ $? -eq 0 ]] || return 1
    if command -v restorecon >/dev/null && [[ -e /sys/fs/selinux/enforce ]]; then
        restorecon -v "$SATSUMA_CLAMD_CONF" "$SATSUMA_FRESHCLAM_CONF" || return 1
    fi
    if [[ "$SATSUMA_PLATFORM_FAMILY" == fedora ]]; then
        systemd-tmpfiles --create /usr/lib/tmpfiles.d/clamd.scan.conf || return 1
        command -v restorecon >/dev/null && restorecon -R /run/clamd.scan || true
    fi
}

satsuma_update_clamav_signatures() {
    [[ $EUID -eq 0 ]] || return 1
    satsuma_platform_config || return 1
    local updater_active=false unit i
    # Respect an already-running daemon or a scheduled one-shot. Never start a
    # second direct freshclam process against the same database directory.
    for unit in clamav-freshclam.service clamav-freshclam-once.service freshclam.service; do
        if systemctl is-active --quiet "$unit"; then updater_active=true; fi
    done
    if command -v pgrep >/dev/null && pgrep -x freshclam >/dev/null; then updater_active=true; fi
    if [[ "$updater_active" != true ]]; then
        if systemctl is-enabled --quiet clamav-freshclam-once.timer 2>/dev/null; then
            # Reuse the same one-shot unit as the timer, so systemd serializes
            # a simultaneous timer firing rather than starting another writer.
            systemctl start clamav-freshclam-once.service || return 1
        else
            systemctl enable --now "$SATSUMA_FRESHCLAM_UNIT" || return 1
        fi
    fi
    # The distro unit runs freshclam's authenticated CVD database updates. Clamd
    # will independently validate the database before its readiness ping passes.
    for ((i=0; i<120; i++)); do
        if [[ ( -s /var/lib/clamav/main.cvd || -s /var/lib/clamav/main.cld ) &&
              ( -s /var/lib/clamav/daily.cvd || -s /var/lib/clamav/daily.cld ) ]]; then
            return 0
        fi
        (( i % 4 != 0 )) || echo "ClamAV imzaları bekleniyor ($((i*5))/600 sn)..."
        sleep 5
    done
    echo "ClamAV imza veritabanı hazır olmadı; koruma başarılı sayılmadı." >&2
    return 1
}

satsuma_start_clamd_platform() {
    [[ $EUID -eq 0 ]] || return 1
    satsuma_platform_config || return 1
    systemctl enable --now "$SATSUMA_CLAMD_UNIT" || return 1
    local i
    for ((i=0; i<90; i++)); do
        systemctl is-active --quiet "$SATSUMA_CLAMD_UNIT" || return 1
        timeout 10 clamdscan --config-file "$SATSUMA_CLAMD_CONF" --ping 1 >/dev/null 2>&1 && return 0
        sleep 2
    done
    echo "Clamd platform servisi yanıt vermedi: $SATSUMA_CLAMD_UNIT" >&2
    return 1
}


# Source this helper into the managed script; it performs no work at load time.
# Requires distro-installed suricata, suricata-update, Python3/PyYAML, flock, timeout.
# No remote executable, arbitrary updater configuration or extra source is loaded.
satsuma_suricata_rules_bootstrap() (
    [[ $EUID -eq 0 ]] || { echo "Suricata kural kurulumu root gerektirir." >&2; return 1; }
    local binary updater stage output rules_path=/var/lib/satsuma-rules/suricata.rules
    local queue="${SURICATA_NFQUEUE_NUM:-0}" proxyvar
    local -a updater_env=(PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C)
    # Every exit says why (live session field run 2026-11-10: setup stopped here
    # without a message). Her çıkış nedenini yazar.
    [[ "$queue" =~ ^(0|[1-9][0-9]{0,4})$ ]] && (( queue <= 65535 )) || { echo "Suricata: geçersiz NFQUEUE numarası: $queue" >&2; return 1; }
    binary=$(command -v suricata) || { echo "Suricata: suricata komutu bulunamadı" >&2; return 1; }
    updater=$(command -v suricata-update) || { echo "Suricata: suricata-update komutu bulunamadı" >&2; return 1; }
    command -v flock >/dev/null && command -v timeout >/dev/null || { echo "Suricata: flock ya da timeout komutu yok" >&2; return 1; }
    # Retain only standard HTTP proxy routing, never updater/Python overrides.
    for proxyvar in HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; do
        [[ -v "$proxyvar" ]] && updater_env+=("$proxyvar=${!proxyvar}")
    done
    # Trusted root-owned paths only. Reject ancestor links before mkdir/open.
    /usr/bin/python3 -I -S - "$binary" "$updater" <<'SATSUMA_SURICATA_BOOTSTRAP_PATHS'
import os, stat, sys
from pathlib import Path
for path, create in [("/var/lib/satsuma-sentinel/suricata-bootstrap", True),
                     ("/var/lib/satsuma-rules", True)]:
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in Path(path).parts[1:]:
            created=False
            try: os.mkdir(part,0o755,dir_fd=fd); created=True
            except FileExistsError: pass
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd); fd=nxt
            st=os.fstat(fd)
            if st.st_uid!=0 or st.st_mode & 0o022:
                raise RuntimeError('Untrusted Suricata directory: '+path)
            if created and path=='/var/lib/satsuma-rules': os.fchmod(fd,0o755)
    finally: os.close(fd)
for value in [*sys.argv[1:], '/etc/suricata/suricata.yaml',
              '/var/lib/satsuma-sentinel/suricata-bootstrap/update.lock',
              '/var/lib/satsuma-rules/suricata.rules']:
    path=Path(value)
    # /sbin and similar distro aliases are normalized only for tool executables.
    if value in sys.argv[1:]: path=Path(os.path.realpath(path))
    for part in [*reversed(path.parents), path]:
        try: st=part.lstat()
        except FileNotFoundError: break
        if stat.S_ISLNK(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise RuntimeError('Untrusted Suricata path: '+str(part))
        if part==path and (not stat.S_ISREG(st.st_mode) or st.st_nlink!=1):
            raise RuntimeError('Not a single-link file: '+str(part))
SATSUMA_SURICATA_BOOTSTRAP_PATHS
    [[ $? -eq 0 ]] || { echo "Suricata: kural klasörü ya da program yolu güvenilir değil (ayrıntı yukarıda)" >&2; return 1; }
    local lock=/var/lib/satsuma-sentinel/suricata-bootstrap/update.lock
    exec 9>"$lock" || { echo "Suricata: kilit dosyası açılamadı: $lock" >&2; return 1; }
    if ! flock -w 30 9; then
        echo "Suricata: kural güncellemesi 30 sn kilit bekledi; başka bir işlem çalışıyor:" >&2
        fuser -v "$lock" >&2 2>&1 || ps -eo pid,etime,cmd | grep -E 'suricata-update|satsuma' | grep -v grep >&2
        return 1
    fi
    stage=$(mktemp -d /var/lib/satsuma-sentinel/suricata-bootstrap/stage.XXXXXXXX) || { echo "Suricata: geçici klasör açılamadı" >&2; return 1; }
    trap 'rm -rf -- "$stage"' EXIT
    mkdir -m 700 "$stage/data" "$stage/output" "$stage/log" || { echo "Suricata: geçici klasör hazırlanamadı" >&2; return 1; }
    # Fresh data-dir has no enabled third-party source definitions. An explicit
    # generated config prevents /etc/suricata/update.yaml shell-hook injection.
    cat > "$stage/update.yaml" <<'SATSUMA_MANAGED_UPDATE_YAML'
sources: []
local: []
etopen: true
disable-conf: /dev/null
enable-conf: /dev/null
modify-conf: /dev/null
drop-conf: /dev/null
test-command: null
reload-command: null
SATSUMA_MANAGED_UPDATE_YAML
    # ETOPEN_URL is intentionally absent from this clean environment; upstream
    # otherwise lets that variable replace the default HTTPS ET/Open feed.
    echo "Suricata ET/Open imzaları indiriliyor ve doğrulanıyor..."
    if ! timeout --kill-after=10s 900s env -i "${updater_env[@]}" \
        /usr/bin/python3 -I "$updater" \
        --config "$stage/update.yaml" --data-dir "$stage/data" \
        --suricata "$binary" --suricata-conf /etc/suricata/suricata.yaml \
        --output "$stage/output" --no-reload --fail \
        > "$stage/update.log" 2>&1; then
        tail -n 30 "$stage/update.log" >&2
        echo "ET/Open kural güncellemesi başarısız; önceki yönetilen kurallar korunuyor." >&2
        return 1
    fi
    output="$stage/output/suricata.rules"
    [[ -s "$output" && ! -L "$output" ]] || return 1
    grep -Eq '^(alert|drop|reject|pass)[[:space:]]' "$output" || return 1
    # A local acceptance-test rule proves the configured engine CAN drop traffic.
    # It is NOT evidence that ET/Open alert-only signatures automatically block.
    # Malware signatures remain at their published action until reviewed SIDs
    # are explicitly selected for conversion using a managed --drop-conf file.
    grep -Eq 'sid:[[:space:]]*99000001[[:space:]]*;' "$output" && {
        echo "Yerel IPS test SID değeri upstream kuralla çakışıyor." >&2; return 1;
    }
    cat >> "$output" <<'SATSUMA_LOCAL_IPS_RULE'
drop http any any -> any any (msg:"SATSUMA CONTROLLED IPS ACCEPTANCE TEST"; flow:established,to_server; http.user_agent; content:"Satsuma-IPS-Test-9c747c71"; startswith; sid:99000001; rev:1;)
SATSUMA_LOCAL_IPS_RULE
    timeout --kill-after=10s 300s env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
        "$binary" -T --init-errors-fatal -q "$queue" -c /etc/suricata/suricata.yaml -S "$output" \
        -l "$stage/log" -v > "$stage/test.log" 2>&1 || {
        tail -n 30 "$stage/test.log" >&2; return 1;
    }
    grep -Eq '[1-9][0-9]* rules successfully loaded' "$stage/test.log" || return 1
    # Atomic replacement only after the final exclusive ruleset passes -T -q.
    local installed
    installed=$(mktemp /var/lib/satsuma-rules/.satsuma-rules.XXXXXXXX) || return 1
    install -m 0644 -- "$output" "$installed" &&
        mv -f -- "$installed" "$rules_path" || { rm -f -- "$installed"; return 1; }
    echo "ET/Open kuralları ve yerel IPS kabul-test kuralı hazır: $rules_path"
    echo "Servis ve doğrulama aynı dosyayı -S $rules_path ile kullanmalıdır."
)

satsuma_audit_setup() {
    /usr/bin/python3 -I -S - "$@" <<'SATSUMA_AUDIT_SETUP_PY'
"""Manage only Satsuma-owned Linux audit watches; never clear global rules."""
import json, os, shlex, stat, subprocess, sys, tempfile
from pathlib import Path
KEYS=('satsuma_identity','satsuma_home_write','satsuma_dns_tamper','satsuma_suricata_config')
PERSIST=Path('/etc/audit/rules.d/70-satsuma-security.rules')

def run(args,check=True):
    p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=30)
    if check and p.returncode: raise RuntimeError('%s: %s'%(args[0],p.stderr.strip()[:500]))
    return p

def fingerprint(line):
    args=shlex.split(line); values={}; i=0
    while i<len(args):
        a=args[i]
        if a in ('-w','-p','-k') and i+1<len(args):
            values[{'-w':'path','-p':'perm','-k':'key'}[a]]=args[i+1]; i+=2; continue
        if a=='-F' and i+1<len(args):
            k,sep,v=args[i+1].partition('=')
            if sep and k in ('path','dir','perm','key'): values['path' if k=='dir' else k]=v
            i+=2; continue
        i+=1
    if set(values)>={'path','perm','key'}: return values['path'],''.join(sorted(set(values['perm']))),values['key']
    return None

def desired_watches():
    rows=[]; missing=[]
    for path,perms,key,required in [
        ('/etc/passwd','wa',KEYS[0],True),('/etc/shadow','wa',KEYS[0],True),
        ('/etc/sudoers','wa',KEYS[0],False),('/home','wa',KEYS[1],False),
        ('/etc/resolv.conf','a',KEYS[2],False),('/etc/hosts','a',KEYS[2],False),
        ('/etc/nsswitch.conf','wa',KEYS[2],False),('/etc/suricata/suricata.yaml','wa',KEYS[3],False)]:
        p=Path(path)
        if not p.exists():
            if required: raise RuntimeError('Required audit path missing: '+path)
            missing.append(path); continue
        # Symlinked resolver configs are legitimate; watch their canonical target.
        real=p.resolve(strict=True)
        if any(ch in str(real) for ch in ('\n','\r',' ')): raise RuntimeError('Unsupported audit path')
        st=real.stat()
        runtime_dns=(path=='/etc/resolv.conf' and str(real) in
                     ('/run/systemd/resolve/stub-resolv.conf','/run/systemd/resolve/resolv.conf'))
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
            raise RuntimeError('Unsupported audit target type: '+str(real))
        # This is an observation target, never executable/configuration input.
        # systemd-resolved owns its runtime files; don't chown them to root.
        if st.st_uid!=0 and not (runtime_dns and stat.S_ISREG(st.st_mode)):
            raise RuntimeError('Unexpected audit target owner: '+str(real))
        rows.append((str(real),''.join(sorted(perms)),key))
    return sorted(set(rows)),missing

def configure():
    if os.geteuid()!=0: raise RuntimeError('Root required')
    run(['systemctl','enable','auditd.service'])
    if run(['systemctl','is-active','--quiet','auditd.service'],False).returncode:
        run(['systemctl','start','auditd.service'])
    status=dict(line.split(None,1) for line in run(['auditctl','-s']).stdout.splitlines() if len(line.split(None,1))==2)
    enabled=status.get('enabled')
    if enabled not in ('0','1','2'): raise RuntimeError('Audit enabled state unavailable')
    desired,missing=desired_watches()
    current=[fingerprint(line) for line in run(['auditctl','-l']).stdout.splitlines()]
    current={row for row in current if row and row[2] in KEYS}
    if enabled=='2':
        if not set(desired)<=current: raise RuntimeError('Audit rules are immutable; required watches missing. Reboot with corrected persistent rules before activation.')
        return {'ok':True,'immutable':True,'changed':False,'optional_paths_absent':missing,'runtime_only_watches':[r[0] for r in desired if r[0].startswith('/run/')]}
    if enabled=='0': run(['auditctl','-e','1'])
    if current!=set(desired):
        # -D is always key-filtered, never applied to the administrator's rules.
        for key in KEYS:
            if any(row[2]==key for row in current): run(['auditctl','-D','-k',key])
        for path,perms,key in desired: run(['auditctl','-w',path,'-p',perms,'-k',key])
    observed={fingerprint(line) for line in run(['auditctl','-l']).stdout.splitlines()}
    if not set(desired)<=observed: raise RuntimeError('Audit watch readback mismatch')
    PERSIST.parent.mkdir(parents=True,exist_ok=True,mode=0o750)
    if PERSIST.is_symlink(): raise RuntimeError('Symlink audit rules file')
    fd,name=tempfile.mkstemp(prefix='.satsuma-',dir=PERSIST.parent)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o640)
            for path,perms,key in desired:
                if path.startswith('/run/'):continue  # recreated after boot; avoid ENOENT in early audit rule loading
                f.write('-w %s -p %s -k %s\n'%(path,perms,key))
            f.flush();os.fsync(f.fileno())
        os.replace(name,PERSIST)
        if Path("/sys/fs/selinux/enforce").exists():run(["restorecon","-v",str(PERSIST)])
    finally:
        if os.path.exists(name): os.unlink(name)
    return {'ok':True,'immutable':False,'watches':len(desired),'optional_paths_absent':missing,'runtime_only_watches':[r[0] for r in desired if r[0].startswith('/run/')]}

if __name__=='__main__':
    try: print(json.dumps(configure(),ensure_ascii=False,indent=2))
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        print('AUDIT-SETUP: '+str(exc),file=sys.stderr);sys.exit(2)
SATSUMA_AUDIT_SETUP_PY
}

satsuma_audit_poll() {
    /usr/bin/python3 -I -S - "$@" <<'SATSUMA_AUDIT_EVENTS_PY'
#!/usr/bin/env python3
"""Bounded incremental Linux audit reader. Never interprets audit text as code.

Counts distinct audited /home pathnames, not modified file contents. The first
poll starts at EOF. Operational gaps are explicit and never become burst alarms.
"""
import argparse
import base64
import json
import os
import re
import stat
import sys
import time

MAX_READ = 4 * 1024 * 1024
MAX_LINE = 64 * 1024
MAX_STATE = 16 * 1024 * 1024
MAX_PENDING = 4096
MAX_EVENT_PATHS = 128
MAX_ROLLING = 20000
MAX_PENDING_BYTES = 2 * 1024 * 1024
MAX_EVENT_BYTES = 64 * 1024
MAX_PATH_BYTES = 4096
MAX_ROLLING_PATH_BYTES = 4 * 1024 * 1024
IDLE_SECONDS = 2
KEYS = frozenset(("satsuma_home_write", "satsuma_identity", "satsuma_dns_tamper", "satsuma_suricata_config"))
CRITICAL = tuple(sorted(KEYS - {"satsuma_home_write"}))
TYPE_RE = re.compile(r"(?:^|\s)type=(SYSCALL|PATH|CWD|EOE)(?:\s|$)")
ID_RE = re.compile(r"\bmsg=audit\(([0-9]+(?:\.[0-9]+)?):([0-9]+)\)")
FIELD_RE = re.compile(r'(?:^|\s)([A-Za-z0-9_]+)=("[^"\r\n]*"|[^\s]+)')


def _decode(value):
    if value is None:
        return None
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", value):
        try:
            return bytes.fromhex(value).decode("utf-8", "replace")
        except ValueError:
            return None
    return None


def _path(name, cwd):
    if not name or name in ("(null)", "(none)") or "\x00" in name:
        return None
    if not name.startswith("/"):
        if not cwd or not cwd.startswith("/") or "\x00" in cwd:
            return None
        name = os.path.join(cwd, name)
    path = "/" + os.path.normpath(name).lstrip("/")
    return path if path.startswith("/home/") else None


def _state_directory(path):
    parent = os.path.dirname(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parent.split("/"):
            if not part:
                continue
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise RuntimeError("Untrusted audit state directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _load_state(dirfd, name):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > MAX_STATE:
            raise RuntimeError("Untrusted audit state file")
        data = os.read(fd, MAX_STATE + 1)
        obj = json.loads(data)
        if not isinstance(obj, dict) or obj.get("version") != 1:
            raise ValueError("Unsupported state")
        if not isinstance(obj.get("offset"), int) or obj["offset"] < 0:
            raise ValueError("Invalid offset")
        for key in ("pending", "home_paths", "home_events", "completed"):
            if not isinstance(obj.get(key), dict):
                raise ValueError("Invalid state collection")
        if len(obj["pending"]) > MAX_PENDING or any(len(obj[k]) > MAX_ROLLING for k in ("home_paths", "home_events", "completed")):
            raise ValueError("State collection over budget")
        return obj
    finally:
        os.close(fd)


def _save_state(dirfd, name, obj):
    payload = json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
    if len(payload) > MAX_STATE:
        raise RuntimeError("Audit state byte budget exceeded")
    temporary = ".audit-events-" + os.urandom(12).hex()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dirfd)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
        os.fsync(dirfd)
    finally:
        try:
            os.unlink(temporary, dir_fd=dirfd)
        except FileNotFoundError:
            pass


def _open_log(path):
    pin = os.open(path, os.O_PATH | os.O_NOFOLLOW)
    try:
        info = os.fstat(pin)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("Audit log must be a regular file")
        return os.open("/proc/self/fd/%d" % pin, os.O_RDONLY | os.O_NONBLOCK)
    finally:
        os.close(pin)


def audit_poll(log_path, state_path, threshold=500, window=60):
    """Return (JSON-compatible report, exit code). Exit 2 means incomplete I/O.

    A threshold result remains a neutral observation and does not cause exit 1.
    Caller must serialize polls (the parent scanner already holds a scan lock).
    """
    now = time.time()
    report = {
        "event": "audit_summary", "time": now, "window_seconds": window,
        "threshold": threshold, "metric": "distinct audited /home pathnames",
        "baseline_only": False, "reset": None, "incomplete": False, "issues": [],
        "bytes_read": 0, "records_read": 0, "completed_events": 0,
        "successful_home_events": 0, "failed_home_events": 0,
        "home_events_in_window": 0, "home_unique_paths": 0,
        "threshold_exceeded": False, "pending_events": 0,
        "unmatched_events": 0, "expired_events": 0, "duplicate_events": 0,
        "critical": {key: {"successful_events": 0, "failed_events": 0, "unknown_outcome_events": 0} for key in CRITICAL},
    }
    dirfd = logfd = None

    def issue(reason):
        report["incomplete"] = True
        if reason not in report["issues"] and len(report["issues"]) < 30:
            report["issues"].append(reason)

    try:
        if not isinstance(threshold, int) or threshold < 1 or not isinstance(window, int) or not 1 <= window <= 3600:
            raise ValueError("Invalid threshold/window")
        dirfd = _state_directory(state_path)
        state_name = os.path.basename(state_path)
        try:
            state = _load_state(dirfd, state_name)
        except (ValueError, TypeError, KeyError):
            state = None
            issue("invalid_state_baseline_reset")
        logfd = _open_log(log_path)
        info = os.fstat(logfd)
        identity = [info.st_dev, info.st_ino]
        if state is None:
            state = {"version": 1, "identity": identity, "offset": info.st_size, "tail": "", "dropping_line": False,
                     "anchor": "", "pending": {}, "home_paths": {}, "home_events": {}, "completed": {}}
            if info.st_size:
                state["anchor"] = base64.b64encode(os.pread(logfd, min(64, info.st_size), max(0, info.st_size - 64))).decode("ascii")
            _save_state(dirfd, state_name, state)
            report["baseline_only"] = True
            return report, 2 if report["incomplete"] else 0
        offset = state["offset"]
        reset = None
        if state.get("identity") != identity:
            reset = "rotated"
        elif info.st_size < offset:
            reset = "truncated"
        elif offset and state.get("anchor"):
            old_anchor = base64.b64decode(state["anchor"], validate=True)
            current = os.pread(logfd, len(old_anchor), offset - len(old_anchor))
            if current != old_anchor:
                reset = "rewritten"
        if reset:
            report["reset"] = reset
            if state["pending"] or state.get("tail") or state.get("dropping_line"):
                report["unmatched_events"] += len(state["pending"])
                issue("partial_records_discarded_on_log_reset")
            state.update(identity=identity, offset=0, tail="", dropping_line=False, pending={})
            offset = 0
        cutoff = now - window
        for key in ("home_paths", "home_events", "completed"):
            state[key] = {name: ts for name, ts in state[key].items() if isinstance(ts, (int, float)) and cutoff <= ts <= now + 5}
        pending = state["pending"]
        pending_bytes = sum(len(e.get("cwd", "").encode("utf-8")) + sum(len(p.encode("utf-8")) for p in e.get("paths", [])) for e in pending.values())
        rolling_path_bytes = sum(len(name.encode("utf-8")) for name in state["home_paths"])
        if pending_bytes > MAX_PENDING_BYTES or rolling_path_bytes > MAX_ROLLING_PATH_BYTES:
            raise ValueError("Cached path byte budget exceeded")

        def finish(event_id, event):
            nonlocal rolling_path_bytes
            report["completed_events"] += 1
            if event_id in state["completed"]:
                report["duplicate_events"] += 1
                return
            ts = event.get("ts", 0)
            if ts < cutoff:
                report["expired_events"] += 1
                return
            if ts > now + 5:
                issue("future_event_timestamp")
                return
            if not event.get("syscall"):
                report["unmatched_events"] += 1
                return
            keys = set(event.get("keys", [])) & KEYS
            if not keys:
                return
            state["completed"][event_id] = ts
            if len(state["completed"]) > MAX_ROLLING:
                state["completed"].pop(next(iter(state["completed"])))
                issue("completed_event_budget")
            success = event.get("success")
            for key in keys & set(CRITICAL):
                field = "successful_events" if success == "yes" else "failed_events" if success == "no" else "unknown_outcome_events"
                report["critical"][key][field] += 1
            if "satsuma_home_write" not in keys:
                return
            if success != "yes":
                if success == "no":
                    report["failed_home_events"] += 1
                else:
                    report["unmatched_events"] += 1
                return
            names = {_path(name, event.get("cwd")) for name in event.get("paths", [])}
            names.discard(None)
            if not names:
                report["unmatched_events"] += 1
                return
            report["successful_home_events"] += 1
            state["home_events"][event_id] = ts
            for name in names:
                if name not in state["home_paths"]:
                    size = len(name.encode("utf-8"))
                    if len(state["home_paths"]) >= MAX_ROLLING or rolling_path_bytes + size > MAX_ROLLING_PATH_BYTES:
                        issue("rolling_path_budget")
                        continue
                    rolling_path_bytes += size
                state["home_paths"][name] = max(ts, state["home_paths"].get(name, 0))
            if len(state["home_events"]) > MAX_ROLLING:
                state["home_events"].pop(next(iter(state["home_events"])))
                issue("rolling_event_budget")

        def finish_pending(event_id):
            nonlocal pending_bytes
            event = pending.pop(event_id)
            pending_bytes -= len(event.get("cwd", "").encode("utf-8")) + sum(len(p.encode("utf-8")) for p in event.get("paths", []))
            finish(event_id, event)

        chunk = os.pread(logfd, MAX_READ, offset)
        report["bytes_read"] = len(chunk)
        state["offset"] = offset + len(chunk)
        data = base64.b64decode(state.get("tail", ""), validate=True) + chunk
        pieces = data.split(b"\n")
        lines, tail = pieces[:-1], pieces[-1]
        if state.get("dropping_line") and lines:
            lines.pop(0)
            state["dropping_line"] = False
        if len(tail) > MAX_LINE:
            tail = b""
            state["dropping_line"] = True
            issue("oversized_record")
        state["tail"] = base64.b64encode(tail).decode("ascii")
        for raw in lines:
            if len(raw) > MAX_LINE:
                issue("oversized_record")
                continue
            text = raw.decode("utf-8", "replace")
            typematch, idmatch = TYPE_RE.search(text), ID_RE.search(text)
            if not typematch or not idmatch:
                continue
            report["records_read"] += 1
            kind = typematch.group(1)
            event_id = idmatch.group(1) + ":" + idmatch.group(2)
            fields = {key: value for key, value in FIELD_RE.findall(text)}
            ts = float(idmatch.group(1))
            if event_id not in pending:
                if len(pending) >= MAX_PENDING:
                    oldest = min(pending, key=lambda key: pending[key].get("last_seen", 0))
                    finish_pending(oldest)
                    issue("pending_event_budget")
                pending[event_id] = {"ts": ts, "last_seen": now, "paths": [], "keys": [], "syscall": False}
            event = pending[event_id]
            event["last_seen"] = now
            if kind == "SYSCALL":
                event["syscall"] = True
                event["success"] = fields.get("success", "")
                raw_key = fields.get("key", "")
                decoded_key = _decode(raw_key) if raw_key.startswith('"') else raw_key
                event["keys"] = list(set(re.split(r"[\x01,]", decoded_key or "")) & KEYS)
            elif kind == "PATH":
                if fields.get("nametype", "").strip('"') != "PARENT":
                    name = _decode(fields.get("name"))
                    if name is not None:
                        size = len(name.encode("utf-8"))
                        event_size = len(event.get("cwd", "").encode("utf-8")) + sum(len(p.encode("utf-8")) for p in event["paths"])
                        if size <= MAX_PATH_BYTES and len(event["paths"]) < MAX_EVENT_PATHS and event_size + size <= MAX_EVENT_BYTES and pending_bytes + size <= MAX_PENDING_BYTES:
                            event["paths"].append(name)
                            pending_bytes += size
                        else:
                            issue("event_path_budget")
            elif kind == "CWD":
                cwd = _decode(fields.get("cwd"))
                old_size = len(event.get("cwd", "").encode("utf-8"))
                size = len((cwd or "").encode("utf-8"))
                if cwd is not None and size <= MAX_PATH_BYTES and pending_bytes - old_size + size <= MAX_PENDING_BYTES:
                    event["cwd"] = cwd
                    pending_bytes += size - old_size
                else:
                    issue("event_cwd_budget")
            elif kind == "EOE":
                finish_pending(event_id)
        current_size = os.fstat(logfd).st_size
        backlog = current_size > state["offset"]
        if backlog:
            issue("read_budget_backlog")
        else:
            for event_id in list(pending):
                event = pending[event_id]
                if now - event.get("last_seen", now) >= IDLE_SECONDS:
                    finish_pending(event_id)
        if state["offset"]:
            state["anchor"] = base64.b64encode(os.pread(logfd, min(64, state["offset"]), max(0, state["offset"] - 64))).decode("ascii")
        report["pending_events"] = len(pending)
        report["home_events_in_window"] = len(state["home_events"])
        report["home_unique_paths"] = len(state["home_paths"])
        report["threshold_exceeded"] = report["home_unique_paths"] >= threshold
        _save_state(dirfd, state_name, state)
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, OverflowError) as exc:
        issue("audit_poll_failed:" + type(exc).__name__)
    finally:
        if logfd is not None:
            os.close(logfd)
        if dirfd is not None:
            os.close(dirfd)
    return report, 2 if report["incomplete"] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", default="/var/log/audit/audit.log")
    parser.add_argument("--state", default="/var/lib/satsuma-sentinel/state/audit-events.json")
    parser.add_argument("--threshold", type=int, default=500)
    parser.add_argument("--window", type=int, default=60)
    args = parser.parse_args()
    result, code = audit_poll(args.log, args.state, args.threshold, args.window)
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())

SATSUMA_AUDIT_EVENTS_PY
}

satsuma_network_guard() {
    /usr/bin/python3 -I -S - "$@" <<'SATSUMA_NETWORK_GUARD_PY'
"""Pure current-socket threshold decisions. No network or firewall actions.

The global emergency threshold is a user-chosen operational policy, not evidence
of malware. A normal browser or VPN workload can exceed it. OTX reputation is
intentionally independent of the socket/subnet thresholds in this module.
"""
from collections import defaultdict
from collections.abc import Mapping
import ipaddress

MAX_SOCKETS = 4096
MAX_PROTECTIONS = 4096
MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024


def _integer(value, minimum, maximum, name):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError('Invalid ' + name)
    return value


def _address(value):
    try:
        addr = ipaddress.ip_address(value)
    except (ValueError, TypeError) as exc:
        raise ValueError('Invalid peer address') from exc
    # Socket output may describe IPv4 peers through an IPv6-mapped address.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _endpoint(value):
    """Return (address, port, interface) from ss IPv4/IPv6 endpoint syntax."""
    if not isinstance(value, str) or ':' not in value:
        return None
    host, port = value.rsplit(':', 1)
    if not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
        return None
    host = host.removeprefix('[').removesuffix(']')
    if host in ('*', ''):
        return None
    interface = ''
    if '%' in host:
        host, interface = host.rsplit('%', 1)
        if not interface or any(c.isspace() for c in interface):
            return None
    try:
        addr = _address(host)
    except ValueError:
        return None
    if addr.is_unspecified:
        return None
    return addr, int(port), interface


def parse_ss_snapshot(text):
    """Parse ``ss -Htun``; count TCP ESTAB and connected UDP ESTAB peers.

    Every retained row is one current socket, even if several sockets reach the
    same peer. TCP SYN/LISTEN and UDP UNCONN/listeners are excluded. The call
    must be a current snapshot in this network namespace; no historic merging.
    A budget error yields no partial decisions; the caller must handle it.
    """
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_SNAPSHOT_BYTES:
        raise ValueError('Socket snapshot exceeds byte budget')
    rows = text.splitlines()
    if len(rows) > MAX_SOCKETS:
        raise ValueError('Socket snapshot exceeds row budget')
    sockets = []
    for row in rows:
        columns = row.split()
        if not columns:
            continue
        # Expected columns: Netid State Recv-Q Send-Q LocalAddress PeerAddress.
        # This intentionally does not accept display headers or guessed layouts.
        if len(columns) < 6:
            raise ValueError('Unrecognized ss snapshot layout')
        proto, state = columns[0].lower(), columns[1].upper()
        if proto not in ('tcp', 'tcp6', 'udp', 'udp6'):
            raise ValueError('Unrecognized socket protocol')
        if state != 'ESTAB':
            continue
        endpoint = _endpoint(columns[5])
        if endpoint is None:
            continue
        peer, port, interface = endpoint
        if peer.is_loopback:
            continue
        local = _endpoint(columns[4])
        sockets.append({'protocol': 'udp' if proto.startswith('udp') else 'tcp',
                        'state': 'ESTAB', 'remote_ip': str(peer),
                        'remote_port': port,
                        'interface': interface or (local[2] if local else '')})
    return sockets


def _protection_networks(values):
    result = []
    for index, value in enumerate(values):
        if index >= MAX_PROTECTIONS:
            raise ValueError('Protection inventory exceeds budget')
        try:
            network = ipaddress.ip_network(value, strict=False)
        except (ValueError, TypeError) as exc:
            raise ValueError('Invalid protected IP/network') from exc
        result.append(network)
    return result


def classify_thresholds(connections, protected_ips=(), threshold30=30, subnet10=10):
    """Return a latched-cutoff decision and IPv4 /24 candidates; apply nothing.

    ``connections`` is the list returned by parse_ss_snapshot. Every record must
    represent a CURRENT connected TCP/UDP socket. IPv6, WireGuard peers, DNS,
    private destinations and protected peers ALL count toward the global cutoff.
    This explicitly matches the user's total-device cutoff choice.

    Subnet broadening independently needs >=subnet10 distinct active IPv4 peers
    in the SAME /24; multiple ports/sockets to one address count once. No OTX
    positive verdict is needed. Any overlapping protected IP/CIDR suppresses
    that subnet block, even if the protected address is not currently connected.
    Runtime code should supply active WireGuard endpoints, resolver/gateway IPs
    and any specifically configured CDN exemptions, not broad inferred ranges.
    """
    _integer(threshold30, 1, MAX_SOCKETS, 'global socket threshold')
    _integer(subnet10, 2, 256, 'distinct peer threshold')
    protections = _protection_networks(protected_ips)
    groups = defaultdict(set)
    count = 0
    for index, record in enumerate(connections):
        if index >= MAX_SOCKETS:
            raise ValueError('Current socket inventory exceeds budget')
        if not isinstance(record, Mapping):
            raise ValueError('Expected socket record mappings')
        proto = record.get('protocol')
        state = record.get('state')
        if proto not in ('tcp','udp') or state != 'ESTAB':
            raise ValueError('Snapshot contains a non-connected socket')
        peer = _address(record.get('remote_ip'))
        _integer(record.get('remote_port'), 1, 65535, 'peer port')
        if peer.is_loopback or peer.is_unspecified:
            continue
        count += 1
        if isinstance(peer, ipaddress.IPv4Address):
            groups[ipaddress.IPv4Network((int(peer) & 0xffffff00,24))].add(peer)
    blocks, exemptions, evidence = [], [], {}
    for network, peers in groups.items():
        if len(peers) < subnet10:
            continue
        evidence[str(network)] = [str(p) for p in sorted(peers, key=int)]
        if any(network.version == p.version and network.overlaps(p) for p in protections):
            exemptions.append(network)
        else:
            blocks.append(network)
    order = lambda n: int(n.network_address)
    return {'connected_socket_count':count,
            'emergency_cutoff':count >= threshold30,
            'block_subnets':[str(n) for n in sorted(blocks,key=order)],
            'protected_subnet_exemptions':[str(n) for n in sorted(exemptions,key=order)],
            'subnet_evidence':evidence,
            'requires_otx_for_subnet':False,
            'snapshot_scope':'current network namespace; TCP ESTAB and connected UDP'}


def classify_ss(text, protected_ips=(), threshold30=30, subnet10=10):
    return classify_thresholds(parse_ss_snapshot(text),protected_ips,threshold30,subnet10)

"""Fast.log candidates require recent matching EVE and a live TCP peer.
UDP is review-only for IP-wide bans; Suricata packet verdicts are unchanged.
"""
import datetime, json, os, re, stat, time
from pathlib import Path

def bounded_log(path,limit=2*1048576,offset=None):
    pin=fd=None
    try:
        pin=os.open(path,os.O_PATH|os.O_NOFOLLOW);st=os.fstat(pin)
        if not stat.S_ISREG(st.st_mode):raise RuntimeError('Not a regular log')
        fd=os.open('/proc/self/fd/%d'%pin,os.O_RDONLY|os.O_NONBLOCK)
        start=max(0,st.st_size-limit) if offset is None else min(offset,st.st_size)
        os.lseek(fd,start,os.SEEK_SET);data=os.read(fd,limit)
        return data,st,start+len(data)
    except FileNotFoundError:return b'',None,0
    finally:
        for d in (fd,pin):
            if d is not None:os.close(d)

def verified_fastlog(state,protected,now=None):
    now=time.time() if now is None else now
    events={};result={'ips':[],'udp_review':0,'unverified':0}
    eve,_,_=bounded_log('/var/log/suricata/eve.json')
    for line in eve.splitlines():
        if len(line)>65536:continue
        try:
            e=json.loads(line)
            if e.get('event_type')!='alert' or e.get('proto')!='TCP':continue
            if e.get('alert',{}).get('severity') not in (1,2,3):continue
            ts=datetime.datetime.fromisoformat(e['timestamp'].replace('Z','+00:00')).timestamp()
            if not -5<=now-ts<=120:continue
            flow=e.get('flow',{})
            if flow.get('pkts_toserver',0)<=0 or flow.get('pkts_toclient',0)<=0:continue
            key=(int(e['alert']['signature_id']),e['src_ip'],e['dest_ip'])
            events[key]=e
        except (ValueError,KeyError,TypeError):continue
    data,st,end=bounded_log('/var/log/suricata/fast.log',offset=state.get('fast_offset',0))
    if st is None:return result
    identity=[st.st_dev,st.st_ino]
    if state.get('fast_identity') not in (None,identity) or state.get('fast_offset',0)>st.st_size:
        data,st,end=bounded_log('/var/log/suricata/fast.log',offset=0)
        state['fast_partial']=''
    raw=state.get('fast_partial','').encode()+data
    lines=raw.split(b'\n');partial=lines.pop()
    state.update(fast_identity=identity,fast_offset=end,fast_partial=partial.decode('utf-8','replace') if len(partial)<65536 else '')
    peers=set()
    for line in command(['ss','-Htn','state','established']).stdout.splitlines():
        fields=line.split()
        if len(fields)>=4:
            parsed=_endpoint(fields[3])
            if parsed:peers.add(str(parsed[0]))
    protected_nets=_protection_networks(protected)
    for line in lines:
        if len(line)>65536:result['unverified']+=1;continue
        text=line.decode('utf-8','replace')
        sid=re.search(r'\[\d+:(\d+):\d+\]',text)
        priority=re.search(r'\[Priority:\s*([123])\]',text)
        packet=re.search(r'\{(TCP|UDP)\}\s+(\S+)\s+->\s+(\S+)',text)
        if not sid or not priority or not packet:continue
        if packet[1]=='UDP':result['udp_review']+=1;continue
        src=_endpoint(packet[2]);dst=_endpoint(packet[3])
        if not src or not dst:result['unverified']+=1;continue
        key=(int(sid[1]),str(src[0]),str(dst[0]))
        if key not in events:result['unverified']+=1;continue
        for addr in (src[0],dst[0]):
            if addr.version!=4 or str(addr) not in peers:continue
            if any(addr.version==n.version and addr in n for n in protected_nets):continue
            result['ips'].append(str(addr))
    result['ips']=sorted(set(result['ips']))
    return result

# Runtime appended to the pure threshold classifier. Never invoke through a shell.
import fcntl, json, os, stat, subprocess, sys, tempfile, time
from pathlib import Path
STATE=Path('/var/lib/satsuma-sentinel/state/network-guard.json')

def command(args,check=True,input=None):
    p=subprocess.run(args,input=input,stdin=None if input is not None else subprocess.DEVNULL,
                     text=True,capture_output=True,timeout=15)
    if check and p.returncode: raise RuntimeError(args[0]+': '+p.stderr[-400:])
    return p

def secure_state_dir():
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in STATE.parent.parts[1:]:
            try: os.mkdir(part,0o700,dir_fd=fd)
            except FileExistsError: pass
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=nxt;st=os.fstat(fd)
            if st.st_uid!=0 or st.st_mode&0o022: raise RuntimeError('Untrusted network state directory')
    finally: os.close(fd)

def load_state():
    try: fd=os.open(STATE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    except FileNotFoundError: return {'latched':False,'subnets':[]}
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or st.st_nlink!=1 or st.st_size>1048576:
            raise RuntimeError('Untrusted network state')
        data=json.loads(os.read(fd,1048577))
        if not isinstance(data.get('latched'),bool) or not isinstance(data.get('subnets'),list): raise ValueError('Invalid network state')
        data['subnets']=[str(ipaddress.IPv4Network(n)) for n in data['subnets'][:4096]]
        return data
    finally: os.close(fd)

def save_state(data):
    fd,name=tempfile.mkstemp(prefix='.network-',dir=STATE.parent)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600);json.dump(data,f);f.flush();os.fsync(f.fileno())
        os.replace(name,STATE)
    finally:
        if os.path.exists(name):os.unlink(name)

def emergency():
    # A distinct table can be removed without flushing other security rules.
    batch='add table inet satsuma_emergency\ndelete table inet satsuma_emergency\ntable inet satsuma_emergency {\n'
    for hook in ('input','output','forward'):
        loop='iifname "lo" accept;' if hook=='input' else 'oifname "lo" accept;' if hook=='output' else ''
        batch+='chain '+hook+' { type filter hook '+hook+' priority -100; policy drop; '+loop+' counter drop; }\n'
    batch+='}\n'
    command(['nft','-c','-f','-'],input=batch);command(['nft','-f','-'],input=batch)

def protections():
    result={'127.0.0.0/8','192.168.1.1','192.168.1.2'}
    try:
        for row in json.loads(command(['ip','-j','route','show','default']).stdout):
            if row.get('gateway'): result.add(str(ipaddress.ip_address(row['gateway'])))
        for row in json.loads(command(['ip','-j','address','show']).stdout):
            for addr in row.get('addr_info',[]):
                if addr.get('local'): result.add(str(ipaddress.ip_address(addr['local'])))
        for line in Path('/etc/resolv.conf').read_text().splitlines():
            fields=line.split()
            if len(fields)>1 and fields[0]=='nameserver': result.add(str(ipaddress.ip_address(fields[1])))
        for line in command(['wg','show','all','endpoints'],False).stdout.splitlines():
            endpoint=line.split()[-1]
            parsed=_endpoint(endpoint)
            if parsed: result.add(str(parsed[0]))
    except (OSError,ValueError,IndexError) as exc:
        raise RuntimeError('Infrastructure exemption inventory incomplete') from exc
    return sorted(result)

def step(mode='check'):
    if os.geteuid()!=0: raise RuntimeError('Root required')
    secure_state_dir()
    lockfd=os.open(STATE.parent/'network-guard.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lockfd,fcntl.LOCK_EX)
        state=load_state()
        if mode=='reset':
            if command(['nft','list','table','inet','satsuma_emergency'],False).returncode==0:
                command(['nft','delete','table','inet','satsuma_emergency'])
            state['latched']=False;save_state(state)
            return {'latched':False,'note':'Only global cutoff cleared; threshold rechecks continue. Subnet bans retained.'}
        if mode=='enforce-state':
            for subnet in state['subnets']:
                args=['nft','get','element','inet','satsuma_filter','blocked_ips','{',subnet,'}']
                if command(args,False).returncode: command(['nft','add',*args[2:]])
            if state['latched']: emergency()
            return {'latched':state['latched']}
        if state['latched']:
            emergency();return {'latched':True,'reason':'global 30 socket threshold; manual reset required'}
        raw=command(['ss','-Htun']).stdout
        # A very large snapshot already exceeds the explicit30 threshold if
        # its first bounded prefix contains30 verified connected socket rows.
        try: report=classify_ss(raw,protections())
        except ValueError:
            prefix='\n'.join(raw.splitlines()[:4096])[:MAX_SNAPSHOT_BYTES]
            report=classify_ss(prefix,protections())
            if report['connected_socket_count']<30: raise
            report['snapshot_truncated']=True
        new=[]
        if report['emergency_cutoff']:
            emergency();state['latched']=True
            # Flush network state, not the rest of the firewall. TCP sockets
            # may remain visible until their applications time out.
            command(['conntrack','-F'],False)
        else:
            for subnet in report['block_subnets']:
                if subnet in state['subnets']: continue
                command(['nft','add','element','inet','satsuma_filter','blocked_ips','{',subnet,'}'])
                state['subnets'].append(subnet);new.append(subnet)
        if not state['latched']:
            fast=verified_fastlog(state,protections())
            for ip in fast['ips']:
                args=['nft','get','element','inet','satsuma_filter','blocked_ips','{',ip,'}']
                if command(args,False).returncode: command(['nft','add',*args[2:]])
            report['fastlog']=fast
        save_state(state);report.update(latched=state['latched'],new_subnets=new)
        return report
    finally: os.close(lockfd)

def runtime_main():
    mode=sys.argv[1] if len(sys.argv)>1 else 'check'
    if mode not in ('check','watch','reset','enforce-state'): raise ValueError('Unknown network operation')
    while True:
        try:
            result=step('check' if mode=='watch' else mode)
            print(json.dumps(result,ensure_ascii=True),flush=True)
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
            print(json.dumps({'incomplete':True,'error':str(exc)}),flush=True)
            if mode!='watch': return 2
        if mode!='watch':return 0
        time.sleep(3)

if __name__=='__main__':sys.exit(runtime_main())

SATSUMA_NETWORK_GUARD_PY
}

# Source-inert: functions run only through the caller's explicit setup/CLI.
# noexec blocks direct execution; interpreters can still read scripts. This is
# not a complete code-execution ban. No files are erased and fstab is untouched.
_satsuma_tmp_require_root() {
    [[ $EUID -eq 0 ]] || { echo "Geçici alan sertleştirmesi root gerektirir." >&2; return 1; }
}

_satsuma_tmp_validate() {
    /usr/bin/python3 -I -S - "$@" <<'SATSUMA_TMP_PATHS_PY'
import os, stat, sys
from pathlib import Path

def trusted_directory(path, sticky_leaf=False):
    for component in [*reversed(Path(path).parents), Path(path)]:
        st=component.lstat()
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid!=0:
            raise RuntimeError('Güvensiz dizin: '+str(component))
        if st.st_mode & 0o022:
            if not (sticky_leaf and str(component)==path and st.st_mode & stat.S_ISVTX):
                raise RuntimeError('Yazılabilir güvensiz üst dizin: '+str(component))

def trusted_file(path, required=False):
    trusted_directory(str(Path(path).parent))
    try: st=Path(path).lstat()
    except FileNotFoundError:
        if required: raise
        return
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022 or st.st_nlink!=1:
        raise RuntimeError('Güvensiz dosya: '+path)

try:
    if os.geteuid()!=0: raise RuntimeError('Root gerekli')
    if sys.argv[1:]==['--install']:
        trusted_file('/usr/local/bin/satsuma-mini', required=True)
        trusted_file('/etc/systemd/system/satsuma-tmp-hardening.service')
    elif not sys.argv[1:]:
        for directory in ('/tmp','/var/tmp','/dev/shm'):
            trusted_directory(directory, sticky_leaf=True)
    else:
        raise RuntimeError('Desteklenmeyen doğrulama seçeneği')
except (OSError,RuntimeError) as exc:
    print(str(exc),file=sys.stderr)
    sys.exit(1)
SATSUMA_TMP_PATHS_PY
}

_satsuma_tmp_mount_info() {
    # Exact fixed paths contain no spaces; -T reports the effective covering
    # mount, which may be / before a directory is made its own bind mount.
    findmnt -rn -T "$1" -o TARGET,VFS-OPTIONS
}

_satsuma_tmp_has_flags() {
    local flags="$1" flag
    for flag in noexec nosuid nodev; do
        [[ ",$flags," == *",$flag,"* ]] || return 1
    done
}

satsuma_tmp_harden() {
    _satsuma_tmp_require_root || return 1
    _satsuma_tmp_validate || return 1
    command -v findmnt >/dev/null && command -v mount >/dev/null || return 1
    local target mounted flags info
    for target in /tmp /var/tmp /dev/shm; do
        info=$(_satsuma_tmp_mount_info "$target") || {
            echo "Mount bilgisi okunamadı: $target" >&2; return 1;
        }
        [[ "$info" != *$'\n'* ]] || { echo "Belirsiz mount bilgisi: $target" >&2; return 1; }
        read -r mounted flags <<< "$info"
        [[ "$flags" =~ ^[a-zA-Z0-9_,=-]+$ ]] || return 1
        if [[ "$mounted" == "$target" ]] && _satsuma_tmp_has_flags "$flags"; then
            printf '%s\n' "$target: noexec,nosuid,nodev doğrulandı (mevcut mount)."
            continue
        fi
        if [[ "$mounted" != "$target" ]]; then
            mount --bind -- "$target" "$target" || {
                echo "Bind mount başarısız: $target" >&2; return 1;
            }
            info=$(_satsuma_tmp_mount_info "$target") || return 1
            [[ "$info" != *$'\n'* ]] || return 1
            read -r mounted flags <<< "$info"
            [[ "$mounted" == "$target" && "$flags" =~ ^[a-zA-Z0-9_,=-]+$ ]] || return 1
        fi
        # bind-remount changes this mount's VFS flags only. Keep all existing
        # VFS flags (ro/rw, noatime/relatime, etc.) and append restrictions last.
        mount -o "remount,bind,$flags,noexec,nosuid,nodev" -- "$target" || {
            echo "noexec/nosuid/nodev uygulanamadı: $target" >&2; return 1;
        }
        info=$(_satsuma_tmp_mount_info "$target") || return 1
        [[ "$info" != *$'\n'* ]] || return 1
        read -r mounted flags <<< "$info"
        if [[ "$mounted" != "$target" ]] || ! _satsuma_tmp_has_flags "$flags"; then
            echo "Mount güvenlik bayrakları doğrulanamadı: $target" >&2
            return 1
        fi
        printf '%s\n' "$target: noexec,nosuid,nodev doğrulandı."
    done
}

satsuma_tmp_install_service() {
    _satsuma_tmp_require_root || return 1
    _satsuma_tmp_validate --install || return 1
    local staged
    staged=$(mktemp /etc/systemd/system/.satsuma-tmp.XXXXXXXX) || return 1
    cat > "$staged" <<'SATSUMA_TMP_UNIT'
[Unit]
Description=Satsuma temporary directory mount restrictions
After=local-fs.target
Before=display-manager.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/satsuma-mini --tmp-harden
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SATSUMA_TMP_UNIT
    if [[ $? -ne 0 ]] || ! chmod 0644 "$staged" ||
       ! mv -f -- "$staged" /etc/systemd/system/satsuma-tmp-hardening.service; then
        rm -f -- "$staged"
        return 1
    fi
    # The caller applies live flags after package installation/configuration.
    # This unit persists the restrictions for subsequent normal boots.
    if command -v restorecon >/dev/null && [[ -e /sys/fs/selinux/enforce ]]; then
        restorecon -v /etc/systemd/system/satsuma-tmp-hardening.service || return 1
    fi
    systemctl daemon-reload && systemctl enable satsuma-tmp-hardening.service
}

satsuma_keyboard_trq() {
    [[ $EUID -eq 0 ]] || return 1
    satsuma_platform_config || return 1
    echo "Klavye: Türkçe Q ayarlanıyor."
    if [[ "$SATSUMA_PLATFORM_FAMILY" == debian ]]; then
        /usr/bin/python3 -I -S - <<'SATSUMA_KEYBOARD_PY'
import os, stat, tempfile
from pathlib import Path
p=Path('/etc/default/keyboard')
if p.is_symlink(): raise RuntimeError('Symlink keyboard config')
old=p.read_text() if p.exists() else ''
settings={'XKBMODEL':'pc105','XKBLAYOUT':'tr','XKBVARIANT':'','XKBOPTIONS':''}
lines=[line for line in old.splitlines() if line.split('=',1)[0].strip() not in settings]
lines.extend(key+'="'+value+'"' for key,value in settings.items())
fd,tmp=tempfile.mkstemp(prefix='.satsuma-keyboard-',dir=p.parent)
try:
    with os.fdopen(fd,'w') as out:
        os.fchmod(out.fileno(),0o644);out.write('\n'.join(lines)+'\n');out.flush();os.fsync(out.fileno())
    os.replace(tmp,p)
finally:
    if os.path.exists(tmp):os.unlink(tmp)
SATSUMA_KEYBOARD_PY
        [[ $? -eq 0 ]] || return 1
        if command -v setupcon >/dev/null; then
            setupcon --keyboard-only || echo "Aktif sanal konsol yok; TR Q kalıcı ayarı sonraki oturumda uygulanacak."
        fi
    else
        localectl set-keymap trq && localectl set-x11-keymap tr pc105 || {
            echo "Klavye: localectl başarısız (kod $?); TR Q ayarlanamadı." >&2; return 1; }
    fi
    local who="${SUDO_USER:-}" uid schemas
    if [[ -n "$who" && "$who" != root ]] && command -v gsettings >/dev/null; then
        uid=$(id -u "$who" 2>/dev/null) || return 1
        if [[ "$uid" =~ ^[0-9]+$ ]] && (( uid>=1000 )) && [[ -S "/run/user/$uid/bus" ]]; then
            schemas=$(runuser -u "$who" -- env "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus" gsettings list-schemas 2>/dev/null)
            if [[ "$schemas" == *org.gnome.desktop.input-sources* ]]; then
                runuser -u "$who" -- env "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus" gsettings set org.gnome.desktop.input-sources sources "[('xkb','tr')]" || return 1
            fi
            if [[ "$schemas" == *org.mate.peripherals-keyboard-xkb.kbd* ]]; then
                runuser -u "$who" -- env "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus" gsettings set org.mate.peripherals-keyboard-xkb.kbd layouts "['tr']" || return 1
            fi
        fi
    fi
    echo "TR Q kalıcı ayarı hazır; mevcut oturum uygulanmadıysa yeniden giriş gerekir."
}

satsuma_network_install_service() {
    cat > /etc/systemd/system/satsuma-network-guard.service <<'SATSUMA_NET_UNIT'
[Unit]
Description=Satsuma network thresholds and verified Suricata fast.log bans
After=network.target satsuma-firewall.service suricata.service
[Service]
Type=simple
ExecStart=/usr/local/bin/satsuma-mini --network-watch
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
MemoryMax=256M
[Install]
WantedBy=multi-user.target
SATSUMA_NET_UNIT
    chmod 644 /etc/systemd/system/satsuma-network-guard.service || return 1
    restorecon -v /etc/systemd/system/satsuma-network-guard.service || return 1
    systemctl daemon-reload && systemctl enable --now satsuma-network-guard.service
}

satsuma_file_guard() {
    /usr/bin/python3 -I -S - "$@" <<'SATSUMA_EMBEDDED_PYTHON'
#!/usr/bin/env python3
"""Satsuma scan and reversible quarantine helper. Python standard library."""
import argparse, datetime as dt, fcntl, hashlib, json, os, re, shutil
import stat, subprocess, sys, tempfile, uuid, time, resource
from pathlib import Path

BASE = Path("/var/lib/satsuma-sentinel/quarantine")
LOG = Path("/var/log/satsuma")
DIRS = ["/home", "/tmp", "/var", "/usr/bin", "/usr/sbin",
        "/usr/local/bin", "/usr/local/bin", "/etc", "/opt"]
LOCK = "/run/satsuma-file-scan.lock"
RUN_STATE = LOG / "file-scan-running.json"
SCHEDULE_STATE = LOG / "file-scan-schedule.json"
SCHEDULER_LOCK = "/run/satsuma-file-scheduler.lock"
# Only mutable user/application areas are eligible for automatic isolation.
# System binaries, /etc and service databases remain review-only.
AUTO_ROOTS = ["/home", "/tmp", "/var/tmp", "/var/www", "/opt"]


def safe_root(path, roots):
    path = os.path.abspath(path)
    return any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots)


def secure_dir(path):
    path = Path(path)
    if not path.is_absolute():
        raise RuntimeError("Absolute directory required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
            st = os.fstat(fd)
            if st.st_uid != 0 or st.st_mode & 0o022:
                raise RuntimeError("Untrusted directory: " + str(path))
        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
    return path

def record(kind, **data):
    secure_dir(LOG)
    obj = {"time": dt.datetime.now(dt.timezone.utc).isoformat(),
           "event": kind, **data}
    with open(LOG / "file-scan.jsonl", "a", encoding="utf-8") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    # A small dedicated event journal keeps the live feed readable without
    # dropping the full per-file review/audit records from the original log.
    if kind in ("scan_started", "scan_start", "scan_result", "scan_failed",
                "quarantined", "quarantine_error", "restored", "scan_skipped",
                "scan_cycle_started", "scan_cycle_finished", "known_threat_returned"):
        try:
            with open(LOG / "file-events.jsonl", "a", encoding="utf-8") as f:
                os.fchmod(f.fileno(), 0o600)
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        except OSError:
            pass
    print(json.dumps(obj, ensure_ascii=False), flush=True)

def sha(fd):
    remaining=os.fstat(fd).st_size
    h = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while remaining>0:
        b = os.read(fd, min(1048576,remaining))
        if not b:
            raise RuntimeError("File truncated during hash")
        remaining-=len(b)
        h.update(b)
    return h.hexdigest()

def identity(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

def open_source(path):
    path = os.path.abspath(path)
    parent, name = os.path.split(path)
    if not name or name in (".", "..") or "\n" in path or "\r" in path:
        raise RuntimeError("Unsupported path")
    d = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parent.split("/"):
            if part:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                              os.O_NOFOLLOW, dir_fd=d)
                os.close(d)
                d = nxt
        pin = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=d)
        try:
            st = os.fstat(pin)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise RuntimeError("Not an ordinary single-link file")
            f = os.open("/proc/self/fd/%d" % pin, os.O_RDONLY | os.O_NONBLOCK)
            if identity(st) != identity(os.fstat(f)):
                os.close(f)
                raise RuntimeError("Source changed during open")
        finally:
            os.close(pin)
        return d, f, name, path, st
    except Exception:
        os.close(d)
        raise

def write_json(path, obj):
    fd, tmp = tempfile.mkstemp(prefix=".manifest-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def quarantine(path, engine, reason, apply=False, expected_sha=None):
    path = os.path.abspath(path)
    if path == str(BASE) or path.startswith(str(BASE) + "/"):
        return None
    if engine == "manual" and not any(
        path == root or path.startswith(root.rstrip("/") + "/") for root in AUTO_ROOTS
    ):
        record("review", path=path, engine=engine, reason="Protected system area")
        return None
    if not apply:
        record("candidate", path=path, engine=engine, reason=reason)
        return None
    secure_dir(BASE)
    d = f = q = None
    try:
        d, f, name, path, st = open_source(path)
        if st.st_size > 2 * 1024 * 1024 * 1024:
            raise RuntimeError("File over 2 GiB: manual review required")
        if shutil.disk_usage(BASE).free < st.st_size + 256*1048576:
            raise RuntimeError("Insufficient quarantine disk budget")
        original_hash = sha(f)
        if expected_sha is not None and original_hash != expected_sha:
            raise RuntimeError("Source content differs from scanned content")
        os.lseek(f, 0, os.SEEK_SET)
        ident = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex
        folder = secure_dir(BASE / ident)
        target = folder / (name + ".bak")
        q = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        h = hashlib.sha256()
        while True:
            b = os.read(f, 1048576)
            if not b:
                break
            h.update(b)
            view = memoryview(b)
            while view:
                view = view[os.write(q, view):]
        os.fsync(q)
        os.fchmod(q, 0)
        os.fsync(q)
        os.close(q)
        q = None
        current = os.stat(name, dir_fd=d, follow_symlinks=False)
        if h.hexdigest() != original_hash or identity(st) != identity(os.fstat(f)) or identity(st) != identity(current):
            raise RuntimeError("Source changed during quarantine")
        meta = {"id": ident, "state": "prepared", "original": path,
                "stored": str(target), "sha256": original_hash, "size": st.st_size,
                "uid": st.st_uid, "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode),
                "engine": engine, "reason": reason}
        write_json(folder / "manifest.json", meta)
        syncfd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(syncfd)
        finally:
            os.close(syncfd)
        os.unlink(name, dir_fd=d)
        os.fsync(d)
        meta["state"] = "quarantined"
        write_json(folder / "manifest.json", meta)
        record("quarantined", id=ident, path=path, engine=engine, reason=reason)
        return ident
    except Exception as exc:
        record("quarantine_error", path=path, error=str(exc))
        return None
    finally:
        for fd in (q, f, d):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

def capture(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=7200)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")

def preserve_last_success(engine):
    path = LOG / (engine + "-last-success.json")
    if path.is_file():
        return
    previous = read_json(LOG / (engine + "-status.json"))
    if previous.get("returncode") == 0 and previous.get("completed"):
        write_json(path, previous)


# Bounded sequential scanner. Only scanner code is replaced.
import resource, signal
SCAN_VMEM_MB = int(os.environ.get("SATSUMA_SCAN_VMEM_MB", "6144"))
SCAN_VMEM = SCAN_VMEM_MB * 1048576
SCAN_TIMEOUT = int(os.environ.get("SATSUMA_SCAN_FILE_TIMEOUT", "180"))
SCAN_MAX_FILES = 10000000
# V58: ClamAV artık clamscan (dosya başına DB yükleyen tek kullanımlık
# süreç) yerine clamdscan (kalıcı clamd'e soket üzerinden bağlanan ince
# istemci) kullanıyor. Boyut/recursion/scantime limitleri artık
# clamd.conf'ta (satsuma_scanner_updates -> configure_clamd_limits)
# sunucu tarafında uygulanıyor; istemci küçük ve kısa ömürlü olduğu için
# ayrı, daha düşük bir bellek/timeout bütçesi yeterli.
CLAMD_CLIENT_TIMEOUT = int(os.environ.get("SATSUMA_CLAMD_CLIENT_TIMEOUT", "120"))
CLAMD_CLIENT_VMEM = int(os.environ.get("SATSUMA_CLAMD_CLIENT_VMEM_MB", "512")) * 1048576

def clamd_command():
    os_release=Path('/etc/os-release').read_text()
    fedora=bool(re.search(r'^ID=[\"\']?fedora[\"\']?$',os_release,re.M))
    return ['clamdscan','--config-file','/etc/clamd.d/scan.conf' if fedora else '/etc/clamav/clamd.conf']

def ensure_clamd_reachable():
    rc, out, err = bounded_child(clamd_command()+["--ping", "1"], None, 15, CLAMD_CLIENT_VMEM)
    if rc != 0:
        raise RuntimeError("clamd (clamav-daemon) erişilemiyor - clamdscan --ping "
                           "başarısız (rc=%s): %s" % (rc, err.decode("utf-8", "replace")[:300]))

def bounded_child(cmd, cwd=None, timeout=180, memory=SCAN_VMEM, pass_fds=(), stdin_fd=None):
    def limits():
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (16*1048576,16*1048576))
    with tempfile.TemporaryFile(mode="w+b") as out, tempfile.TemporaryFile(mode="w+b") as err:
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=out, stderr=err,
                                start_new_session=True, preexec_fn=limits, pass_fds=pass_fds,
                                stdin=stdin_fd if stdin_fd is not None else subprocess.DEVNULL)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            rc = 124
        except BaseException:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            raise
        out.seek(0)
        err.seek(0)
        return rc, out.read(), err.read()

def scan_targets(roots, internal, issue, note=None):
    """Yield regular files to scan. A symlink whose target lies outside every
    scan root is followed and its target scanned (field run 2026-11-11: such
    targets were never scanned); one inside a root is scanned there. Sockets
    and FIFOs have no content and are counted, not reported as failures.

    Taranacak normal dosyaları verir. Hedefi hiçbir tarama kökünde olmayan
    sembolik bağ izlenir ve hedefi taranır (saha çalışması 2026-11-11: bu
    hedefler hiç taranmıyordu); kökteki hedef kendi yerinde taranır. Soket ve
    FIFO'nun içeriği yoktur; sayılır, hata sayılmaz.
    """
    seen = set()
    outside_dirs = []
    note = note or (lambda kind, path, target=None: None)
    def add_outside_dir(directory, link):
        # User decision 2026-11-11: the folder a link leads to outside the
        # roots is scanned too (its files, one level).
        # Kullanıcı kararı 2026-11-11: bağın kök dışında götürdüğü klasör de
        # taranır (dosyaları, tek seviye).
        if directory not in outside_dirs and not in_roots(directory) and not safe_root(directory, internal):
            outside_dirs.append(directory)
            note("outside_dir", link, directory)
    scan_roots = [os.path.abspath(r) for r in roots]
    def in_roots(target):
        return safe_root(target, scan_roots)
    for root in roots:
        root = os.path.abspath(root)
        if not os.path.lexists(root):
            issue("Scan root missing: " + root)
            continue
        if os.path.islink(root):
            issue("Symlink root requires review: " + root)
            continue
        if os.path.isfile(root):
            iterator = [root]
        elif os.path.isdir(root):
            def walk():
                for directory, dirs, files in os.walk(root, followlinks=False,
                                                       onerror=lambda e: issue(str(e))):
                    dirs[:] = sorted(d for d in dirs if not safe_root(os.path.join(directory,d),internal))
                    for name in sorted(files):
                        yield os.path.join(directory,name)
                    for name in dirs:
                        path = os.path.join(directory,name)
                        if os.path.islink(path):
                            target = os.path.realpath(path)
                            if in_roots(target) or safe_root(target, internal):
                                note("symlink_covered", path, target)
                            elif os.path.isdir(target):
                                add_outside_dir(target, path)
                            else:
                                issue("Directory symlink outside scan roots requires review: "+path+" -> "+target)
            iterator = walk()
        else:
            issue("Unsupported scan root: "+root)
            continue
        for path in iterator:
            if safe_root(path,internal):
                continue
            try:
                st=os.lstat(path)
            except OSError as exc:
                issue(str(exc))
                continue
            if stat.S_ISLNK(st.st_mode):
                target = os.path.realpath(path)
                try:
                    st = os.lstat(target)
                except OSError:
                    issue("Broken or unreadable symlink requires review: "+path)
                    continue
                if safe_root(target, internal):
                    continue
                if stat.S_ISDIR(st.st_mode):
                    if in_roots(target):
                        note("symlink_covered", path, target)
                    else:
                        add_outside_dir(target, path)
                    continue
                if not stat.S_ISREG(st.st_mode):
                    issue("Symlink to non-regular file requires review: "+path+" -> "+target)
                    continue
                if in_roots(target):
                    note("symlink_covered", path, target)
                    continue
                note("symlink_followed", path, target)
                add_outside_dir(os.path.dirname(target), path)
                path = target
            elif stat.S_ISSOCK(st.st_mode) or stat.S_ISFIFO(st.st_mode):
                note("special_skipped", path)
                continue
            elif not stat.S_ISREG(st.st_mode):
                issue("Non-regular file requires review: "+path)
                continue
            identity=(st.st_dev,st.st_ino)
            if identity in seen:
                continue
            seen.add(identity)
            yield path,st.st_size
    for directory in outside_dirs:
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError as exc:
            issue("Folder behind a symlink could not be read: "+directory+": "+str(exc))
            continue
        for entry in entries:
            path = entry.path
            if safe_root(path, internal):
                continue
            try:
                st = os.lstat(path)
            except OSError as exc:
                issue(str(exc))
                continue
            if not stat.S_ISREG(st.st_mode):
                # Links, subfolders and special files here are not followed further.
                # Buradaki bağlar, alt klasörler ve özel dosyalar daha ileri izlenmez.
                note("outside_dir_not_regular", path)
                continue
            identity=(st.st_dev,st.st_ino)
            if identity in seen:
                continue
            seen.add(identity)
            yield path,st.st_size

def scan(engine, roots, apply=False):
    started=int(time.time())
    run_id=uuid.uuid4().hex
    secure_dir(LOG)
    preserve_last_success(engine)
    roots=[os.path.abspath(p) for p in roots]
    log=LOG/(engine+"-"+run_id+".log")
    grouped={}
    scanned_hashes={}
    scanned_sizes={}
    matches=isolated=review=failed=candidates=0
    discovered=attempted=scanned_files=unreadable=limited=failed_files=0
    errors=[]
    issues=[]
    result={"engine":engine,"started":started,"completed":0,"run_id":run_id,
            "matches":0,"files_with_matches":0,"quarantined":0,"review":0,
            "failed":0,"candidates":0,"returncode":2,"apply":apply,
            "log":str(log),"errors":[],"state":"running"}
    def issue(message):
        nonlocal unreadable
        unreadable+=1
        if len(issues)<100:
            issues.append(message)
    linked_from={}
    target_notes={"symlink_followed":0,"symlink_covered":0,"special_skipped":0,
                  "outside_dir":0,"outside_dir_not_regular":0}
    def note(kind,path,target=None):
        target_notes[kind]=target_notes.get(kind,0)+1
        if kind=="symlink_followed":
            linked_from.setdefault(target,path)
    def add_match(path,reason):
        nonlocal matches
        reasons=grouped.setdefault(path,set())
        if reason not in reasons:
            reasons.add(reason)
            matches+=1
        if matches>100000:
            raise RuntimeError("Match limit exceeded")
    def progress():
        write_json(LOG/(engine+"-status.json"),dict(result,
            discovered=discovered,attempted=attempted,scanned_files=scanned_files,
            unreadable=unreadable,limited=limited,failed_files=failed_files,
            matches=matches,files_with_matches=len(grouped),state="running"))
    progress()
    write_json(RUN_STATE,{"engine":engine,"started":started,"pid":os.getpid(),
                          "run_id":run_id,"apply":apply})
    record("scan_started",engine=engine,run_id=run_id,apply=apply)
    try:
        if engine not in ("clamav",):
            raise RuntimeError("Unsupported scanner")
        if not roots:
            raise RuntimeError("No scan roots")
        if engine=="clamav":
            ensure_clamd_reachable()
        with tempfile.TemporaryDirectory(prefix="satsuma-scan-",dir="/run") as work:
            internal=[str(BASE),str(LOG),work]
            with open(log,"x",encoding="utf-8") as report:
                os.fchmod(report.fileno(),0o600)
                for path,size in scan_targets(roots,internal,issue,note):
                    discovered+=1
                    if discovered>SCAN_MAX_FILES:
                        raise RuntimeError("File inventory limit exceeded")
                    attempted+=1
                    try:
                        # V58: clamscan yerine clamdscan (--fdpass) -
                        # kalıcı clamd sürecine bağlanıyor, imza
                        # veritabanını HER DOSYADA yeniden yüklemiyor.
                        # Yüz binlerce dosyalık ağaçlarda clamscan'in
                        # dosya başına DB yükleme maliyeti pratikte
                        # taramayı hiç bitirmiyordu; clamd bunu bir kez
                        # yükleyip bellekte tutuyor. --fdpass, clamd
                        # kendi kullanıcısıyla (clamav) okuyamayacağı
                        # root-only/kullanıcı dosyalarını, açık dosya
                        # tanıtıcısını soket üzerinden ileterek okuyor.
                        if size>256*1048576:
                            limited+=1
                            if len(issues)<100:
                                issues.append("ClamAV file exceeds configured size: "+repr(path))
                            record("review", engine=engine, path=path,
                                   rules=["size_limit_exceeded"], reason="incomplete")
                        else:
                            parentfd,scanfd,_,_,scanstat=open_source(path)
                            try:
                                if scanstat.st_size>256*1048576:
                                    raise RuntimeError("Source grew beyond size limit")
                                before_hash=sha(scanfd)
                                os.lseek(scanfd,0,os.SEEK_SET)
                                cmd=clamd_command()+["--stream","--infected","--stdout",
                                     "--no-summary","-"]
                                rc,out,err=bounded_child(cmd,None,CLAMD_CLIENT_TIMEOUT,
                                                         CLAMD_CLIENT_VMEM,stdin_fd=scanfd)
                                if identity(scanstat)!=identity(os.fstat(scanfd)) or before_hash!=sha(scanfd):
                                    raise RuntimeError("Source changed while scanning")
                                scanned_hashes[path]=before_hash
                                scanned_sizes[path]=scanstat.st_size
                            finally:
                                os.close(scanfd); os.close(parentfd)
                            text=out.decode("utf-8","replace")
                            stderr=err.decode("utf-8","replace")
                            report.write(text)
                            if stderr:
                                report.write("\nSTDERR "+repr(path)+": "+stderr+"\n")
                            if rc not in (0,1):
                                raise RuntimeError("clamdscan exit %s: %s"%(rc,stderr[:1000]))
                            for line in text.splitlines():
                                if line.endswith(" FOUND") and ": " in line:
                                    reason=line.rsplit(": ",1)[1][:-6]
                                    # V58: limit uyarıları (MaxFileSize/
                                    # MaxScanSize/MaxRecursion clamd.conf'ta
                                    # aşıldığında) gerçek imza gibi otomatik
                                    # karantinaya GİTMEMELİ - sadece review.
                                    if reason.startswith("Heuristics.Limits.Exceeded"):
                                        limited+=1
                                        if len(issues)<100: issues.append("ClamAV limit: "+path)
                                        record("review", engine=engine, path=path,
                                               rules=[reason], reason="incomplete")
                                    else:
                                        add_match(path,reason)
                            if re.search(r"(?im)^(ERROR|WARNING|LibClamAV (Error|Warning)):",stderr+"\n"+text):
                                raise RuntimeError(stderr[:1000])
                        scanned_files+=1
                    except (OSError,RuntimeError,subprocess.TimeoutExpired) as exc:
                        if "Match limit exceeded" in str(exc):
                            raise
                        failed_files+=1
                        if len(issues)<100:
                            issues.append("Scan failed "+repr(path)+": "+str(exc))
                        report.write("SCAN ERROR "+repr(path)+": "+str(exc)+"\n")
                        # V58: hata veren dosya sessizce yok sayılmıyor -
                        # incelemeye (review) düşüyor ki "bu dosya taranamadı,
                        # elle bak" görünür kalsın. Kesin bir eşleşme değil,
                        # bu yüzden karantina kararına (
                        # grouped) hiç girmiyor.
                        record("review", engine=engine, path=path,
                               rules=["scan_error: "+str(exc)[:200]], reason="incomplete")
                    if discovered%100==0:
                        progress()
                report.flush()
                os.fsync(report.fileno())
        if unreadable or failed_files or limited:
            errors.extend(issues)
            # V57 DÜZELTME: Eskiden burada RuntimeError fırlatılıp scan()
            # bu noktada kesiliyordu - yani gerçek dünyada NEREDEYSE HER
            # taramada (izin reddi, taramanın ortasında silinen geçici
            # dosya, soket/FIFO gibi "non-regular" dosyalar /etc, /var,
            # /tmp gibi köklerde kaçınılmaz) unreadable>0 oluyor ve alttaki
            # karantina/inceleme döngüsüne HİÇ ULAŞILMIYORDU. Sonuç: 
            # ClamAV gerçek bir tehdit bulsa bile (grouped dolu olsa bile)
            # sessizce karantinaya alınmıyor, review'e de yazılmıyordu -
            # bellek sorunundan çok daha ciddi bir güvenlik regresyonu.
            # Artık kısmi taramayı işaretliyoruz ama grouped'daki eşleşmeler
            # yine de aşağıdaki döngüde karantina/inceleme sürecine giriyor;
            # dönüş kodu yine de kısmi/başarısız (2) olarak işaretlenip
            # dashboard'da görünür kalıyor.
            result["incomplete"] = True
            record("scan_incomplete", engine=engine, unreadable=unreadable,
                   failed_files=failed_files, limited=limited, issues=issues[:20])
        for path,reasons in grouped.items():
            mutable=safe_root(path,AUTO_ROOTS)
            decision=mutable and engine=="clamav"
            if decision:
                candidates+=1
                if quarantine(path,engine,", ".join(sorted(reasons)),apply,scanned_hashes.get(path)):
                    isolated+=1
                elif apply:
                    failed+=1
            else:
                review+=1
                record("review",engine=engine,path=path,rules=sorted(reasons),
                       sha256=scanned_hashes.get(path),size=scanned_sizes.get(path),
                       linked_from=linked_from.get(path))
        if engine=="clamav" and grouped:
            found=[(path,scanned_hashes.get(path),scanned_sizes.get(path),sorted(reasons))
                   for path,reasons in grouped.items()]
            try:
                for item in local_signatures_update(found,run_id,bool(result.get("incomplete"))):
                    record("known_threat_returned",engine=engine,**item)
                    print("ALARM: Daha önce tespit edilen dosya yeniden görüldü; silindiyse geri gelmiş, incelenmeli: "+
                          item["path"]+" | "+item["signature"]+" | ilk tespit: "+str(item.get("first_seen"))+
                          " "+str(item.get("first_path")),file=sys.stderr,flush=True)
            except Exception as exc:
                errors.append("Yerel imza veritabanı güncellenemedi: "+str(exc))
                record("local_signature_error",engine=engine,error=str(exc))
        record("scan_complete",engine=engine,matches=matches,
               files_with_matches=len(grouped),quarantined=isolated,review=review,
               failed=failed,log=str(log),run_id=run_id,apply=apply)
        result["returncode"]=2 if (failed or result.get("incomplete")) else 0
    except Exception as exc:
        errors.append(str(exc))
        result["returncode"]=2
    finally:
        result.update({"completed":int(time.time()),"matches":matches,
                       "files_with_matches":len(grouped),"quarantined":isolated,
                       "review":review,"failed":failed,"candidates":candidates,
                       "discovered":discovered,"attempted":attempted,
                       "scanned_files":scanned_files,"unreadable":unreadable,
                       "limited":limited,"failed_files":failed_files,
                       "symlinks_followed":target_notes["symlink_followed"],
                       "symlinks_covered":target_notes["symlink_covered"],
                       "special_skipped":target_notes["special_skipped"],
                       "outside_dirs_scanned":target_notes["outside_dir"],
                       "state":"complete" if result["returncode"]==0 else "failed",
                       "errors":errors})
        write_json(LOG/(engine+"-status.json"),result)
        if result["returncode"]==0:
            write_json(LOG/(engine+"-last-success.json"),result)
            record("scan_result",**result)
        else:
            record("scan_failed",**result)
        if read_json(RUN_STATE).get("run_id")==run_id:
            RUN_STATE.unlink(missing_ok=True)
    return result["returncode"]

def restore(ident, dest=None):
    if not re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{32}", ident):
        raise RuntimeError("Invalid ID")
    folder = BASE / ident
    meta = json.loads((folder / "manifest.json").read_text())
    if meta["state"] not in ("quarantined", "prepared"):
        raise RuntimeError("Not quarantined")
    if meta["state"] == "prepared" and not dest and os.path.lexists(meta["original"]):
        raise RuntimeError("Original still exists; prepared transaction requires review")
    target = Path(meta["stored"])
    if target.parent != folder or target.is_symlink():
        raise RuntimeError("Invalid stored path")
    d, f, _, _, _ = open_source(target)
    try:
        if sha(f) != meta["sha256"]:
            raise RuntimeError("Checksum mismatch")
    finally:
        os.close(f)
        os.close(d)
    dest = os.path.abspath(dest or meta["original"])
    parent = os.path.dirname(dest)
    if not os.path.isdir(parent) or os.path.islink(parent):
        raise RuntimeError("Restore parent missing or symlinked")
    # Do not restore into a path whose parent traverses a symlink.
    parentfd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parent.split("/"):
            if part:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
                os.close(parentfd)
                parentfd = nxt
        fd = os.open(os.path.basename(dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parentfd)
    except BaseException:
        os.close(parentfd)
        raise
    restored_ok = False
    try:
        h = hashlib.sha256()
        with open(target, "rb") as src:
            while True:
                b = src.read(1048576)
                if not b:
                    break
                h.update(b)
                view = memoryview(b)
                while view:
                    view = view[os.write(fd, view):]
        if h.hexdigest() != meta["sha256"]:
            raise RuntimeError("Restore checksum mismatch")
        os.fsync(fd)
        os.fchown(fd, meta["uid"], meta["gid"])
        os.fchmod(fd, int(meta["mode"]) & 0o777)
        os.fsync(fd)
        restored_ok = True
    finally:
        os.close(fd)
        try:
            if not restored_ok:
                os.unlink(os.path.basename(dest), dir_fd=parentfd)
        finally:
            os.close(parentfd)
    meta["state"] = "restored"
    meta["restored_to"] = dest
    write_json(folder / "manifest.json", meta)
    record("restored", id=ident, path=dest)


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError, TypeError):
        return default if default is not None else {}

def pid_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError, TypeError):
        return False

def quarantine_inventory():
    result = {"total": 0, "active": 0, "prepared": 0, "restored": 0, "recent": []}
    if not BASE.is_dir():
        return result
    for folder in sorted(BASE.iterdir(), reverse=True):
        if not folder.is_dir() or folder.is_symlink():
            continue
        meta = read_json(folder / "manifest.json")
        if not meta or meta.get("id") != folder.name:
            continue
        result["total"] += 1
        state = meta.get("state", "")
        if state == "quarantined":
            result["active"] += 1
            if len(result["recent"]) < 5:
                result["recent"].append({"id": meta["id"], "path": meta.get("original", ""),
                                         "reason": meta.get("reason", "")})
        elif state == "prepared":
            result["prepared"] += 1
        elif state == "restored":
            result["restored"] += 1
    return result

AIDE_STATE_DIR = Path("/var/lib/satsuma-sentinel/aide")

def aide_dashboard():
    """AIDE reference state for the dashboard; a pending difference is shown in red.

    Panoda AIDE örneğinin durumu; onay bekleyen fark kırmızı gösterilir.
    """
    try:
        if (AIDE_STATE_DIR / "onay-bekliyor").is_file():
            return CRED + "AIDE: FARK VAR - onay bekliyor (satsuma-aide)" + C0
        if (AIDE_STATE_DIR / "aide.db.gz").is_file():
            return "AIDE: örnek var, onay bekleyen fark yok"
        return "AIDE: örnek henüz yok"
    except OSError:
        return "AIDE: okunamadı (root gerekir)"

def ram35_dashboard():
    data=read_json(Path('/var/lib/satsuma-sentinel/state/memory35-status.json'))
    if not data:return 'RAM35: HENUZ DURUM YOK'
    try:age=max(0,time.time()-float(data['updated_at']))
    except (KeyError,ValueError,TypeError):return 'RAM35: GECERSIZ DURUM'
    state=str(data.get('status','UNKNOWN')) if age<=120 else 'STALE'
    return 'RAM35: %s | yas: %ds | tam RAM kapsamasi yok' % (state,int(age))

def dashboard_data():
    schedule = read_json(SCHEDULE_STATE)
    running = read_json(RUN_STATE)
    if running and not pid_alive(running.get("pid")):
        running = {}
    clamav = read_json(LOG / "clamav-status.json")
    last_clamav = read_json(LOG / "clamav-last-success.json")
    if not last_clamav and clamav.get("returncode") == 0:
        last_clamav = clamav
    return {"clamav": clamav, "memory":read_json(LOG / "memory-status.json"), "browser":read_json(LOG / "browser-status.json"),
            "last_success": {"clamav":last_clamav},
            "schedule": schedule, "running": running,
            "quarantine": quarantine_inventory()}

# Local ClamAV hash database (user request 2026-11-11): every file a scan
# flags is added by SHA-256, so the same content is caught again even if the
# upstream signature changes. A flagged hash or path that was absent in the
# previous complete scan and is seen again raises a "came back" alarm.
# Yerel ClamAV özet veritabanı (kullanıcı isteği 2026-11-11): taramanın
# işaretlediği her dosya SHA-256 ile eklenir; üst imza değişse bile aynı içerik
# yine yakalanır. Önceki tam taramada olmayan, daha önce işaretlenmiş bir özet
# ya da yol yeniden görülürse "geri geldi" alarmı verilir.
LOCAL_DB = Path("/var/lib/clamav/satsuma-yerel.hsb")
LOCAL_META = LOG / "yerel-imzalar.json"
NOT_SIGNATURES = ("scan_error", "size_limit", "Heuristics.Limits")

def local_signature_name(reason):
    base = str(reason)
    if base.endswith(".UNOFFICIAL"):
        base = base[:-len(".UNOFFICIAL")]
    if base.startswith("Satsuma.Yerel."):
        base = base[len("Satsuma.Yerel."):]
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:120] or "Bilinmeyen"
    return "Satsuma.Yerel." + base

def local_history_paths():
    """Paths flagged by a signature in earlier scans, from the scan journal.

    Önceki taramalarda bir imzaya takılan yollar, tarama günlüğünden.
    """
    paths = {}
    for line in tail_lines(LOG / "file-scan.jsonl", maximum=200000, byte_limit=67108864):
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("event") != "review" or not obj.get("rules") or not obj.get("path"):
            continue
        rules = [r for r in obj["rules"] if not str(r).startswith(NOT_SIGNATURES)]
        if rules and obj["path"] not in paths:
            paths[obj["path"]] = {"first_seen": obj.get("time"), "signature": rules[0],
                                  "last_seen_run": "gecmis"}
    return paths

def write_local_db(hashes):
    lines = []
    for digest, item in sorted(hashes.items()):
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not isinstance(item.get("size"), int) or item["size"] <= 0:
            continue
        lines.append("%s:%d:%s" % (digest, item["size"], local_signature_name(item.get("signature"))))
    body = ("\n".join(lines) + "\n").encode() if lines else b""
    try:
        if LOCAL_DB.read_bytes() == body:
            return False
    except FileNotFoundError:
        if not body:
            return False
    if LOCAL_DB.is_symlink():
        raise RuntimeError("Local signature database is a symlink")
    fd, name = tempfile.mkstemp(prefix=".satsuma-yerel.", dir=str(LOCAL_DB.parent))
    try:
        with os.fdopen(fd, "wb") as out:
            os.fchmod(out.fileno(), 0o644)
            out.write(body); out.flush(); os.fsync(out.fileno())
        os.replace(name, LOCAL_DB)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    if shutil.which("restorecon"):
        subprocess.run(["restorecon", str(LOCAL_DB)], capture_output=True, timeout=30)
    return True

def local_signatures_update(found, run_id, incomplete=False):
    meta = read_json(LOCAL_META) or {}
    hashes = meta.setdefault("hashes", {})
    paths = meta.setdefault("paths", {})
    if not meta.get("backfilled"):
        for path, item in local_history_paths().items():
            paths.setdefault(path, item)
        meta["backfilled"] = True
    previous = meta.get("last_run")
    seen_as = previous if incomplete else run_id
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    returned = []
    for path, digest, size, reasons in found:
        signatures = [r for r in reasons if not str(r).startswith(NOT_SIGNATURES)]
        if not signatures:
            continue
        prior = hashes.get(digest) if digest else None
        prior = prior or paths.get(path)
        if prior and prior.get("last_seen_run") != previous:
            returned.append({"path": path, "sha256": digest, "signature": ", ".join(signatures),
                             "first_seen": prior.get("first_seen"), "first_path": prior.get("first_path", path)})
        if digest:
            entry = hashes.setdefault(digest, {"first_seen": now, "first_path": path,
                                               "signature": signatures[0], "size": size})
            entry["last_seen_run"] = seen_as
            entry["last_seen"] = now
        entry = paths.setdefault(path, {"first_seen": now, "signature": signatures[0]})
        entry["last_seen_run"] = seen_as
    if not incomplete:
        meta["last_run"] = run_id
    changed = write_local_db(hashes)
    write_json(LOCAL_META, meta)
    if changed:
        rc, out, err = bounded_child(clamd_command()+["--reload"], None, 60, CLAMD_CLIENT_VMEM)
        if rc != 0:
            raise RuntimeError("clamd --reload başarısız (rc=%s): %s" % (rc, (out+err).decode("utf-8","replace")[:200]))
    return returned

def scanner_unavailable(engine, message):
    preserve_last_success(engine)
    previous = read_json(LOG / (engine + "-status.json"))
    result = {"engine":engine, "started":int(time.time()), "completed":int(time.time()),
              "matches":0, "files_with_matches":0, "quarantined":0,
              "review":0, "failed":0, "candidates":0, "returncode":2,
              "apply":False, "errors":[message], "log":previous.get("log","")}
    write_json(LOG / (engine + "-status.json"), result)
    record("scan_failed", **result)
    return 2

def scheduler(interval=3600, once=False):
    """Sequential hourly scan cycle. A full cycle never overlaps the next."""
    if interval < 3600:
        raise RuntimeError("Minimum interval is 3600 seconds")
    secure_dir(LOG)
    with open(SCHEDULER_LOCK, "a+") as guard:
        os.fchmod(guard.fileno(), 0o600)
        try:
            fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Another Satsuma file scheduler is running", file=sys.stderr)
            return 3
        while True:
            started = int(time.time())
            record("scan_cycle_started")
            write_json(SCHEDULE_STATE, {"started": started, "next": started + interval,
                                        "interval": interval, "state": "running",
                                        "pid": os.getpid(), "engine": "clamav"})
            results = {}
            for engine in ("clamav",):
                if not shutil.which("clamdscan"):
                    results[engine] = scanner_unavailable(engine, "Engine unavailable")
                    continue
                state = read_json(SCHEDULE_STATE)
                state["engine"] = engine
                write_json(SCHEDULE_STATE, state)
                with open(LOCK, "a+") as lock:
                    os.fchmod(lock.fileno(), 0o600)
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    try:
                        results[engine] = scan(engine, DIRS, False)
                        results["memory"] = memory_scan()
                        results["browser"] = browser_audit()
                    except Exception as exc:
                        results[engine] = scanner_unavailable(engine, str(exc))
            finished = int(time.time())
            next_run = max(started + interval, finished + interval if finished - started >= interval else started + interval)
            write_json(SCHEDULE_STATE, {"started": started, "completed": finished,
                                        "next": next_run, "interval": interval,
                                        "state": "idle", "pid": os.getpid(),
                                        "results": results})
            record("scan_cycle_finished", results=results)
            if once:
                return 0 if all(v == 0 for v in results.values()) else 2
            time.sleep(max(0, next_run - time.time()))


def dashboard_lines():
    data = dashboard_data()
    schedule = data["schedule"]
    running = data["running"]
    inv = data["quarantine"]
    def fmt(ts):
        try:
            return dt.datetime.fromtimestamp(int(ts), dt.timezone.utc).astimezone().strftime("%d.%m %H:%M:%S")
        except (ValueError, TypeError, OverflowError, OSError):
            return "henüz yok"
    def number(value):
        try:
            return str(int(value))
        except (TypeError, ValueError):
            return "0"
    state = schedule.get("state", "not_scheduled")
    print("Durum: " + ("TARANIYOR" if running else state))
    print("Aktif motor: " + (running.get("engine", "-") if running else "-"))
    print("Son döngü: " + fmt(schedule.get("completed")))
    print("Sonraki döngü: " + fmt(schedule.get("next")))
    for engine in ("clamav",):
        s = data[engine]
        print(engine.upper() + " | " +
              ("BAŞARILI" if s.get("returncode") == 0 else
               "HATA" if s.get("returncode") is not None else "HENÜZ YOK"))
        print("  Son: " + fmt(s.get("completed")) +
              " | Eşleşme: " + number(s.get("matches")) +
              " | Dosya: " + number(s.get("files_with_matches")))
        print("  Karantina: " + number(s.get("quarantined")) +
              " | İnceleme: " + number(s.get("review")) +
              " | Aday: " + number(s.get("candidates")) +
              " | Hata: " + number(s.get("failed")))
        if engine == "clamav":
            print("  Taranan dosya: " + number(s.get("scanned_files")))
    drops=read_drop_stats()
    print("Suricata IPS drop: "+(str(drops['blocked']) if drops['available'] else "bilinmiyor"))
    print(ram35_dashboard())
    print(aide_dashboard())
    print("Karantina toplam: " + number(inv["total"]) +
          " | Aktif: " + number(inv["active"]) +
          " | Hazırlanmış: " + number(inv["prepared"]) +
          " | Geri yüklenen: " + number(inv["restored"]))
    for item in inv["recent"][:5]:
        print("  " + item["id"] + " | " + item["path"])


def _clean_screen_text(value):
    import unicodedata
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(value or ""))
    value = "".join(c if c.isprintable() else " " for c in value)
    return " ".join(value.split())

def _screen_width(value):
    import unicodedata
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1
               for c in value)

def _fit_screen(value, width):
    value = _clean_screen_text(value)
    if width <= 0:
        return ""
    if _screen_width(value) <= width:
        return value
    out = ""
    for c in value:
        if _screen_width(out + c) > width - 1:
            break
        out += c
    return out + "…"

def _probe(command):
    try:
        p = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=2, text=True)
        return p.stdout.strip() if p.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""

def _service_state(name):
    try:
        result = subprocess.run(["systemctl", "is-active", name],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=2, text=True)
        return result.stdout.strip() or "bilinmiyor"
    except (OSError, subprocess.TimeoutExpired):
        return "bilinmiyor"

"""Read Suricata's own IPS verdict counters without executing anything.

Only ips.blocked is a drop verdict here. capture.kernel_drops, decoder errors,
NFT address bans and alert counts are deliberately never used as substitutes.
Counters can reset when Suricata restarts; statistics delta-mode is not inferred.
"""
import datetime as _dt
import json
import math
import os
import re
import stat
import time

_MAX_COUNTER = (1 << 64) - 1
_DEFAULT_TAIL = 2 * 1024 * 1024
_ROW = re.compile(r'^\s*ips\.(blocked|accepted)\s*\|\s*Total\s*\|\s*([0-9]+)\s*$', re.M)
_DATE = re.compile(r'^Date:\s*(.*?)\s*(?:\(uptime:.*)?$', re.M)


def _counter(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_COUNTER:
        return None
    return value


def _finite_number(value):
    return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)


def _iso_epoch(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = _dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        # An EVE timestamp with no offset cannot be silently treated as UTC.
        if parsed.tzinfo is None:
            return None
        return parsed.timestamp()
    except (ValueError, OverflowError, OSError):
        return None


def _stats_epoch(value):
    if not isinstance(value, str):
        return None
    for pattern in ('%m/%d/%Y -- %H:%M:%S', '%m/%d/%Y -- %H:%M:%S.%f'):
        try:
            # stats.log Date uses Suricata's local wall clock. This helper runs
            # on that same host, so timestamp() applies its local zone/DST.
            return _dt.datetime.strptime(value, pattern).timestamp()
        except (ValueError, OverflowError, OSError):
            continue
    return None


def _tail_regular(path, max_bytes):
    pin = descriptor = None
    try:
        # O_PATH cannot invoke device open handlers. Refuse final symlinks and
        # every non-regular object before reopening the pinned regular file.
        pin = os.open(path, os.O_PATH | os.O_NOFOLLOW)
        before = os.fstat(pin)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('not a regular log file')
        descriptor = os.open('/proc/self/fd/%d' % pin, os.O_RDONLY | os.O_NONBLOCK)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('log identity changed while opening')
        offset = max(0, opened.st_size - max_bytes)
        data = os.pread(descriptor, min(max_bytes, opened.st_size), offset)
        if offset:
            # Drop a possibly partial first line. Never parse half a JSON row.
            newline = data.find(b'\n')
            data = data[newline + 1:] if newline >= 0 else b''
        return data.decode('utf-8', 'replace'), opened.st_mtime
    finally:
        for fd in (descriptor, pin):
            if fd is not None:
                os.close(fd)


def _read_eve(path, max_bytes):
    text, mtime = _tail_regular(path, max_bytes)
    latest = None
    malformed = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except (ValueError, RecursionError):
            malformed += 1
            continue
        if not isinstance(event, dict) or event.get('event_type') != 'stats':
            continue
        stats = event.get('stats')
        blocked = accepted = None
        if isinstance(stats, dict):
            ips = stats.get('ips')
            if isinstance(ips, dict):
                blocked = _counter(ips.get('blocked'))
                accepted = _counter(ips.get('accepted'))
            else:
                blocked = _counter(stats.get('ips.blocked'))
                accepted = _counter(stats.get('ips.accepted'))
        latest = {'source':os.fspath(path), 'source_format':'eve_stats',
                  'blocked':blocked, 'accepted':accepted,
                  'record_timestamp':event.get('timestamp') if isinstance(event.get('timestamp'),str) else None,
                  'record_epoch':_iso_epoch(event.get('timestamp')), 'file_mtime':mtime}
    if latest is not None:
        latest['malformed_lines_ignored'] = malformed
    return latest


def _read_stats(path, max_bytes):
    text, mtime = _tail_regular(path, max_bytes)
    dates = list(_DATE.finditer(text))
    timestamp = None
    if dates:
        last = dates[-1]
        timestamp = last.group(1).strip()
        text = text[last.end():]
    elif not re.search(r'^\s*[A-Za-z0-9_.]+\s*\|.*\|\s*[0-9]+\s*$', text, re.M):
        return None
    values = {}
    for match in _ROW.finditer(text):
        # int conversion is bounded by the short decimal field length too.
        raw = match.group(2)
        values[match.group(1)] = _counter(int(raw)) if len(raw) <= 20 else None
    return {'source':os.fspath(path), 'source_format':'stats.log',
            'blocked':values.get('blocked'), 'accepted':values.get('accepted'),
            'record_timestamp':timestamp, 'record_epoch':_stats_epoch(timestamp),
            'file_mtime':mtime}


def read_drop_stats(log_path='/var/log/suricata/stats.log',
                    eve_path='/var/log/suricata/eve.json', *,
                    max_bytes=_DEFAULT_TAIL, max_age=300, now=None):
    """Return the newest available statistics record, preserving missing vs 0.

    `available` means an actual ips.blocked counter was read, not that a live
    drop was proved. Check `freshness`, `age_seconds` and `age_basis` before
    treating the counter as current. If the latest record lacks ips.blocked,
    blocked is None: older counters and other types of drop are not substituted.
    The caller must not subtract successive values across a reset without care.
    """
    if isinstance(max_bytes,bool) or not isinstance(max_bytes,int) or not 1024 <= max_bytes <= 8*1024*1024:
        raise ValueError('invalid tail byte budget')
    if not _finite_number(max_age) or max_age < 0:
        raise ValueError('invalid maximum age')
    if now is None:
        now = time.time()
    if not _finite_number(now):
        raise ValueError('invalid current timestamp')
    candidates, errors = [], []
    for parser, path in ((_read_stats,log_path),(_read_eve,eve_path)):
        try:
            record = parser(path,max_bytes)
            if record is not None:
                candidates.append(record)
        except (OSError,ValueError) as exc:
            errors.append({'source':os.fspath(path),'reason':str(exc)[:300]})
    common = {'available':False, 'blocked':None, 'accepted':None,
              'source':None, 'source_format':None, 'record_timestamp':None,
              'age_seconds':None, 'age_basis':None, 'freshness':'unknown',
              'counter_may_reset':True,
              'counter_semantics':'Suricata ips.blocked; reset on restart; delta-mode not verified',
              'errors':errors}
    if not candidates:
        common['reason'] = 'no Suricata statistics record with a readable IPS counter'
        return common
    # Prefer actual record timestamps. With neither source timestamp known,
    # mtime only chooses a source; it never establishes a fresh counter.
    timed = [r for r in candidates if r['record_epoch'] is not None]
    selected = max(timed, key=lambda r:r['record_epoch']) if timed else max(candidates,key=lambda r:r['file_mtime'])
    epoch = selected.get('record_epoch')
    basis = 'record_timestamp' if epoch is not None else 'file_mtime_estimate'
    age = max(0.0, float(now - (epoch if epoch is not None else selected['file_mtime'])))
    # Unknown/future timestamp source freshness is never advertised as current.
    future = epoch is not None and epoch > now + 60
    freshness = 'unknown' if epoch is None or future else ('stale' if age > max_age else 'current')
    selected.pop('record_epoch',None)
    selected.pop('file_mtime',None)
    common.update(selected)
    common.update(available=selected['blocked'] is not None,
                  age_seconds=round(age,3),age_basis=basis,freshness=freshness)
    if common['available']:
        common['reason'] = 'actual ips.blocked counter; traffic drop test not performed'
    else:
        common['reason'] = 'latest statistics record does not contain a valid ips.blocked counter'
    return common


def _network_snapshot():
    import socket
    result = {"host": socket.gethostname(), "ip": "-", "wan": "-",
              "services": {}, "connections": [], "events": []}
    route = _probe(["ip", "-4", "route", "get", "1.1.1.1"])
    m = re.search(r"\bdev\s+(\S+)", route)
    if m:
        result["wan"] = m.group(1)
    m = re.search(r"\bsrc\s+(\d+(?:\.\d+){3})", route)
    if m:
        result["ip"] = m.group(1)
    for name in ("suricata", "satsuma-file-scan"):
        result["services"][name] = _service_state(name)
    try:
        with open("/proc/net/netfilter/nfnetlink_queue") as f:
            result["queue"] = any(line.split() and line.split()[0] == "0"
                                  for line in f)
    except OSError:
        result["queue"] = False
    raw = _probe(["ss", "-Hntup", "state", "established"])
    groups = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        peer = parts[4]
        name = re.search(r'users:\(\("([^"]+)', line)
        process = name.group(1) if name else "unknown"
        key = (peer, process)
        groups[key] = groups.get(key, 0) + 1
    result["connections"] = [{"ip": k[0], "process": k[1], "count": v}
                             for k, v in sorted(groups.items(),
                                                key=lambda item: -item[1])[:20]]
    result["connection_count"] = sum(groups.values())
    result["connection_groups"] = len(groups)
    return result

def _screen_stamp(ts):
    try:
        if not ts:
            return "-"
        return dt.datetime.fromtimestamp(int(ts)).strftime("%d.%m %H:%M")
    except (ValueError, TypeError, OverflowError, OSError):
        return "-"

def _screen_num(value):
    try:
        return str(int(value))
    except (ValueError, TypeError):
        return "0"

def _screen_status(value, state=None):
    if state == "running":
        return "TARANIYOR"
    if value == 0:
        return "OK"
    return "HATA" if value is not None else "BEKLIYOR"

def render_compact_screen(network=None, columns=None, rows=None, now=None):
    """Return a bounded, read-only terminal frame with one source for scan totals."""
    data = dashboard_data()
    n = network if network is not None else _network_snapshot()
    terminal = shutil.get_terminal_size((100, 30))
    width = max(40, min(int(columns or terminal.columns), 240))
    height = max(10, int(rows or terminal.lines))
    now = int(now or time.time())
    if width < 64 or height < 18:
        data = dashboard_data()
        n = network if network is not None else _network_snapshot()
        schedule = data["schedule"]
        running = data["running"]
        inv = data["quarantine"]
        lines = [
            "SATSUMA | " + time.strftime("%d.%m %H:%M:%S", time.localtime(now)),
            "%s | %s" % (n.get("host", "-"), n.get("ip", "-")),
            "Suricata: %s | NFQ0: %s" % (
                n.get("services", {}).get("suricata", "-"),
                "bagli" if n.get("queue") else "yok"),
            "Saatlik tarama: " + (running.get("engine", "-").upper() if running else
                                 schedule.get("state", "bekliyor")),
            "Son: %s | Sonraki: %s" % (
                _screen_stamp(schedule.get("completed")),
                _screen_stamp(schedule.get("next"))),
        ]
        for engine in ("clamav",):
            st = data[engine]
            lines.append("%s %s | E:%s D:%s Q:%s" % (
                engine.upper(), _screen_status(st.get("returncode"), st.get("state")),
                _screen_num(st.get("matches")), _screen_num(st.get("files_with_matches")),
                _screen_num(st.get("quarantined"))))
        lines.append("Karantina: %s aktif / %s toplam" %
                     (_screen_num(inv.get("active")), _screen_num(inv.get("total"))))
        lines.append("Ctrl+C: cikis | Izleme modu")
        return "\n".join(_fit_screen(line, width) for line in lines[:height]) + "\n"
    lines = []
    def add(value):
        lines.append(_fit_screen(value, width))
    def rule(title):
        add("─ " + title + " " + "─" * max(0, width - _screen_width(title) - 3))
    def service(name, label):
        return label + ": " + n.get("services", {}).get(name, "-")
    def countdown(ts):
        try:
            remaining = max(0, int(ts) - now)
            if remaining == 0:
                return "bekleniyor"
            return "%02d:%02d:%02d" % (remaining // 3600, remaining // 60 % 60,
                                       remaining % 60)
        except (TypeError, ValueError):
            return "-"
    schedule = data["schedule"]
    running = data["running"]
    inv = data["quarantine"]
    add("SATSUMA OMNI-SENTINEL | " + time.strftime("%d.%m.%Y %H:%M:%S",
                                                    time.localtime(now)))
    add("Host: %s | IP: %s | WAN: %s" %
        (n.get("host", "-"), n.get("ip", "-"), n.get("wan", "-")))
    rule("AG VE KORUMA")
    add(service("suricata", "Suricata") + " | NFQUEUE 0: " +
        ("bagli" if n.get("queue") else "bagli degil"))
    blocks = n.get("blocks", {})
    if blocks:
        add("Blok: %s | Suricata: %s | OTX: %s | DNS-less: %s | Anomali: %s" %
            tuple(_screen_num(blocks.get(k, 0)) for k in
                  ("total", "suricata", "otx", "dnsless", "anomaly")))
    add("Baglantilar: %s | Gruplar: %s" %
        (_screen_num(n.get("connection_count", 0)),
         _screen_num(n.get("connection_groups", 0))))
    rule("SAATLIK DOSYA TARAMASI")
    state = "CALISIYOR: " + running.get("engine", "-").upper() if running else (
        "DONGU SURUYOR" if schedule.get("state") == "running" else "BEKLIYOR")
    add("Durum: %s | Son: %s | Sonraki: %s" %
        (state, _screen_stamp(schedule.get("completed")),
         countdown(schedule.get("next"))))
    for engine in ("clamav",):
        status = data[engine]
        add("%s %s | Son: %s | Eslesme: %s | Dosya: %s" %
            (engine.upper(), _screen_status(status.get("returncode"), status.get("state")),
             _screen_stamp(status.get("completed")),
             _screen_num(status.get("matches")),
             _screen_num(status.get("files_with_matches"))))
        add("  Karantina: %s | Inceleme: %s | Hata: %s%s" %
            (_screen_num(status.get("quarantined")),
             _screen_num(status.get("review")), _screen_num(status.get("failed")),
             " | Taranan: " + _screen_num(status.get("scanned_files"))
             if engine == "clamav" else ""))
    add("Karantina: %s aktif / %s toplam | Geri yuklenen: %s | Eksik islem: %s" %
        tuple(_screen_num(inv.get(k)) for k in
              ("active", "total", "restored", "prepared")))
    add(ram35_dashboard())
    add(aide_dashboard())
    # Reserve the footer and allocate the remaining rows to useful live detail.
    footer = "Ctrl+C: cikis | Tarama: 1 saat | Izleme modu: sistem ayarlari degismez"
    room = max(0, height - len(lines) - 1)
    events = list(n.get("events") or [])
    alerts = list(n.get("alerts") or [])
    connections = list(n.get("connections") or [])
    recent = list(inv.get("recent") or [])
    # Priority: actual alerts, recent security activity, then connections.
    if room >= 2 and (alerts or events):
        rule("SON GUVENLIK OLAYLARI")
        room -= 1
        for entry in (alerts + events)[:min(3, room)]:
            add(entry)
            room -= 1
    if room >= 3 and connections:
        rule("AKTIF BAGLANTILAR")
        room -= 1
        for c in connections[:min(5, room)]:
            add("%s | %s | %s" % (c.get("ip", "-"), _screen_num(c.get("count", 1)),
                                  c.get("process", "-")))
            room -= 1
    if room >= 2 and recent:
        rule("SON KARANTINA")
        room -= 1
        for item in recent[:min(2, room)]:
            add(item.get("path", "-"))
            room -= 1
    add(footer)
    return "\n".join(lines[:height]) + "\n"

def screen_loop():
    """Read-only monitor; never starts scanners or changes security services."""
    if not sys.stdout.isatty():
        print(render_compact_screen())
        return 0
    print("\033[?1049h\033[?25l", end="", flush=True)
    try:
        while True:
            print("\033[H\033[2J" + render_compact_screen(), end="", flush=True)
            time.sleep(3)
    except KeyboardInterrupt:
        return 0
    finally:
        print("\033[?25h\033[?1049l", end="", flush=True)


# ---- SATSUMA COLOR TERMINAL: shared read-only renderer ----
SGR_RE = re.compile(r"\x1b\[[0-9;]*m")
ESC_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|.)")
C0 = "\033[0m"
CRED = "\033[1;31m"
CGREEN = "\033[1;32m"
CYELLOW = "\033[1;33m"
CBLUE = "\033[1;34m"
CCYAN = "\033[1;36m"
CMAGENTA = "\033[1;35m"
CWHITE = "\033[1;37m"
CDIM = "\033[2m"
CBOLD = "\033[1m"
EVENT_WINDOW_SECONDS = 86400

def visible_width(value):
    import unicodedata
    plain = SGR_RE.sub("", str(value))
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1
               for c in plain if c.isprintable())

def safe_ansi(value):
    """Decode literal ANSI color codes and retain only safe SGR escapes."""
    value = str(value or "")

    # Eski loglarda metin olarak saklanan \033[...m kodlarını
    # gerçek ANSI renk kodlarına dönüştür.
    value = re.sub(
        r"\\(?:033|x1b)\[([0-9;]*)m",
        lambda m: "\033[" + m.group(1) + "m",
        value
    )

    # Yalnızca güvenli SGR renk kodlarını koru.
    value = ESC_RE.sub(
        lambda m: m.group(0) if SGR_RE.fullmatch(m.group(0)) else "",
        value
    )

    return "".join(
        c if c.isprintable() or c == "\033" else " "
        for c in value
    )

def fit_ansi(value, width):
    value = safe_ansi(value)
    if width <= 0:
        return ""
    result, used, truncated = [], 0, False
    import unicodedata
    tokens = re.split(r"(\x1b\[[0-9;]*m)", value)
    for token in tokens:
        if SGR_RE.fullmatch(token or ""):
            result.append(token)
            continue
        for char in token:
            cell = 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
            if used + cell > width:
                truncated = True
                break
            result.append(char)
            used += cell
        if truncated:
            break
    if truncated and width > 1:
        # Do not emit an extra character outside the terminal's last column.
        while used > width - 1 and result:
            last = result.pop()
            if not SGR_RE.fullmatch(last):
                used -= visible_width(last)
        result.append("…")
    return "".join(result) + C0

def tail_lines(path, maximum=300, byte_limit=262144):
    """Bounded tail; never load an unbounded security log into memory."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - byte_limit))
            if size > byte_limit:
                f.readline()
            from collections import deque
            return [b.decode("utf-8", "replace") for b in deque(f, maxlen=maximum)]
    except OSError:
        return []

def event_time(value):
    try:
        if isinstance(value, (int, float)):
            return float(value)
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        return 0.0

def format_event_time(ts):
    try:
        return dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S")
    except (OSError, ValueError, OverflowError):
        return "--:--:--"

def display_event(obj):
    """Return a meaningful event; generic per-file review spam stays in logs."""
    kind = obj.get("event", "")
    engine = str(obj.get("engine", "")).upper()
    path = str(obj.get("path", ""))
    reason = str(obj.get("reason", ""))
    basename = os.path.basename(path)
    if kind in ("scan_started", "scan_start"):
        return CYELLOW, "[%s] Tarama basladi%s" % (engine, " (otomatik karantina)" if obj.get("apply") else " (rapor)")
    if kind == "scan_complete":
        # Final scan_result includes actual quarantine counts; avoid misleading duplicates.
        return None
    if kind == "scan_result":
        return (CRED if obj.get("returncode") else CGREEN,
                "[%s] Tamamlandi: %s eslesme, %s dosya, %s karantina, %s hata" %
                (engine, _screen_num(obj.get("matches")),
                 _screen_num(obj.get("files_with_matches")),
                 _screen_num(obj.get("quarantined")),
                 _screen_num(obj.get("failed"))))
    if kind == "scan_failed":
        detail = obj.get("error") or obj.get("errors") or obj.get("returncode") or "ayrintilar logda"
        return CRED, "[%s] TARAMA HATASI: %s" % (engine, detail)
    if kind == "quarantined":
        return CRED, "[KARANTINA/%s] %s | %s" % (engine or "MANUEL", basename, reason)
    if kind == "quarantine_error":
        return CRED, "[KARANTINA-HATA] %s | %s" % (basename, obj.get("error", ""))
    if kind == "restored":
        return CGREEN, "[GERI YUKLEME] %s" % basename
    if kind == "known_threat_returned":
        return CRED, "[TEKRAR] Daha once tespit edilen dosya yeniden goruldu, incelenmeli: %s | %s" % (path, obj.get("signature", ""))
    if kind == "scan_skipped":
        return CYELLOW, "[TARAMA] Cakisma: diger tarama devam ediyor"
    if kind == "scan_cycle_started":
        return CCYAN, "[DOSYA TARAMASI] Saatlik dongu basladi"
    if kind == "scan_cycle_finished":
        return CGREEN, "[DOSYA TARAMASI] Saatlik dongu tamamlandi"
    return None

def file_security_events(now=None, maximum=400):
    now = float(now or time.time())
    events = []
    # Read both the new compact journal and the older full journal so the
    # pre-existing quarantine history remains visible after an upgrade.
    raw_lines = tail_lines(LOG / "file-events.jsonl", maximum=2000, byte_limit=2097152)
    raw_lines += tail_lines(LOG / "file-scan.jsonl", maximum=20000, byte_limit=8388608)
    for line in raw_lines:
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        ts = event_time(obj.get("time"))
        if ts <= 0 or ts > now + 300 or ts < now - EVENT_WINDOW_SECONDS:
            continue
        formatted = display_event(obj)
        if formatted is not None:
            color, message = formatted
            events.append({"timestamp":ts,"message":message,"color":color,
                           "source":"file","key":str(obj.get("event"))+"|"+str(obj.get("time"))+
                           "|"+str(obj.get("id") or obj.get("path") or obj.get("log") or "")})
    unique = {}
    for event in events:
        unique[event["key"]] = event
    return sorted(unique.values(), key=lambda e:e["timestamp"])[-maximum:]

def main_security_events(now=None, maximum=80):
    """Recover existing Satsuma live messages from the original main log."""
    now = float(now or time.time())
    entries = []
    for line in tail_lines("/var/log/satsuma_ai.log", maximum=600, byte_limit=524288):
        if " | " not in line:
            continue
        rawtime, message = line.split(" | ", 1)
        ts = event_time(rawtime)
        if not ts or ts > now + 300 or ts < now - EVENT_WINDOW_SECONDS:
            continue
        message = safe_ansi(message.strip())
        entries.append({"timestamp":ts,"message":message,"source":"main",
                        "key":str(ts)+message})
    return entries[-maximum:]

def combined_events(network=None, now=None):
    now = float(now or time.time())
    entries = file_security_events(now)
    n = network or {}
    entries += main_security_events(now)
    if "events" in n:
        for i, item in enumerate(n.get("events") or []):
            if isinstance(item, dict):
                msg = item.get("message", "")
                ts = event_time(item.get("time") or item.get("timestamp")) or now-i*.00001
            else:
                msg = str(item)
                # Preserve the original HH:MM:SS so file-scan events can be
                # interleaved chronologically instead of buried by old entries.
                match = re.match(r"^(\d{2}):(\d{2}):(\d{2})\s*\|", SGR_RE.sub("",msg))
                if match:
                    clock = dt.datetime.fromtimestamp(now).replace(
                        hour=int(match.group(1)), minute=int(match.group(2)),
                        second=int(match.group(3)), microsecond=0)
                    ts = clock.timestamp()
                    if ts > now + 60:
                        ts -= 86400
                else:
                    ts = now-i*.00001
            entries.append({"timestamp":ts,"message":msg,"source":"main","key":str(ts)+msg})
    for i,item in enumerate(n.get("alerts") or []):
        msg = item.get("message","") if isinstance(item,dict) else str(item)
        if msg:
            entries.append({"timestamp":now-i*.00001,"message":msg,"color":CRED,
                            "source":"alert","key":"alert:"+msg})
    entries.sort(key=lambda e:e["timestamp"],reverse=True)
    seen, result = set(), []
    for e in entries:
        key=(e.get("source"),e.get("key"))
        if key in seen:
            continue
        seen.add(key)
        result.append(e)
    return result

def screen_event_line(event, width):
    message = safe_ansi(event.get("message",""))
    prefix = event.get("color","")
    if re.match(r"^\d{2}:\d{2}:\d{2}\s*\|", SGR_RE.sub("",message)):
        return fit_ansi("  "+prefix+message+C0,width)
    return fit_ansi("  "+CDIM+format_event_time(event.get("timestamp",0))+C0+
                    " | "+prefix+message+C0,width)

def _ipv4_peer(peer):
    peer = str(peer or "")
    if peer.startswith("["):
        return peer.rsplit("]:",1)[0].strip("[]")
    if ":" in peer:
        return peer.rsplit(":",1)[0]
    return peer

def terminal_network_snapshot():
    """Read-only fallback for a separately launched dashboard."""
    n=_network_snapshot()
    connections=[]
    for c in n.get("connections",[]):
        ip=_ipv4_peer(c.get("ip",""))
        connections.append({"ip":ip,"subnet":ip+"/32" if re.fullmatch(r"\d+(?:\.\d+){3}",ip) else ip,
                            "count":c.get("count",0),"process":c.get("process","unknown"),
                            "trusted":False})
    n["connections"]=connections
    # No inferred trust status, no guessed counters.
    return n


def render_original_style(network=None, columns=None, rows=None, now=None, events=None, data=None):
    """Original ANSI styling; responsive event feed and connection table."""
    n=network if network is not None else terminal_network_snapshot()
    data=data if data is not None else dashboard_data()
    now=float(now or time.time())
    size=shutil.get_terminal_size((100,36))
    width=max(40,min(int(columns or size.columns),240))
    height=max(10,int(rows or size.lines))
    entries=events if events is not None else combined_events(n,now)
    lines=[]
    def add(value):
        lines.append(fit_ansi(value,width))
    def border():
        add(CCYAN+"+"+"-"*max(0,width-2)+"+"+C0)
    def heading(title,color=CCYAN):
        border()
        add(" "+color+"[*] "+title+C0)
    if width < 64 or height < 18:
        inv=data.get("quarantine") or {}
        lines=[]
        add(CWHITE+"SATSUMA"+C0+" | "+time.strftime("%H:%M:%S",time.localtime(now)))
        for engine in ("clamav",):
            st=data.get(engine) or {}
            add(CCYAN+engine.upper()+C0+" E:"+_screen_num(st.get("matches"))+
                " D:"+_screen_num(st.get("files_with_matches"))+
                " Q:"+_screen_num(st.get("quarantined")))
        add(CMAGENTA+"Karantina:"+C0+" "+_screen_num(inv.get("active"))+
            " / "+_screen_num(inv.get("total")))
        add(CMAGENTA+"[*] CANLI GUVENLIK OLAY AKISI"+C0)
        connections=list(n.get("connections") or [])
        room=max(0,height-len(lines)-3)
        conn_slots=min(len(connections),2,max(0,room//3))
        event_slots=max(0,room-conn_slots)
        for e in entries[:event_slots]:
            add(screen_event_line(e,width))
        add(CGREEN+"[*] AKTIF BAGLANTILAR"+C0+" ("+
            _screen_num(n.get("connection_count",0))+")")
        for c in connections[:conn_slots]:
            add(CGREEN+str(c.get("ip","-"))+C0+" | "+
                _screen_num(c.get("count",0))+" | "+str(c.get("process","unknown")))
        add(CDIM+"Ctrl+C: cikis"+C0)
        return "\n".join(lines[:height])+"\n"
    def state(value):
        return (CGREEN if value in ("active","OK","bagli") else CRED)+str(value)+C0
    def fmt(ts):
        return _screen_stamp(ts)
    schedule=data.get("schedule") or {}
    running=data.get("running") or {}
    inv=data.get("quarantine") or {}
    services=n.get("services") or {}
    add(CCYAN+"+"+"="*max(0,width-2)+"+"+C0)
    add(" "+CWHITE+CBOLD+"SATSUMA OMNI-SENTINEL"+C0+
        " | "+time.strftime("%d.%m.%Y %H:%M:%S",time.localtime(now))+
        " | "+n.get("ip","-"))
    add(" "+CCYAN+"WAN:"+C0+" "+str(n.get("wan","-"))+
        " | Suricata: "+state(services.get("suricata","bilinmiyor"))+
        " | NFQ0: "+state("bagli" if n.get("queue") else "bagli degil")+
        " | Dosya tarama: "+state(services.get("satsuma-file-scan","bilinmiyor")))
    b=n.get("blocks") or {}
    if b:
        add(" "+CRED+"Blok: "+_screen_num(b.get("total"))+C0+
            " | Suricata: "+_screen_num(b.get("suricata"))+
            " | OTX: "+_screen_num(b.get("otx"))+
            " | DNS-less: "+_screen_num(b.get("dnsless"))+
            " | Anomali: "+_screen_num(b.get("anomaly")))
    # Compact, factual scan summary: no duplicate layer list or resource bars.
    add(" "+CMAGENTA+"DOSYA TARAMASI"+C0+
        " | Son: "+fmt(schedule.get("completed"))+
        " | Sonraki: "+fmt(schedule.get("next")))
    for engine in ("clamav",):
        st=data.get(engine) or {}
        label=_screen_status(st.get("returncode"), st.get("state"))
        color=CGREEN if label=="OK" else CRED if label=="HATA" else CYELLOW
        add(" "+color+engine.upper()+" "+label+C0+
            " | Eşleşme: "+_screen_num(st.get("matches"))+
            " | Dosya: "+_screen_num(st.get("files_with_matches"))+
            " | Karantina: "+_screen_num(st.get("quarantined"))+
            " | Hata: "+_screen_num(st.get("failed")))
        if st.get("returncode") not in (None, 0):
            prior=(data.get("last_success") or {}).get(engine) or {}
            detail=st.get("errors") or []
            if isinstance(detail, list):
                detail="; ".join(str(x) for x in detail)
            add(" "+CRED+"  Son tarama başarısız"+C0+
                " | Son başarılı: "+_screen_stamp(prior.get("completed"))+
                " | "+str(detail or "Ayrıntılar tarama günlüğünde"))
    add(" "+CMAGENTA+"Karantina:"+C0+" "+_screen_num(inv.get("active"))+
        " aktif / "+_screen_num(inv.get("total"))+" toplam"+
        " | İnceleme: "+_screen_num((data.get("clamav") or {}).get("review"))+
        " | "+(CYELLOW+"TARANIYOR "+str(running.get("engine","")).upper()+C0
               if running else CDIM+"Beklemede"+C0))
    connections=list(n.get("connections") or [])
    drop_stats=read_drop_stats()
    net_state=read_json(Path("/var/lib/satsuma-sentinel/state/network-guard.json"))
    add(" Ağ kilidi: "+("AKTİF — yerelden --network-reset gerekir" if net_state.get("latched") else "kapalı")+" | Eşik: 30 toplam / 10 IP aynı /24")
    add(" Suricata IPS drop: "+(str(drop_stats['blocked']) if drop_stats['available'] else "bilinmiyor")+
        " | Kaynak: "+str(drop_stats.get('source') or "yok")+
        " | Tazelik: "+str(drop_stats.get('freshness') or "bilinmiyor"))
    add(" "+ram35_dashboard())
    add(" "+aide_dashboard())
    footer=" "+CDIM+"Ctrl+C: cikis | Saatlik ClamAV | Salt okunur dashboard"+C0
    # Two section headings, one table header and one footer: six fixed rows.
    room=max(0,height-len(lines)-6)
    if height>=30:
        connection_slots=min(len(connections),12,max(0,room//3))
    elif height>=22:
        connection_slots=min(len(connections),5,max(0,room//3))
    else:
        connection_slots=min(len(connections),2,max(0,room//4))
    event_slots=max(0,room-connection_slots)
    heading("CANLI GUVENLIK OLAY AKISI",CMAGENTA)
    if entries:
        for e in entries[:event_slots]:
            add(screen_event_line(e,width))
        for _ in range(max(0,event_slots-len(entries))):
            add("  "+CDIM+"—"+C0)
    elif event_slots:
        add("  "+CGREEN+"[✓] Yeni güvenlik olayı yok"+C0)
        for _ in range(event_slots-1):
            add("  "+CDIM+"—"+C0)
    heading("AKTIF BAGLANTILAR (%s baglanti, %s subnet)" %
            (_screen_num(n.get("connection_count",0)),_screen_num(n.get("connection_groups",0))),CGREEN)
    if width>=88:
        add(" "+CWHITE+"IP ADRES".ljust(22)+" | "+"SUBNET".ljust(20)+" | "+"BAĞLANTI".ljust(9)+" | PROSES"+C0)
    elif width>=64:
        add(" "+CWHITE+"IP ADRES".ljust(17)+" | "+"SUBNET".ljust(18)+" | "+"BAĞ".ljust(5)+" | PROSES"+C0)
    else:
        add(" "+CWHITE+"IP ADRES".ljust(16)+" | "+"BAĞ".ljust(4)+" | PROSES"+C0)
    for c in connections[:connection_slots]:
        ip=str(c.get("ip","-")); subnet=str(c.get("subnet",ip+"/32"))
        count=_screen_num(c.get("count",0))
        proc=str(c.get("process","unknown"))
        trusted=bool(c.get("trusted"))
        color=CDIM if trusted else CRED if int(count)>=5 else CYELLOW if int(count)>3 else CGREEN
        proc+= " (güvenilir)" if trusted else ""
        if width>=88:
            row=" %-20s | %-20s | %-9s | %s" % (ip,subnet,count,proc)
        elif width>=64:
            row=" %-15s | %-18s | %-5s | %s" % (ip,subnet,count,proc)
        else:
            row=" %-15s | %-4s | %s" % (ip,count,proc)
        add(color+row+C0)
    add(footer)
    return "\n".join(lines[:height])+"\n"

def original_style_loop():
    if not sys.stdout.isatty():
        print(render_original_style(),end="")
        return 0
    print("\033[?1049h\033[?25l",end="",flush=True)
    try:
        while True:
            print("\033[H\033[2J"+render_original_style(),end="",flush=True)
            time.sleep(3)
    except KeyboardInterrupt:
        return 0
    finally:
        print("\033[?25h\033[?1049l",end="",flush=True)


# This scans RAM-backed FILES, not arbitrary process address spaces.
def browser_audit():
    result={'checked':0,'critical':[],'warnings':[],'incomplete':[],'policy_runtime_verified':False}
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal(): continue
        try:
            raw=(proc/'cmdline').read_bytes()
            if not raw: continue
            args=[a for a in raw.split(b'\0') if a]; name=os.path.basename(os.fsdecode(args[0])).lower()
            # Firefox renames its child processes ("Isolated Web Content"), so the
            # program file decides, not the shown name (live field run 2026-11-10:
            # only 2 of 17 Firefox processes were checked).
            # Firefox alt süreçlerinin görünen adını değiştirir; program dosyasına bakılır.
            try: exe=os.path.basename(os.readlink(proc/'exe')).removesuffix(' (deleted)').lower()
            except OSError: exe=''
            if exe in ('firefox','firefox-bin','chrome','chromium','chromium-browser'): name=exe
            if name in ('gnome-browser-connector','chrome-gnome-shell'):
                result['critical'].append({'pid':int(proc.name),'reason':'GNOME connector process observed; browser integration must remain denied'})
                continue
            if not any(x in name for x in ('firefox','chromium','chrome')): continue
            status={}
            for line in (proc/'status').read_text().splitlines():
                if ':' in line:
                    k,v=line.split(':',1); status[k]=v.strip()
            result['checked']+=1; issues=[]
            env={}
            for item in (proc/'environ').read_bytes().split(b'\0'):
                if b'=' in item:
                    k,v=item.split(b'=',1)
                    if k.startswith(b'MOZ_'): env[k.decode('ascii','replace')]=v
            for key in ('MOZ_DISABLE_CONTENT_SANDBOX','MOZ_DISABLE_RDD_SANDBOX','MOZ_DISABLE_GPU_SANDBOX','MOZ_DISABLE_GMP_SANDBOX'):
                if env.get(key,b'') not in (b'',b'0'):
                    issues.append('sandbox environment override: '+key)
            for key in ('MOZ_ALLOW_DOWNGRADE','MOZ_ASSUME_USER_NS'):
                if env.get(key,b'') not in (b'',b'0'):
                    result['warnings'].append({'pid':int(proc.name),'reason':'review launcher environment: '+key})
            if status.get('Uid','').split()[:1]==['0']: issues.append('browser runs as root')
            if b'--no-sandbox' in args or b'--disable-seccomp-filter-sandbox' in args:
                issues.append('sandbox disabled on command line')
            # Firefox names the child type last ("tab", "socket", "rdd", "utility"...).
            # The fork server applies seccomp to the children it starts and does not
            # carry it itself; every other child type must be filtered.
            # Fork server seccomp'u ürettiği süreçlere uygular; diğer her tür filtreli olmalı.
            child_type=args[-1].decode('ascii','replace') if b'-contentproc' in args else ''
            renderer=b'--type=renderer' in args or (b'-contentproc' in args and child_type!='forkserver')
            if renderer and status.get('Seccomp')!='2':
                issues.append('content process seccomp filter absent'+(' ('+child_type+')' if child_type else ''))
            for why in issues: result['critical'].append({'pid':int(proc.name),'reason':why})
        except (FileNotFoundError,ProcessLookupError): continue
        except PermissionError: result['incomplete'].append(int(proc.name))
    result['completed']=int(time.time())
    result['returncode']=1 if result['critical'] else (2 if result['incomplete'] else 0)
    write_json(LOG/'browser-status.json',result)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    return result['returncode']

def memory_scan():
    secure_dir(LOG)
    result = {'scope':'tmpfs/devtmpfs regular files and process memfd/deleted files',
              'full_ram_scan':False,'scanned':0,'matches':0,'failed':0,'limited':0,
              'changed':0,'device_nodes_skipped':0,'bytes':0,'issues':[]}
    deadline=time.monotonic()+180
    max_file=64*1048576; max_total=512*1048576; seen=set(); examined=0
    def issue(kind, path, why):
        result[kind]+=1
        if len(result['issues'])<100:
            result['issues'].append({'path':str(path),'reason':str(why)[:300]})
    def candidates():
        # Walk /dev too, but inspect only ordinary files. Never open devices.
        mounts=[]; others=set()
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            left,right=line.split(' - ',1)
            point=left.split()[4].replace('\\040',' ')
            if right.split()[0] in ('tmpfs','devtmpfs'):
                mounts.append(point)
            else:
                # FUSE (gvfs, doc portal), proc, cgroup...: not memory files, and a
                # user's FUSE mount refuses even root. Live session fix 2026-11-10.
                # tmpfs olmayan bağlantılar bellek dosyası değildir; atlanır.
                others.add(point)
        roots=['/dev','/dev/shm','/run/user']
        roots.extend(m for m in mounts if re.fullmatch(r'/run/user/[0-9]+',m))
        for root in dict.fromkeys(roots):
            if not any(root==m or root.startswith(m.rstrip('/')+'/') for m in mounts):
                continue
            if not os.path.isdir(root) or os.path.islink(root): continue
            for parent,dirs,files in os.walk(root,followlinks=False,
                    onerror=lambda e: issue('failed',getattr(e,'filename',root),e)):
                if time.monotonic()>=deadline:
                    issue('limited',parent,'directory traversal deadline'); return
                dirs[:]=[d for d in dirs if not os.path.islink(os.path.join(parent,d)) and
                         os.path.join(parent,d) not in others and
                         not os.path.ismount(os.path.join(parent,d))]
                for name in files: yield os.path.join(parent,name),False
        for proc in Path('/proc').iterdir():
            if not proc.name.isdecimal(): continue
            try:
                exe=proc/'exe'; target=os.readlink(exe)
                if target.endswith(' (deleted)'): yield str(exe),True
                for fd in (proc/'fd').iterdir():
                    try: target=os.readlink(fd)
                    except FileNotFoundError: continue
                    if target.startswith(('/memfd:','memfd:')) or target.endswith(' (deleted)'):
                        yield str(fd),True
            except (FileNotFoundError,ProcessLookupError): continue
            except PermissionError as exc: issue('failed',proc,exc)
    try:
        ensure_clamd_reachable()
        for path,magic in candidates():
            examined+=1
            if examined>4096 or time.monotonic()>=deadline or result['bytes']>=max_total:
                issue('limited',path,'global time/file/byte budget reached'); break
            pin=fd=None
            try:
                # O_PATH does not invoke device open handlers. Follow only the
                # explicitly enumerated /proc magic links, then require regular.
                pin=os.open(path,os.O_PATH | (0 if magic else os.O_NOFOLLOW))
                st=os.fstat(pin)
                if not stat.S_ISREG(st.st_mode):
                    result['device_nodes_skipped']+=1; continue
                key=(st.st_dev,st.st_ino)
                if key in seen: continue
                seen.add(key)
                if st.st_size>max_file or result['bytes']+st.st_size>max_total:
                    issue('limited',path,'file size budget'); continue
                fd=os.open('/proc/self/fd/%d'%pin,os.O_RDONLY|os.O_NONBLOCK)
                if identity(st)!=identity(os.fstat(fd)): raise RuntimeError('file changed before scan')
                # The content goes over the socket (--stream): clamd never opens the
                # file, so SELinux needs no new permission for user files and memfds
                # (live session field run 2026-11-10: 20 files failed with --fdpass).
                # İçerik soketten gönderilir; clamd dosyayı açmaz, SELinux izni gerekmez.
                rc,out,err=bounded_child(clamd_command()+['--stream','--infected','--stdout','--no-summary',
                    '-'],timeout=max(1,min(30,int(deadline-time.monotonic()))),
                    memory=CLAMD_CLIENT_VMEM,stdin_fd=fd)
                result['bytes']+=st.st_size
                if rc not in (0,1):
                    # --stdout sends clamd's own error to stdout; report both streams.
                    why=(out+b' '+err).decode('utf-8','replace').strip()
                    raise RuntimeError('clamdscan (kod %d): %s'%(rc,why[:300] or 'neden bildirilmedi'))
                text=out.decode('utf-8','replace')
                if 'Heuristics.Limits.Exceeded' in text:
                    issue('limited',path,'clamd scan limit'); continue
                if identity(st)!=identity(os.fstat(fd)):
                    issue('changed',path,'file changed during scan'); continue
                result['scanned']+=1
                if rc==1:
                    result['matches']+=1
                    record('memory_file_match',path=path,report=text[:2000],action='review_only')
            except (FileNotFoundError,ProcessLookupError):
                issue('changed',path,'process/file disappeared')
            except (OSError,RuntimeError,subprocess.SubprocessError) as exc:
                issue('failed',path,exc)
            finally:
                for descriptor in (fd,pin):
                    if descriptor is not None: os.close(descriptor)
    except (OSError,RuntimeError) as exc: issue('failed','memory-scan',exc)
    result['incomplete']=bool(result['failed'] or result['limited'] or result['changed'])
    result['completed']=int(time.time())
    result['returncode']=2 if result['incomplete'] else (1 if result['matches'] else 0)
    write_json(LOG/'memory-status.json',result)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    return result['returncode']

def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    s = sub.add_parser("scan")
    s.add_argument("engine", choices=["clamav"])
    s.add_argument("--path", action="append", dest="paths")
    s.add_argument("--apply", action="store_true")
    q = sub.add_parser("quarantine")
    q.add_argument("path")
    q.add_argument("--reason", required=True)
    q.add_argument("--apply", action="store_true")
    r = sub.add_parser("restore")
    r.add_argument("id")
    r.add_argument("--to")
    mem_parser=sub.add_parser("memory-scan")
    mem_parser.add_argument("--wait", action="store_true")
    sub.add_parser("browser-audit")
    sub.add_parser("list")
    sub.add_parser("screen")
    sub.add_parser("screen-old")
    status_parser = sub.add_parser("status")
    status_parser.add_argument("--dashboard", action="store_true")
    sched = sub.add_parser("scheduler")
    sched.add_argument("--once", action="store_true")
    sched.add_argument("--interval", type=int, default=3600)
    a = p.parse_args()
    if a.action in ("screen", "screen-old", "status"):
        pass
    elif os.geteuid() != 0:
        p.error("Root required")
    if a.action not in ("screen", "screen-old", "status"):
        secure_dir(BASE)
        secure_dir(LOG)
    if a.action == "screen-old":
        return screen_loop()
    if a.action == "screen":
        incoming = os.environ.get("SATSUMA_SCREEN_DATA", "")
        if incoming:
            try:
                network = json.loads(incoming)
            except ValueError:
                network = {}
            print(render_original_style(network=network), end="")
            return 0
        return original_style_loop()
    if a.action == "status":
        if a.dashboard:
            dashboard_lines()
        else:
            print(json.dumps(dashboard_data(), ensure_ascii=False, indent=2))
        return 0
    if a.action == "scheduler":
        return scheduler(a.interval, a.once)
    if a.action == "list":
        for item in sorted(BASE.iterdir()):
            if (item / "manifest.json").is_file():
                m = json.loads((item / "manifest.json").read_text())
                print(m["id"], m["state"], m["original"])
        return 0
    if a.action == "browser-audit":
        return browser_audit()
    if a.action == "restore":
        restore(a.id, a.to)
        return 0
    with open(LOCK, "a+") as lock:
        os.fchmod(lock.fileno(), 0o600)
        wait_until=time.monotonic()+(120 if getattr(a,'wait',False) else 0)
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic()>=wait_until:
                    record("scan_skipped", reason="Another scan is running; preflight not complete")
                    return 3
                time.sleep(0.25)
        try:
            if a.action == "quarantine":
                result = quarantine(a.path, "manual", a.reason, a.apply)
                return 0 if result or not a.apply else 2
            if a.action == "browser-audit":
                return browser_audit()
            if a.action == "memory-scan":
                return memory_scan()
            return scan(a.engine, a.paths or DIRS, a.apply)
        finally:
            pass

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print("ERROR:", exc, file=sys.stderr)
        sys.exit(2)
SATSUMA_EMBEDDED_PYTHON
}

satsuma_file_dashboard() {
    satsuma_file_guard status --dashboard
}

satsuma_file_scheduler_start() {
    if systemctl is-enabled --quiet satsuma-file-scan.service 2>/dev/null; then
        if ! systemctl is-active --quiet satsuma-file-scan.service 2>/dev/null; then
            echo "Tarama servisi durdurulmuş; bağımsız ve sınırsız tarayıcı başlatılmıyor." >&2
        fi
        return 0
    fi
    if [[ -r /run/satsuma-file-scheduler.lock ]] &&
       command -v fuser >/dev/null 2>&1 &&
       fuser /run/satsuma-file-scheduler.lock >/dev/null 2>&1; then
        return 0
    fi
    echo "Yönetilen tarama servisi kurulu değil. Önce --scanner-repair çalıştırın." >&2
    return 1
}

satsuma_file_scanners_initialize() {
    install -d -m 700 /var/log/satsuma /var/lib/satsuma-sentinel/quarantine || return 1
    if [[ "$ENABLE_CLAMAV" == "true" ]] && ! command -v clamdscan >/dev/null 2>&1; then
        ENABLE_CLAMAV=false
    fi
}

satsuma_file_dashboard_section() {
    printf '\n%s\n' "  ---------------- DOSYA GUVENLIGI ----------------"
    satsuma_file_dashboard 2>/dev/null || printf '%s\n' "  Tarama durumu okunamadi."
    printf '%s\n' "  ------------------------------------------------"
}


satsuma_scanner_packages() {
    satsuma_install_platform_packages
}

# Satsuma transactional clamd configuration (V59 repair).
# Configuration changes are staged, validated, backed up and applied once.
_CLAMD_SCAN_CONF="/etc/clamav/clamd.conf"
_CLAMD_MEM_DROPIN_DIR="/etc/systemd/system/clamav-daemon.service.d"
_CLAMD_MEM_DROPIN="$_CLAMD_MEM_DROPIN_DIR/satsuma-memory.conf"
CLAMD_MEMORY_HIGH="${CLAMD_MEMORY_HIGH:-2G}"
CLAMD_MEMORY_MAX="${CLAMD_MEMORY_MAX:-3G}"
export CLAMD_MEMORY_HIGH CLAMD_MEMORY_MAX

wait_for_clamd_ready() {
    local i
    for ((i=0; i<90; i++)); do
        if ! systemctl is-active --quiet clamav-daemon.service; then
            return 1
        fi
        timeout 10 clamdscan --ping 1 >/dev/null 2>&1 && return 0
        sleep 2
    done
    return 1
}

satsuma_clamd_transaction() {
    satsuma_platform_config || return 1
    /usr/bin/python3 -I -S - "$SATSUMA_PLATFORM_FAMILY" <<'SATSUMA_CLAMD_TRANSACTION_PY'
#!/usr/bin/env python3
"""Satsuma: transactional clamd configuration update. Standard library only."""
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

if sys.argv[1] == 'fedora':
    CONF=Path('/etc/clamd.d/scan.conf'); FRESH_CONF=Path('/etc/freshclam.conf'); UNIT='clamd@scan.service'
elif sys.argv[1] == 'debian':
    CONF=Path('/etc/clamav/clamd.conf'); FRESH_CONF=Path('/etc/clamav/freshclam.conf'); UNIT='clamav-daemon.service'
else: raise RuntimeError('Unknown scanner platform')
DROP=Path('/etc/systemd/system')/(UNIT+'.d')/'satsuma-memory.conf'
BACKUPS=Path('/var/lib/satsuma-sentinel/clamd-config-backups')
LOCKDIR=Path('/run')
SCAN_LIMITS = {
    "MaxFileSize": "256M", "MaxScanSize": "512M",
    "StreamMaxLength": "256M", "MaxRecursion": "16",
    "MaxFiles": "10000", "MaxScanTime": "120000",
}

def run(args, timeout=30, check=True):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError("%s failed (%s): %s" % (args[0], p.returncode, p.stdout[-2000:]))
    return p

def log(message):
    print("[CLAMD] " + message, flush=True)

def memory_value(name, default):
    value = os.environ.get(name, default)
    if not re.fullmatch(r"[1-9][0-9]*[KMGT]", value):
        raise ValueError("Invalid %s: %s" % (name, value))
    return value, int(value[:-1]) * 1024 ** ("KMGT".index(value[-1]) + 1)

def render_config(source):
    text = source.decode("utf-8")
    result, seen = [], set()
    for line in text.splitlines(keepends=True):
        match = re.match(r"^\s*([A-Za-z][A-Za-z0-9]*)\s+", line)
        key = match.group(1) if match else None
        if key in SCAN_LIMITS:
            if key not in seen:
                result.append(key + " " + SCAN_LIMITS[key] + "\n")
                seen.add(key)
            continue
        result.append(line)
    if result and not result[-1].endswith("\n"):
        result[-1] += "\n"
    for key, value in SCAN_LIMITS.items():
        if key not in seen:
            result.append(key + " " + value + "\n")
    return "".join(result).encode("utf-8")

def render_dropin():
    high, h = memory_value("CLAMD_MEMORY_HIGH", "2G")
    maximum, m = memory_value("CLAMD_MEMORY_MAX", "3G")
    if h >= m:
        raise ValueError("MemoryHigh must be lower than MemoryMax")
    return ("[Service]\nMemoryAccounting=yes\nMemoryHigh=%s\nMemoryMax=%s\n"
            "OOMPolicy=stop\n" % (high, maximum)).encode()

def read_state(path):
    if path.is_symlink():
        raise RuntimeError("Refusing symlink target: " + str(path))
    if not path.exists():
        return None
    if not path.is_file():
        raise RuntimeError("Not a regular configuration file: " + str(path))
    st = path.stat()
    return {"data": path.read_bytes(), "mode": st.st_mode & 0o7777,
            "uid": st.st_uid, "gid": st.st_gid}

def atomic_write(path, data, state=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".satsuma-", dir=path.parent)
    try:
        os.fchmod(fd, state["mode"] if state else 0o644)
        if state:
            os.fchown(fd, state["uid"], state["gid"])
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        if path in (CONF,DROP) and Path("/sys/fs/selinux/enforce").exists():run(["restorecon","-v",str(path)])
        dirfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def restore(path, state):
    if state is None:
        if path.exists() or path.is_symlink():
            path.unlink()
    else:
        atomic_write(path, state["data"], state)

def validate(candidate, work):
    dropin = render_dropin()
    # clamconf has --config-dir, not --config-file or --config-test.
    # Validate a staged directory, never a live configuration.
    cfgdir = work / "validation"
    cfgdir.mkdir()
    (cfgdir / "clamd.conf").write_bytes(candidate)
    fresh = FRESH_CONF
    if fresh.is_file() and not fresh.is_symlink():
        shutil.copy2(fresh, cfgdir / "freshclam.conf")
    result = run(["clamconf", "--config-dir", str(cfgdir)], timeout=30)
    if re.search(r"(?im)^\s*(ERROR|FATAL):|error parsing|unknown option|invalid option", result.stdout):
        raise RuntimeError("ClamAV configuration validation failed: " + result.stdout[-2000:])
    # Validate the drop-in syntax without installing it.
    unit = work / "satsuma-clamd-check.service"
    unit.write_text("[Unit]\nDescription=Satsuma configuration check\n"
                    "[Service]\nType=oneshot\nExecStart=/bin/true\n" +
                    dropin.decode())
    result = run(["systemd-analyze", "verify", str(unit)], timeout=30)
    if re.search(r"(?im)unknown lvalue|failed to parse|invalid argument|bad unit file setting", result.stdout):
        raise RuntimeError("Invalid systemd drop-in: " + result.stdout[-2000:])

def wait_ready():
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if run(["systemctl", "is-active", "--quiet", UNIT], check=False).returncode != 0:
            raise RuntimeError("clamav-daemon is not active")
        if run(["clamdscan", "--config-file",str(CONF),"--ping", "1"], timeout=10, check=False).returncode == 0:
            return
        time.sleep(2)
    raise RuntimeError("clamd did not become ready within 180 seconds")

def snapshot(states):
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(BACKUPS, 0o700)
    folder = Path(tempfile.mkdtemp(prefix="config-", dir=BACKUPS))
    os.chmod(folder, 0o700)
    manifest = {}
    for label, state in states.items():
        manifest[label] = None if state is None else {k:v for k,v in state.items() if k!="data"}
        if state is not None:
            atomic_write(folder / label, state["data"], state)
    atomic_write(folder / "manifest.json", json.dumps(manifest, indent=2).encode(),
                 {"mode":0o600,"uid":os.geteuid(),"gid":os.getegid()})
    return folder

def transaction():
    if os.geteuid() != 0:
        raise RuntimeError("Root required")
    if not CONF.is_file() or CONF.is_symlink():
        raise RuntimeError("Missing or unsafe clamd.conf")
    for cmd in ("clamconf", "clamdscan", "systemctl", "systemd-analyze"):
        if not shutil.which(cmd):
            raise RuntimeError("Required command missing: " + cmd)
    LOCKDIR.mkdir(parents=True, exist_ok=True)
    # Lock order matches the scanner updater: scan lock first.
    def acquire(fd):
        deadline = time.monotonic() + 30
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Scanner/configuration busy; no changes made")
                time.sleep(0.1)
    with open(LOCKDIR / "satsuma-file-scan.lock", "a+") as scan_lock:
        acquire(scan_lock)
        with open(LOCKDIR / "satsuma-clamd-config.lock", "a+") as config_lock:
            acquire(config_lock)
            original = {"clamd.conf":read_state(CONF), "satsuma-memory.conf":read_state(DROP)}
            proposed = {"clamd.conf":render_config(original["clamd.conf"]["data"]),
                        "satsuma-memory.conf":render_dropin()}
            changed = [key for key in proposed if original[key] is None or
                       original[key]["data"] != proposed[key]]
            with tempfile.TemporaryDirectory(prefix="satsuma-clamd-") as tmp:
                work = Path(tmp)
                validate(proposed["clamd.conf"], work)
            if not changed:
                if Path("/sys/fs/selinux/enforce").exists():run(["restorecon","-v",str(CONF),str(DROP)])
                log("Configuration already matches requested values; no restart.")
                return 0
            was_active = run(["systemctl","is-active","--quiet",UNIT],check=False).returncode == 0
            backup = snapshot(original)
            log("Backup: " + str(backup))
            touched = []
            try:
                for label, path in (("clamd.conf",CONF),("satsuma-memory.conf",DROP)):
                    if label in changed:
                        # Existing files retain ownership and mode.
                        touched.append(label)
                        atomic_write(path, proposed[label], original[label])
                run(["systemctl","daemon-reload"])
                if was_active:
                    run(["systemctl","restart",UNIT],timeout=120)
                    wait_ready()
                log("Configuration applied; " + ("daemon ready." if was_active else "daemon left stopped."))
                return 0
            except BaseException as exc:
                log("Apply failed: " + str(exc))
                log("Restoring original configuration.")
                rollback_errors = []
                for label,path in (("clamd.conf",CONF),("satsuma-memory.conf",DROP)):
                    if label in touched:
                        try:
                            restore(path,original[label])
                        except Exception as err:
                            rollback_errors.append(str(err))
                try:
                    run(["systemctl","daemon-reload"])
                    if was_active:
                        run(["systemctl","restart",UNIT],timeout=120)
                        wait_ready()
                    else:
                        run(["systemctl","stop",UNIT],timeout=120)
                except Exception as err:
                    rollback_errors.append(str(err))
                if rollback_errors:
                    log("ROLLBACK FAILED: " + "; ".join(rollback_errors))
                    log("Backup retained for manual recovery: " + str(backup))
                else:
                    log("Original configuration and prior service state restored.")
                raise RuntimeError("Configuration update failed; rollback " +
                                   ("requires manual review" if rollback_errors else "completed")) from exc

if __name__ == "__main__":
    try:
        sys.exit(transaction())
    except Exception as exc:
        print("[CLAMD] ERROR: " + str(exc), file=sys.stderr)
        sys.exit(1)
SATSUMA_CLAMD_TRANSACTION_PY
}

apply_clamd_config_and_restart() {
    satsuma_clamd_transaction
}

satsuma_scanner_updates() {
    satsuma_platform_config && satsuma_update_clamav_signatures && satsuma_suricata_rules_bootstrap
}

satsuma_scanners_configure() {
    satsuma_platform_config && satsuma_prepare_clamd_platform &&
    satsuma_update_clamav_signatures && satsuma_clamd_transaction &&
    satsuma_start_clamd_platform && satsuma_repair_suricata_permissions && satsuma_suricata_rules_bootstrap && satsuma_selinux_label_services
}


satsuma_scanner_install_updates() {
    # Do not create or enable a network updater.
    return 0
}

satsuma_file_install_hourly() {
    [[ $EUID -eq 0 ]] || { echo "Root gerekli" >&2; return 1; }
    local target="/usr/local/bin/satsuma-mini" tmp backup
    command -v flock >/dev/null 2>&1 || return 1
    # V62: root servisi olarak kurulacak betik, düşük yetkili biri tarafından yazılabiliyorsa
    # o kullanıcı root'a yükselebilir. Kaynak root'a ait ve grup/diğer yazamaz olmalı.
    local self_owner self_mode
    local ancestor="$SATSUMA_SELF" astat
    while [[ "$ancestor" != / ]]; do
        [[ ! -L "$ancestor" ]] || return 1
        astat=$(stat -c '%u %a' -- "$ancestor") || return 1
        local au am
        read -r au am <<< "$astat"
        [[ "$au" == 0 ]] && (( (8#$am & 8#022) == 0 )) || {
            echo "Güvensiz kurulum kaynağı/üst dizin: $ancestor" >&2; return 1;
        }
        ancestor=$(dirname -- "$ancestor")
    done
    self_owner=$(stat -c '%u' -- "$SATSUMA_SELF" 2>/dev/null) || return 1
    self_mode=$(stat -c '%a' -- "$SATSUMA_SELF" 2>/dev/null) || return 1
    if [[ "$self_owner" != "0" ]] || (( (8#$self_mode & 8#022) != 0 )); then
        echo "Güvenlik: $SATSUMA_SELF root'a ait olmalı ve grup/diğer yazma izni olmamalı." >&2
        echo "Düzeltmek için: sudo chown root:root '$SATSUMA_SELF' && sudo chmod 750 '$SATSUMA_SELF'" >&2
        return 1
    fi
    install -d -m 700 /var/log/satsuma /var/lib/satsuma-sentinel/quarantine || return 1
    if ! cmp -s "$SATSUMA_SELF" "$target"; then
        tmp=$(mktemp /usr/local/bin/.satsuma.XXXXXXXX) || return 1
        install -m 0750 "$SATSUMA_SELF" "$tmp" || { rm -f "$tmp"; return 1; }
        if [[ -e "$target" || -L "$target" ]]; then
            backup="${target}.bak.$(date +%Y%m%d-%H%M%S)"
            cp -a -- "$target" "$backup" || { rm -f "$tmp"; return 1; }
        fi
        mv -f -- "$tmp" "$target" || return 1
        # V62: eski yedekler birikmesin (son 5 tutulur)
        local old
        while IFS= read -r old; do rm -f -- "$old"; done < <(ls -1t -- "${target}".bak.* 2>/dev/null | tail -n +6)
    fi
    cat > /etc/systemd/system/satsuma-file-scan.service <<'SATSUMA_SYSTEMD_UNIT'
[Unit]
Description=Satsuma hourly ClamAV file scanner
After=local-fs.target satsuma-selinux-guard.service satsuma-memory-hardening.service
Requires=satsuma-selinux-guard.service satsuma-memory-hardening.service
StartLimitIntervalSec=1h
StartLimitBurst=2

[Service]
Type=simple
ExecStart=/usr/local/bin/satsuma-mini --file-scan scheduler
Restart=on-failure
RestartSec=60
Nice=10
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
MemoryAccounting=yes
MemoryHigh=768M
MemoryMax=1G
MemorySwapMax=0
OOMPolicy=stop
KillMode=control-group
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
SATSUMA_SYSTEMD_UNIT
    chmod 644 /etc/systemd/system/satsuma-file-scan.service
    if command -v restorecon >/dev/null; then
        restorecon -v "$target" /etc/systemd/system/satsuma-file-scan.service || return 1
    fi
    systemctl daemon-reload || return 1
    systemctl enable satsuma-file-scan.service || return 1
    echo "Tarama servisi kuruldu. Mevcut tarama kesilmedi."
    echo "Bellek sınırları sonraki servis başlangıcında uygulanır."
}

# Short commands for daily use (user request 2026-11-11). Each one is a fixed,
# root-owned wrapper around a read-only satsuma-mini option; satsuma-clamav tara
# only starts a new scan cycle.
# Günlük kullanım için kısa komutlar (kullanıcı isteği 2026-11-11). Her biri
# satsuma-mini'nin salt okunur bir seçeneğini çağıran, root'a ait sabit bir
# sarmalayıcıdır; yalnızca satsuma-clamav tara yeni bir tarama döngüsü başlatır.
SATSUMA_SHORTCUTS=(satsuma-dashboard satsuma-durum satsuma-clamav satsuma-suricata satsuma-ram satsuma-log satsuma-aide)

satsuma_shortcut_body() {
    printf '%s\n' '#!/bin/bash -p' "# $1 - Satsuma Mini kısa komutu; satsuma-mini --install-service tarafından yazılır." \
        'set -u' '[[ $EUID -eq 0 ]] || exec sudo "$0" "$@"' 'M=/usr/local/bin/satsuma-mini'
    case "$1" in
        satsuma-dashboard) printf '%s\n' 'exec /bin/bash -p "$M" --dashboard-live' ;;
        satsuma-durum) printf '%s\n' \
            'for u in satsuma-mini satsuma-firewall suricata satsuma-file-scan satsuma-ram-clamd satsuma-memory-watch satsuma-network-guard; do' \
            '    printf "%-24s %s\n" "$u" "$(systemctl is-active "$u" 2>/dev/null)"' \
            'done' \
            'echo' 'exec /bin/bash -p "$M" --dashboard' ;;
        satsuma-clamav) printf '%s\n' \
            'if [[ "${1:-}" == tara ]]; then' \
            '    systemctl reset-failed satsuma-file-scan.service 2>/dev/null' \
            '    systemctl restart satsuma-file-scan.service && echo "Yeni tarama döngüsü başlatıldı. İzlemek için: satsuma-clamav"' \
            '    exit $?' \
            'fi' \
            'echo "satsuma-file-scan: $(systemctl is-active satsuma-file-scan 2>/dev/null)"' \
            'exec /bin/bash -p "$M" --dashboard' ;;
        satsuma-suricata) printf '%s\n' \
            'echo "suricata: $(systemctl is-active suricata 2>/dev/null)"' \
            '/bin/bash -p "$M" --verify-ips' \
            'echo' 'echo "Son 20 Suricata alarmı:"' \
            'tail -n 5000 /var/log/suricata/eve.json 2>/dev/null | jq -r '"'"'select(.event_type=="alert") | "\(.timestamp[0:19]) \(.alert.severity) \(.src_ip):\(.src_port // "-") -> \(.dest_ip):\(.dest_port // "-") \(.alert.signature)"'"'"' 2>/dev/null | tail -n 20' ;;
        satsuma-ram) printf '%s\n' 'exec /bin/bash -p "$M" --memory35-status' ;;
        satsuma-aide) printf '%s\n' \
            'if [[ "${1:-}" == onayla ]]; then exec /bin/bash -p "$M" --aide-onayla; fi' \
            'exec /bin/bash -p "$M" --aide-fark' ;;
        satsuma-log) printf '%s\n' 'exec journalctl -f -u satsuma-mini -u satsuma-file-scan -u suricata -u satsuma-memory-watch' ;;
        *) return 1 ;;
    esac
}

satsuma_install_shortcuts() {
    [[ $EUID -eq 0 ]] || return 1
    local name tmp
    for name in "${SATSUMA_SHORTCUTS[@]}"; do
        tmp=$(mktemp /usr/local/bin/.satsuma-kisayol.XXXXXXXX) || return 1
        if ! satsuma_shortcut_body "$name" > "$tmp" || ! chown root:root "$tmp" || ! chmod 0755 "$tmp" ||
           ! /bin/bash -n "$tmp" || ! mv -f -- "$tmp" "/usr/local/bin/$name"; then
            rm -f -- "$tmp"; return 1
        fi
    done
    if command -v restorecon >/dev/null; then
        for name in "${SATSUMA_SHORTCUTS[@]}"; do restorecon "/usr/local/bin/$name" || return 1; done
    fi
    echo "Kısa komutlar: ${SATSUMA_SHORTCUTS[*]}"
}

# Installed-system AIDE commands (user request 2026-11-11). --aide-fark only
# reads; --aide-onayla keeps the old reference as evidence and takes a new one.
# Kurulu sistem AIDE komutları (kullanıcı isteği 2026-11-11). --aide-fark yalnızca
# okur; --aide-onayla eski örneği kanıt olarak saklar ve yenisini alır.
SATSUMA_AIDE_DIR=/var/lib/satsuma-sentinel/aide

satsuma_aide_show_difference() {
    [[ $EUID -eq 0 ]] || { echo "Root gerekli" >&2; return 1; }
    local pending="$SATSUMA_AIDE_DIR/onay-bekliyor" file
    if [[ ! -f "$pending" ]]; then
        echo "Onay bekleyen AIDE farkı yok."
        ls -1t /var/log/satsuma/aide-fark/ 2>/dev/null | head -n 5 | sed 's|^|  önceki rapor: /var/log/satsuma/aide-fark/|'
        return 0
    fi
    file=$(head -n 1 -- "$pending")
    [[ "$file" == /var/log/satsuma/aide-fark/fark-*.txt && -f "$file" && ! -L "$file" ]] || {
        echo "Onay kaydı geçersiz: $pending" >&2; return 1; }
    echo "Onay bekleyen AIDE farkı: $file"
    echo
    cat -- "$file"
}

satsuma_aide_approve() {
    [[ $EUID -eq 0 ]] || { echo "Root gerekli" >&2; return 1; }
    local AIDE_CONF="$SATSUMA_AIDE_DIR/aide-live.conf" db="$SATSUMA_AIDE_DIR/aide.db.gz"
    local new="$SATSUMA_AIDE_DIR/aide.db.new.gz" stamp answer
    [[ -f "$AIDE_CONF" && -s "$db" ]] || { echo "AIDE örneği yok; önce kurulum tamamlanmalı." >&2; return 1; }
    satsuma_aide_show_difference | head -n 60
    echo
    if [[ "${SATSUMA_CONFIRM_AIDE:-}" != YES ]]; then
        [[ -t 0 ]] || { echo "Onay için terminalde çalıştırın ya da SATSUMA_CONFIRM_AIDE=YES verin." >&2; return 64; }
        read -r -p "Sistemin şu anki hali yeni AIDE örneği olsun mu? Onay için EVET yazın: " answer
        [[ "$answer" == EVET ]] || { echo "Onaylanmadı; örnek değişmedi."; return 1; }
    fi
    stamp=$(date +%Y%m%d-%H%M%S)
    cp -a -- "$db" "$db.onceki-$stamp" || return 1
    rm -f -- "$new"
    echo "Yeni AIDE örneği alınıyor (birkaç dakika sürebilir)..."
    aide --config "$AIDE_CONF" --init > /var/log/satsuma/aide-init.log 2>&1 || {
        tail -n 25 /var/log/satsuma/aide-init.log >&2; return 1; }
    [[ -s "$new" ]] && mv -f -- "$new" "$db" && chmod 0600 "$db" || return 1
    rm -f -- "$SATSUMA_AIDE_DIR/onay-bekliyor"
    restorecon -R "$SATSUMA_AIDE_DIR" >/dev/null 2>&1 || true
    echo "Yeni AIDE örneği alındı. Önceki örnek kanıt olarak saklandı: $db.onceki-$stamp"
}

# One-command install: the script copies itself to the single install path and
# runs the confirmed --full setup as a boot service (user request 2026-11-11).
# Tek komutla kurulum: betik kendini tek kurulum yoluna kopyalar ve onaylı --full
# kurulumunu açılış servisi olarak çalıştırır (kullanıcı isteği 2026-11-11).
satsuma_install_main_service() {
    [[ $EUID -eq 0 ]] || { echo "Root gerekli" >&2; return 1; }
    if [[ "${SATSUMA_CONFIRM_FULL:-}" != YES ]]; then
        echo "--install-service, her açılışta --full kurulumunu çalıştıran satsuma-mini servisini kurar ve hemen başlatır."
        echo "--full: tarayıcı politikaları, resmi depo paketleri, nftables/Suricata ve servisler değişir; çekirdek modül yükleme yeniden başlatmaya kadar kilitlenir."
        echo "Devam etmek için: sudo env SATSUMA_CONFIRM_FULL=YES /bin/bash -p $0 --install-service"
        return 64
    fi
    local target=/usr/local/bin/satsuma-mini unit=/etc/systemd/system/satsuma-mini.service tmp
    /bin/bash -p -n "$SATSUMA_SELF" || { echo "Betik sözdizimi hatalı; kurulmadı." >&2; return 1; }
    if [[ "$SATSUMA_SELF" != "$target" ]]; then
        tmp=$(mktemp /usr/local/bin/.satsuma.XXXXXXXX) || return 1
        install -o root -g root -m 0750 "$SATSUMA_SELF" "$tmp" || { rm -f -- "$tmp"; return 1; }
        mv -f -- "$tmp" "$target" || { rm -f -- "$tmp"; return 1; }
    fi
    tmp=$(mktemp /etc/systemd/system/.satsuma-mini.XXXXXXXX) || return 1
    cat > "$tmp" <<'SATSUMA_MAIN_UNIT'
[Unit]
Description=Satsuma Mini (Omni-Sentinel V62) kurulum ve ana izleme döngüsü
Wants=network-online.target
After=network-online.target satsuma-firewall.service suricata.service
StartLimitIntervalSec=1h
StartLimitBurst=5

[Service]
Type=simple
Environment=SATSUMA_CONFIRM_FULL=YES
ExecStart=/bin/bash -p /usr/local/bin/satsuma-mini --full
StandardInput=null
StandardOutput=journal
StandardError=journal
Restart=on-failure
RestartSec=60
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
SATSUMA_MAIN_UNIT
    chmod 0644 "$tmp" && mv -f -- "$tmp" "$unit" || { rm -f -- "$tmp"; return 1; }
    if command -v restorecon >/dev/null; then
        restorecon -v "$target" "$unit" || return 1
    fi
    satsuma_install_shortcuts || return 1
    # Drop-ins written by hand during the 2026-11-11 field run are now built in.
    # 2026-11-11 saha çalışmasında elle yazılan ek dosyalar artık betiğin içinde.
    rm -f -- /etc/systemd/system/satsuma-mini.service.d/teshis.conf \
             /etc/systemd/system/satsuma-mini.service.d/tarama-sirasi.conf
    rmdir --ignore-fail-on-non-empty /etc/systemd/system/satsuma-mini.service.d 2>/dev/null
    systemctl daemon-reload || return 1
    systemctl enable satsuma-mini.service || return 1
    systemctl reset-failed satsuma-mini.service 2>/dev/null
    systemctl restart satsuma-mini.service || return 1
    echo "satsuma-mini servisi kuruldu ve başlatıldı; her açılışta otomatik çalışır."
    echo "İlerleme: journalctl -u satsuma-mini -f | Durum: $target --dashboard"
}

satsuma_repair_suricata_permissions() {
    [[ $EUID -eq 0 ]] || { echo "Suricata izin düzeltmesi root gerektirir." >&2; return 1; }
    /usr/bin/python3 -I -S - <<'SATSUMA_SURICATA_PERMISSIONS_PY'
import os, pwd, stat, sys

def repair():
    rootfd=os.open('/etc',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    directory=filefd=None
    try:
        try: directory=os.open('suricata',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=rootfd)
        except FileNotFoundError:
            print('Suricata yapılandırma dizini henüz yok; paket kurulumu beklenecek.')
            return
        st=os.fstat(directory)
        try: account=pwd.getpwnam('suricata')
        except KeyError: account=None
        if st.st_mode & 0o022:
            raise RuntimeError('Suricata dizini grup/diğer yazmasına açık; otomatik sahiplik devri yapılmadı')
        if st.st_uid!=0:
            if account is None or st.st_uid!=account.pw_uid or st.st_gid!=account.pw_gid:
                raise RuntimeError('Beklenmeyen Suricata dizin sahibi: uid=%d gid=%d'%(st.st_uid,st.st_gid))
            os.fchown(directory,0,account.pw_gid)
            os.fchmod(directory,0o750)
            print('/etc/suricata: root:suricata 750 uygulandı.')
        try: filefd=os.open('suricata.yaml',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        except FileNotFoundError:
            raise RuntimeError('suricata.yaml bulunamadı; paket yapılandırması eksik')
        st=os.fstat(filefd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_mode & 0o022:
            raise RuntimeError('Güvensiz YAML dosya türü, hardlink veya yazma izni')
        if st.st_uid!=0:
            if account is None or st.st_uid!=account.pw_uid:
                raise RuntimeError('Beklenmeyen YAML sahibi: uid=%d'%st.st_uid)
            os.fchown(filefd,0,account.pw_gid)
            os.fchmod(filefd,0o640)
            print('/etc/suricata/suricata.yaml: root:suricata 640 uygulandı.')
        print('Suricata yapılandırma sahipliği kontrol edildi; bu bir içerik/zararlı yazılım doğrulaması değildir.')
    finally:
        for fd in (filefd,directory,rootfd):
            if fd is not None: os.close(fd)

try: repair()
except (OSError,RuntimeError) as exc:
    print('Suricata izin kontrolü: '+str(exc),file=sys.stderr)
    sys.exit(1)
SATSUMA_SURICATA_PERMISSIONS_PY
}

satsuma_usage() {
    echo "Kullanim: $0 --file-scan scan clamav --path /home/satsumabilgisayar --apply"
    echo "         $0 --file-scan scheduler [--once]"
    echo "         $0 --file-scan memory-scan"
    echo "         $0 --file-scan browser-audit"
    echo "         $0 --verify-ips (salt okunur)"
    echo "         $0 --network-reset (30 bağlantı ağ kilidini kaldırır)"
    echo "         $0 --tmp-harden | --keyboard-trq"
    echo "         $0 --python-audit (salt okunur; .pth kodunu calistirmaz)"
    echo "         $0 --browser-paths-audit (salt okunur)"
    echo "         $0 --browser-harden (sıkı yerel politikalar)"
    echo "         $0 --dashboard"
    echo "         $0 --dashboard-live (veya parametresiz)"
    echo "         $0 --install-hourly"
    echo "         $0 --install-service  (kendini kurar, her açılışta --full çalıştırır; onay gerekir)"
    echo "         $0 --aide-fark (salt okunur) | --aide-onayla (kurulu sistem; EVET onayı ister)"
    echo "         $0 --full  (yerel sistem/firewall degisikligi; onay gerekir)"
    echo "         $0 --selinux-audit | --selinux-enforce"
    echo "         $0 --memory35-status | --memory35-scan | --memory35-harden | --memory35-preflight"
    echo "         $0 --help | -h"
    echo "         $0 --repair-suricata-permissions"
    cat <<'SATSUMA_HELP_RUN'

Depodan inen dosyanın adı satsuma-omni-sentinel-v62-fedora-hardened.sh.
Dosyanın bulunduğu klasörde tek komut yeterlidir:

sudo env SATSUMA_CONFIRM_FULL=YES /bin/bash -p ./satsuma-omni-sentinel-v62-fedora-hardened.sh --install-service

Betik kendini /usr/local/bin/satsuma-mini olarak kurar ve satsuma-mini servisini
başlatır; servis her açılışta kurulumu doğrulayıp ana döngüyü çalıştırır.
İlerleme: journalctl -u satsuma-mini -f
Kısa komutlar: satsuma-dashboard, satsuma-durum, satsuma-clamav (tara),
satsuma-suricata, satsuma-ram, satsuma-log, satsuma-aide (onayla)

Canlı oturum ve kurulu sistem kendiliğinden ayırt edilir. Canlı oturumda AIDE
farkı kurulumu durdurur. Kurulu sistemde fark alarm olarak bildirilir, korumalar
çalışmaya devam eder; önceki örnek satsuma-aide onayla diyene kadar korunur.

Servis olmadan, tek seferlik elle kurulum isterseniz:
/bin/bash -p -n ./satsuma-omni-sentinel-v62-fedora-hardened.sh
sudo install -o root -g root -m 0750 ./satsuma-omni-sentinel-v62-fedora-hardened.sh /usr/local/bin/satsuma-mini
sudo env SATSUMA_CONFIRM_FULL=YES /bin/bash -p /usr/local/bin/satsuma-mini --full

Onay değişkeni komuttan önce, env ile verilir; komutun sonuna eklenmez.
Tek kurulum yolu /usr/local/bin/satsuma-mini olarak kullanılır.
Suricata paketinin suricata:suricata sahipliği, onaylanmış --full çalışmasında
root sahipliğine alınır; grup okuma erişimi korunur. Symlink, grup/diğer yazması
ve beklenmeyen sahiplikte işlem durur. Güven denetimleri kaldırılmaz.
--full servis/firewall ayarlarını değiştirir; 30 bağlantıda ağ kilitlenebilir ve
çekirdek modülü kilidi yeniden başlatılana kadar sürer.
SELinux enforcing zorunludur; domain_can_mmap_files kapalı tutulur.
SELinux Disabled ise çalışan çekirdekte etkinleştirilemez; kurulum bu durumda durur.
RAM35: 2.2.35 kaynaklı sınırlı süreç belleği taraması; erişim için izin genişletmez.
ptrace_scope=3 korunur: süreç belleği taraması BLOCKED görünür, temiz sayılmaz.
/dev: nosuid,noexec; /dev/shm: nosuid,nodev,noexec. /dev için nodev eklenmez.
SATSUMA_HELP_RUN
}

if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
    satsuma_usage
    exit 0
fi
case "${1:-}" in
    --selinux-audit) satsuma_selinux_guard audit; exit $? ;;
    --selinux-enforce) satsuma_selinux_guard enforce; exit $? ;;
esac
if [[ "${1:-}" == --repair-suricata-permissions ]]; then
    satsuma_repair_suricata_permissions
    exit $?
fi
if [[ $EUID -eq 0 && "${1:-}" == --full && "${SATSUMA_CONFIRM_FULL:-}" == YES ]]; then
    satsuma_repair_suricata_permissions || exit 1
fi

case "${1:-}" in
    --network-watch) satsuma_network_guard watch; exit $? ;;
    --network-reset) satsuma_network_guard reset; exit $? ;;
    --network-enforce-state) satsuma_network_guard enforce-state; exit $? ;;
    --tmp-harden) satsuma_tmp_harden; exit $? ;;
    --keyboard-trq) satsuma_keyboard_trq; exit $? ;;
esac

if [[ "${1:-}" == --python-audit ]]; then
    satsuma_python_audit
    exit $?
fi
if [[ "${1:-}" == --browser-paths-audit ]]; then
    satsuma_browser_paths_audit
    exit $?
fi

if [[ "${1:-}" == --browser-harden ]]; then
    satsuma_browser_harden
    exit $?
fi

if [[ "${1:-}" == --verify-ips ]]; then
    satsuma_verify_ips 0
    exit $?
fi

# Fail closed if privileged output paths have untrusted ancestors or links.
# Run before any install, configuration, log or lock mutation.
if [[ $EUID -eq 0 ]]; then
    /usr/bin/python3 -I -S - <<'SATSUMA_TRUST_CHECK'
import os, stat, sys
from pathlib import Path
paths = [
    "/var/log/satsuma", "/var/lib/satsuma-sentinel", "/run/satsuma",
    "/run/satsuma-file-scan.lock", "/run/satsuma-file-scheduler.lock",
    "/etc/satsuma", "/etc/clamav", "/etc/systemd/system",
    "/etc/sysctl.d/90-satsuma-security.conf",
    "/etc/nftables.conf", "/etc/suricata", "/etc/default/suricata",
    "/etc/audit/rules.d/70-satsuma-security.rules",
    "/etc/clamd.d/scan.conf", "/etc/freshclam.conf",
    "/etc/default/keyboard",
    "/etc/systemd/system/satsuma-network-guard.service",
    "/etc/systemd/system/satsuma-tmp-hardening.service",
    "/etc/aide", "/var/lib/aide", "/usr/local/bin",
    "/etc/systemd/system/suricata.service.d/satsuma-nfqueue.conf",
    "/etc/systemd/system/satsuma-firewall.service",
    "/etc/systemd/system/satsuma-file-scan.service",
    "/etc/selinux/config", "/etc/sysctl.d/90-satsuma-memory.conf",
    "/etc/clamd.d/satsuma-ram.conf", "/etc/clamav/satsuma-ram.conf",
    "/etc/systemd/system/satsuma-ram-clamd.service",
    "/etc/systemd/system/satsuma-selinux-guard.service",
    "/etc/systemd/system/satsuma-memory-hardening.service",
    "/etc/systemd/system/satsuma-memory-watch.service",
]
paths += [str(p) for p in Path("/var/log").glob("satsuma*")]
# Recursively inspect private application state, but never follow symlinks.
for root in ("/var/log/satsuma", "/var/lib/satsuma-sentinel", "/run/satsuma"):
    if os.path.isdir(root) and not os.path.islink(root):
        for parent, dirs, files in os.walk(root, followlinks=False):
            paths.extend(os.path.join(parent, n) for n in dirs + files)
try:
    for path in paths:
        current = Path("/")
        for part in Path(path).parts[1:]:
            current /= part
            try:
                st = current.lstat()
            except FileNotFoundError:
                break
            if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise RuntimeError("Untrusted privileged path: " + str(current))
            if stat.S_ISREG(st.st_mode) and st.st_nlink != 1:
                raise RuntimeError("Hard-linked privileged file: " + str(current))
except (OSError, RuntimeError) as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(1)
SATSUMA_TRUST_CHECK
    [[ $? -eq 0 ]] || exit 1
fi

SATSUMA_SELF="$(readlink -f -- "${BASH_SOURCE[0]}")"
case "${1:-}" in
    --memory35-status) satsuma_ram35 status; exit $? ;;
    --memory35-scan) satsuma_ram35 once; exit $? ;;
    --memory35-preflight) satsuma_ram35 preflight; exit $? ;;
    --memory35-watch) satsuma_ram35 watch; exit $? ;;
    --memory35-harden) satsuma_ram35 harden; exit $? ;;
esac

if [[ "${1:-}" == "--clamd-config" ]]; then
    satsuma_clamd_transaction
    exit $?
elif [[ "${1:-}" == "--scanner-repair" ]]; then
    satsuma_file_install_hourly
    exit $?
elif [[ "${1:-}" == "--scanner-install" ]]; then
    satsuma_scanner_packages && satsuma_scanners_configure && satsuma_file_install_hourly
    exit $?
elif [[ "${1:-}" == "--scanner-update" ]]; then
    satsuma_scanner_updates
    exit $?
elif [[ "${1:-}" == "--file-scan" ]]; then
    shift
    satsuma_file_guard "$@"
    exit $?
elif [[ "${1:-}" == "--aide-fark" ]]; then
    satsuma_aide_show_difference
    exit $?
elif [[ "${1:-}" == "--aide-onayla" ]]; then
    satsuma_aide_approve
    exit $?
elif [[ "${1:-}" == "--install-service" ]]; then
    satsuma_install_main_service
    exit $?
elif [[ "${1:-}" == "--install-hourly" ]]; then
    satsuma_file_install_hourly
    exit $?
elif [[ "${1:-}" == "--dashboard" ]]; then
    satsuma_file_dashboard
    exit $?
elif [[ "${1:-}" == "--dashboard-live" ]]; then
    satsuma_file_guard screen
    exit $?
fi

# Full setup installs signed distro packages and configures local protection.
# No arguments opens the read-only live dashboard.
if [[ $# -eq 0 ]]; then
    satsuma_file_guard screen
    exit $?
fi
if [[ "${1:-}" != "--full" ]]; then
    satsuma_usage
    exit 0
fi

shift
if [[ "${SATSUMA_CONFIRM_FULL:-}" != "YES" ]]; then
    echo "--full; HTTP/eklentileri engelleyen tarayıcı politikaları uygular; resmi depo paketlerini ve imzalari indirir; nftables/Suricata, tarayici politikalari ve servisleri degistirir; sonunda kernel modul yukleme/kaldirmayi yeniden baslatmaya kadar kilitler."
    echo "Devam etmek icin ayri bir adimda SATSUMA_CONFIRM_FULL=YES verip yeniden calistirin."
    exit 64
fi
# ----- ORIGINAL MAIN SCRIPT / INTEGRATED FILE SCANNING -----
#!/bin/bash
# ==============================================================================
# SATSUMA OMNI-SENTINEL V62 | V61 tabanı + güvenlik sertleştirmeleri
# ==============================================================================
#
# ============================================================================

set -uo pipefail
[[ $EUID -ne 0 ]] && { echo "[!] HATA: Root gerekli!"; exit 1; }

# ------------------------------------------------------------------------------
# V62: Durum/kilit/sonuç dosyaları artık herkesin yazabildiği /var/tmp yerine
# yalnızca root'a ait 0700 dizinlerde tutulur. Eski sürümde düşük yetkili bir
# kullanıcı bu dosyaları önceden oluşturup (offset/kilit/sonuç/MAC) tarama
# mantığını bozabilirdi (ör. AIDE kilidiyle taramayı kapatmak, sahte alarm).
# ------------------------------------------------------------------------------
SATSUMA_STATE_DIR="/var/lib/satsuma-sentinel/state"   # kalıcı (offset, MAC baseline)
SATSUMA_RUN_DIR="/run/satsuma"                        # geçici (kilit, sonuç)

satsuma_secure_dir() {
    local d="$1" owner
    if [[ -L "$d" ]]; then
        echo "[!] HATA: $d bir symlink - güvenli değil, çıkılıyor." >&2
        return 1
    fi
    ( umask 077; mkdir -p -- "$d" ) || return 1
    owner=$(stat -c '%u' -- "$d" 2>/dev/null) || return 1
    if [[ "$owner" != "0" ]]; then
        echo "[!] HATA: $d root'a ait değil (uid=$owner) - güvenli değil, çıkılıyor." >&2
        return 1
    fi
    chmod 700 -- "$d" || return 1
}
satsuma_secure_dir "$SATSUMA_STATE_DIR" || exit 1
satsuma_secure_dir "$SATSUMA_RUN_DIR" || exit 1

# Eski sürümün /var/tmp ve /tmp'deki dosyaları saldırgan tarafından önceden
# yerleştirilmiş olabilir: kullanma, kanıt olarak güvenli dizine taşı.
satsuma_quarantine_legacy_state() {
    local f evdir="" owner moved=0
    for f in /var/tmp/satsuma_* /tmp/.satsuma_suricata_test; do
        [[ -e "$f" || -L "$f" ]] || continue
        if [[ -z "$evdir" ]]; then
            evdir="$SATSUMA_STATE_DIR/legacy-evidence-$(date +%Y%m%d-%H%M%S)"
            ( umask 077; mkdir -p -- "$evdir" ) || return 0
        fi
        owner=$(stat -c '%U(%u)' -- "$f" 2>/dev/null || echo "?")
        echo "[!] Eski durum dosyası bulundu: $f (sahip: $owner) -> $evdir" >&2
        mv -- "$f" "$evdir/" 2>/dev/null || true
        moved=$((moved + 1))
    done
    [[ "$moved" -gt 0 ]] && echo "[!] $moved eski dosya incelenmek üzere taşındı. Sahibi root olmayanlar şüphelidir." >&2
    return 0
}
satsuma_quarantine_legacy_state

# Bayat kilit (çökmüş tarama) güvenlik kontrolünü sonsuza dek kapatmasın.
satsuma_lock_active() {
    local lock="$1"
    [[ -e "$lock" ]] || return 1
    if [[ -n "$(find "$lock" -maxdepth 0 -mmin +120 2>/dev/null)" ]]; then
        rm -f -- "$lock" 2>/dev/null || true
        return 1
    fi
    return 0
}

# ==============================================================================
# 1. RENKLER
# ==============================================================================
C_RESET="\033[0m"
C_BOLD="\033[1m"
C_RED="\033[1;31m"
C_GREEN="\033[1;32m"
C_YELLOW="\033[1;33m"
C_BLUE="\033[1;34m"
C_CYAN="\033[1;36m"
C_MAGENTA="\033[1;35m"
C_WHITE="\033[1;37m"
C_DIM="\033[2m"
C_BG_RED="\033[41m"
C_BG_GREEN="\033[42m"
C_BG_YELLOW="\033[43m"
C_BG_BLUE="\033[44m"

# ==============================================================================
# 2. YAPILANDIRMA
# ==============================================================================
# V54: Hardcoded API key kaynak kodundan KALDIRILDI. Script artık key'i
# SADECE $OTX_KEY_FILE dosyasından okuyor. Bu dosya yoksa/boşsa OTX katmanı
# otomatik devre dışı kalır (aşağıda ENABLE_OTX=false). Key'i ayarlamak için:
#   echo "GERÇEK-KEYIN" > /etc/satsuma/otx.key && chmod 600 /etc/satsuma/otx.key
OTX_API_KEY=""
OTX_KEY_FILE="/etc/satsuma/otx.key"

if [[ -f "$OTX_KEY_FILE" && ! -L "$OTX_KEY_FILE" ]]; then
    # V62: dosya root'a ait değilse kullanma (değiştirilmiş olabilir); izinleri okumadan ÖNCE sıkılaştır.
    if [[ "$(stat -c '%u' -- "$OTX_KEY_FILE" 2>/dev/null)" == "0" ]]; then
        chmod 600 -- "$OTX_KEY_FILE" 2>/dev/null || true
        OTX_API_KEY=$(head -c 256 -- "$OTX_KEY_FILE" 2>/dev/null | tr -d '\n\r')
        # curl config'ine güvenle yazılabilmesi için yalnızca beklenen karakterler
        [[ "$OTX_API_KEY" =~ ^[A-Za-z0-9_-]+$ ]] || OTX_API_KEY=""
    else
        OTX_API_KEY=""
    fi
fi

if [[ -z "$OTX_API_KEY" ]]; then
    ENABLE_OTX=false
else
    ENABLE_OTX=true
fi

WAN_INTERFACE=""
MAX_CONNECTIONS=30   # V62.2: 5 çok düşüktü; tarayıcılar tek IP'ye 6-10+ bağlantı açar (claude.ai bloklanmıştı)
SCAN_INTERVAL=3
INITIAL_SUBNET_MASK=32
MAX_SUBNET_MASK=24
ESCALATION_THRESHOLD=8
ESCALATION_COOLDOWN=3
# V54: KRİTİK - subnet eskalasyon mekanizması VARSAYILAN OLARAK KAPATILDI.
# Bu mekanizma, tek bir IP hiç bloklanmasa bile "aynı subnet'e kısa sürede
# ESCALATION_THRESHOLD kadar farklı bağlantı" görüldüğünde o subnet'i /32'den
# kademeli olarak /24'e kadar genişletiyordu. Chrome gibi tarayıcılar
# Google/Cloudflare/Fastly gibi CDN'lerin onlarca farklı IP'sine paralel
# bağlandığı için bu eşik çok kolay aşılıyor ve gece boyunca /16-/24 gibi
# devasa aralıkların birikmesine yol açıyordu - önceki oturumda canlı
# nftables çıktısında görülen 45.83.0.0/16, 192.178.0.0/16 gibi geniş
# bloklar buradan geliyordu. Bu, "strict per-IP /32, escalation yok" kararına
# aykırıydı. true yaparsan eski davranış geri döner (isteğe bağlı, önerilmez).
# V55: Değişken yorumla ÇELİŞECEK şekilde hâlâ "true" idi - düzeltildi.
ENABLE_SUBNET_ESCALATION=false

ENABLE_DNSLESS=true
DNSLESS_BLOCK_MODE=false   # V62.3: PTR'siz IP (Cloudflare, claude.ai, bulut/CDN) varsayılan olarak yalnızca loglanır, bloklanmaz
DNSLESS_PERSISTENCE_THRESHOLD=3   # V52.9: IP kaç ARDIŞIK taramada PTR'siz görülürse blok tetiklensin
ENABLE_ROOTKIT_CHECK=true
ENABLE_CLAMAV=true
# V58: clamd (clamav-daemon) kendi ayrı systemd birimi olduğu için
# satsuma-file-scan.service'in MemoryMax'ına dahil değil - configure_clamd_memory_limit()
# bu iki değeri clamav-daemon.service için AYRI bir drop-in olarak uygular.
CLAMD_MEMORY_HIGH="${CLAMD_MEMORY_HIGH:-2G}"
CLAMD_MEMORY_MAX="${CLAMD_MEMORY_MAX:-3G}"
ENABLE_SURICATA=true
ENABLE_AI_ANOMALY=true
KILL_CONNECTIONS=true

SURICATA_LOG="/var/log/suricata/eve.json"
# V52.9: Suricata otomatik yeniden yapılandırma ve IPS (inline engelleme) modu.
# "Suricata hiç tepki vermiyor" sorununun en olası sebebi: suricata.yaml'daki
# dinlenen arayüz, ağ topolojisi değiştiğinde (yeni NIC, VM/bridge geçişi vb.)
# ARTIK GEÇERSİZ - Suricata var olmayan/trafik görmeyen bir arayüzü dinliyor
# ve hiç alert üretmiyor. Kurulumda WAN_INTERFACE'e göre otomatik düzeltilir.
ENABLE_SURICATA_AUTOCONFIG=true
SURICATA_YAML="/etc/suricata/suricata.yaml"
SURICATA_DEFAULT_FILE="/etc/default/suricata"   # Debian/Ubuntu paketinde bu dosya interface/mod seçer

# true yapılırsa Suricata pasif izleme (af-packet/IDS) yerine NFQUEUE
# tabanlı INLINE IPS moduna geçer - yani sadece alert vermekle kalmaz,
# kötü paketi anında DÜŞÜRÜR. Bunun için trafiğin ,nftables üzerinden
# Suricata'nın kuyruğuna (queue) yönlendirilmesi gerekir, bu da otomatik
# yapılır.
ENABLE_SURICATA_IPS=true
SURICATA_NFQUEUE_NUM=0
SURICATA_STATE_FILE="$SATSUMA_STATE_DIR/suricata_offset"

OTX_THRESHOLD=11
OTX_CACHE_SIZE=500
MAX_OTX_QUERIES_PER_SCAN=5
OTX_TIMEOUT=5


LOG_FILE="/var/log/satsuma_ai.log"
AUDIT_LOG="/var/log/satsuma_audit.json"
ANOMALY_LOG="/var/log/satsuma_anomaly.log"
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
# PROTOKOL ANOMALİ İZLEME (Zeek yerine - V54)
# ------------------------------------------------------------------------------
# V54: Zeek, Debian 13 (trixie) için resmi paket sunmuyor - kurulum
# başarısız oluyordu. Zeek'in burada üstlendiği rolü (protokol seviyesinde
# şüpheli/anormal davranışları yakalamak) zaten çalışan Suricata devralıyor.
# Suricata'nın eve.json çıktısı, alert dışında bir de "anomaly" event tipi
# üretebiliyor (decoder/stream/protokol anomalileri - Zeek'in notice.log'una
# kavramsal olarak çok yakın). Yeni bir araç kurup bakımını üstlenmek yerine
# zaten güvenilen, test edilmiş Suricata altyapısını genişletiyoruz - ek
# bağımlılık, ek log rotasyonu, ek uyumluluk riski yok.
ENABLE_PROTO_ANOMALY=true
ANOMALY_OFFSET_FILE="$SATSUMA_STATE_DIR/anomaly_offset"
ANOMALY_MAX_ALERTS=20
declare -a PROTO_ANOMALY_ALERTS=()
PROTO_ANOMALY_COUNT=0
PROTO_ANOMALY_LOG="/var/log/satsuma_proto_anomaly.log"

# ------------------------------------------------------------------------------
# ZENGİNLEŞTİRİLMİŞ BİLGİ (Dashboard / Loglar)
# ------------------------------------------------------------------------------
# Her aracın son çalışma zamanı
LAST_PROTO_ANOMALY_SCAN=0
# ==============================================================================
# 2b. VM KORUMASI VE MEŞRU UZAK ERİŞİM YAZILIMI İSTİSNASI (V52.9)
# ==============================================================================
# VM_SUBNET: Bu aralıktaki hiçbir IP, hiçbir sebeple (Suricata alert dahil)
# bloklanmaz veya bağlantısı kesilmez. Sanal makineye tamamen dokunulmaz.
VM_SUBNET=""

# true ise: LEGIT_REMOTE_SOFTWARE listesindeki bir prosese ait olduğu tespit
# edilen bağlantılar/IP'ler, Suricata "tehdit" bulsa bile ASLA bloklanmaz
# veya kill edilmez. Kullanıcı kendi isteğiyle bu yazılımı kullanıyor.
PROTECT_LEGIT_REMOTE=true

# V52.9: Bu dosya varken TÜM blok/kill işlemleri durur (izleme devam eder).
# İnceleme modu: touch /etc/satsuma/pause  |  Bitince: rm /etc/satsuma/pause
PAUSE_FILE="/etc/satsuma/pause"

# ==============================================================================
# 2c. EK GÜVENLİK KATMANLARI (V52.9)
# ==============================================================================
# Suricata sadece AĞ trafiğini görür. Dosya bütünlüğü, kernel denetimi ve
# host-seviyesi rootkit taraması için bu katmanlar eklendi. Hepsi arkaplanda
# çalışır (&), ana döngüyü bloklamaz; sonuçlar dashboard'da ve log'larda
# görünür.

ENABLE_AIDE=true                  # Dosya bütünlük izleme (kripto virüs / değiştirilen binary tespiti)
AIDE_CHECK_INTERVAL=200           # Her N taramada bir kontrol (200 * 3sn ≈ 10 dakika)
# V55.4: Suricata canlılık/self-heal kontrolü - servis düşerse stop/start
# ile kendini onarmayı dener, başaramazsa alarm üretir.
SURICATA_HEALTH_CHECK_INTERVAL=200   # 200 * 3sn ≈ 10 dakika
LAST_SURICATA_HEALTH_OK=0
AIDE_LOG="/var/log/satsuma_aide.log"
# Live session (user decision 2026-11-10): AIDE watches only /etc and the
# program directories, with Satsuma's own profile and database; the system
# /etc/aide.conf is never edited. Canlı oturum: AIDE yalnızca /etc ve program
# dizinlerini, Satsuma'nın kendi profili ve veritabanıyla izler.
AIDE_DIR="/var/lib/satsuma-sentinel/aide"
AIDE_CONF="$AIDE_DIR/aide-live.conf"
AIDE_DB="$AIDE_DIR/aide.db.gz"
AIDE_DB_NEW="$AIDE_DIR/aide.db.new.gz"
AIDE_WATCH=(/etc /usr/bin /usr/sbin /usr/libexec /usr/local /usr/lib/systemd)

ENABLE_RKHUNTER=true             # rkhunter + chkrootkit ile periyodik host rootkit taraması
RKHUNTER_CHECK_INTERVAL=120      # ≈1 saat (1200 * 3sn = 3600sn)
RKHUNTER_LOG="/var/log/satsuma_rkhunter.log"

ENABLE_AUDITD=true                # Kernel seviyesi exec/dosya denetimi (auditd)
AUDITD_CHECK_INTERVAL=20          # Her N taramada bir yeni audit olaylarını tara (≈1 dakika)
AUDITD_STATE_FILE="$SATSUMA_STATE_DIR/audit_offset"
AUDITD_ALERT_LOG="/var/log/satsuma_auditd_alerts.log"
# V54: /home için tek tek yazma olayı değil, tek bir tarama döngüsünde
# ANİ PATLAMA (burst) aranıyor - normal masaüstü kullanımı (tarayıcı
# profil/cache yazmaları vb.) saniyede birkaç yazımla dağınık gerçekleşir;
# gerçek ransomware/kripto-virüs ise saniyeler içinde YÜZLERCE dosyayı
# art arda değiştirir. Bu eşiğin altındaki /home yazmaları sessizce
# loglanır ama "olay" sayılmaz; üstündeki gerçek bir patlama sayılır.
# V55.4: Bilinen masaüstü uygulamaları artık ayrıca hariç tutuluyor (bkz.
# check_audit_events), bu yüzden 300 çoğu durumda hâlâ makul; yine de
# listede olmayan meşru bir uygulama için biraz pay bırakmak amacıyla
# 500'e çıkarıldı.
HOME_WRITE_BURST_THRESHOLD=500

declare -a AUDITD_RULES_APPLIED=()

# V52.9: TOPLU DOSYA ŞİFRELEME (RANSOMWARE) ANLIK YAKALAMA
# Tek bir AIDE kontrolünde bu sayıdan FAZLA dosya değişmişse, bu tekil
# değişiklik değil, aktif bir şifreleme sürecinin imzasıdır. Skor anında
# 100'e sabitlenir ve (varsa) dış bildirim gönderilir.
RANSOMWARE_BURST_THRESHOLD=15
RANSOMWARE_BURST_DETECTED=false

# V52.9: Opsiyonel dış bildirim. Sistem şifrelenirken lokal ekranı
# görme şansın olmayabilir - bu yüzden telefonuna/Discord'a/ntfy.sh'e
# anlık bildirim atmak hayat kurtarır. Boş bırakılırsa devre dışı kalır.
# Örnekler:
# Webhook support removed.

# Remote webhook removed.

# ==============================================================================
# 2d. MITM / DNS ZEHİRLENMESİ TESPİTİ (V52.9)
# ==============================================================================
ENABLE_ARP_WATCH=true             # Gateway MAC adresi değişimini izle (ARP spoofing)
ARP_CHECK_INTERVAL=10             # Her N taramada bir (≈30sn)
GATEWAY_MAC_FILE="$SATSUMA_STATE_DIR/gateway_mac"
ARP_MISMATCH_LOG="/var/log/satsuma_arp_alerts.log"

ENABLE_DNS_CONSISTENCY=true       # Sistem DNS'i ile güvenilir dış resolver'ı karşılaştır
DNS_CHECK_INTERVAL=20             # Her N taramada bir (≈1dk)
TRUSTED_RESOLVERS=("1.1.1.1" "9.9.9.9")
DNS_CANARY_DOMAINS=("dl.fedoraproject.org" "github.com" "cloudflare.com")
DNS_MISMATCH_LOG="/var/log/satsuma_dns_alerts.log"
DNS_MISMATCH_COUNT=0
ARP_MISMATCH_COUNT=0

ENABLE_RESOLV_LOCK=false         # /etc/resolv.conf ve /etc/hosts'u chattr +i ile kilitle

# V56: BELLEK BUDAMA - ana izleme döngüsündeki IP/subnet bazlı associative
# array'ler (OTX_CACHE, DNS_CACHE, PROTECTED_IP_CACHE,
# ANOMALY_SCORES, BLOCKED_IP_CACHE, BLOCKED_SUBNET_CACHE,
# SUBNET_ESCALATION_LEVEL/COOLDOWN) hiç budanmıyordu. Gerçek engelleme
# nftables set'inde kalıcı olduğundan bu dizileri temizlemek güvenliği
# bozmaz - sadece önbellek sıfırlanır, sonraki bağlantıda ucuz bir
# yeniden kontrol yapılır.
CACHE_PRUNE_INTERVAL=2400        # Her N taramada bir buda (~2 saat, SCAN_INTERVAL=3sn ile)
MAX_CACHE_ENTRIES=3000           # Herhangi bir önbellek bu boyutu aşarsa süre beklemeden erken buda

# ==============================================================================
# 3. WHITELIST VE KARA LİSTE
# ==============================================================================
LEGIT_REMOTE_SOFTWARE=(
    # V55: Bu dizi BOŞTU - yani hiçbir uzaktan erişim yazılımı "meşru"
    # olarak tanınmıyordu. Zenarmor kaldırıldığı ve IPS artık input/output
    # trafiğini gerçekten incelediği için (bkz. configure_suricata),
    # kendi kullandığınız uzaktan destek araçları burada olmazsa Suricata
    # bir alarm ürettiğinde is_legit_remote_process() hiçbir zaman muafiyet
    # vermez ve IP'niz/oturumunuz /32 olarak bloklanabilir.
    "anydesk"
    "rustdesk"
)

ROOTKIT_PROCESSES=(
    "nc" "netcat" "ncat" "socat"
    "meterpreter" "beacon" "cobaltstrike"
    "mimikatz" "procdump" "rootkit" "backdoor"
    "webshell" "reverse" "bind"
    "ettercap" "arpspoof" "dsniff"
    "hydra" "john" "sqlmap" "nikto"
)

# V52.9: "nc", "bind", "reverse", "john" gibi çok kısa/genel kelimeler
# substring aramasında masum prosesleri de yakalıyordu (ör. "bind9",
# "async", "reverse-proxy" gibi meşru isimlerin içinde geçiyorlar).
# Bu isimler artık SADECE TAM EŞLEŞME ile kontrol ediliyor.
# Uzun ve kendine has isimler (meterpreter, cobaltstrike, mimikatz, vb.)
# hâlâ substring ile aranıyor çünkü bunların yanlışlıkla başka bir
# proses adının içinde geçme ihtimali pratikte yok denecek kadar az.
ROOTKIT_EXACT_ONLY=(
    "nc" "bind" "reverse" "john"
)

APP_WHITELIST=(
    "systemd" "kernel" "init" "kthreadd" 
    "openvpn" "wireguard" "mullvad" "wg"
    "systemd-resolve" "NetworkManager"
    "gnome-shell" "Xorg" "wayland"
    "curl" "wget" "dnf" "yum" "apt"
    "nft" "ss" "conntrack" "jq"
    "clamav" "freshclam" "clamscan" "clamdscan" "clamd"
    "suricata" "snort" "nftables"
    "anydesk" "rustdesk"
    # V55: "zenarmor-agent"/"eastpect"/"eastpect.service" kaldırıldı -
    # o uygulama artık kullanılmıyor, kalan girişler zaten hiç eşleşmeyen
    # ölü ağırlıktı.
)


RISKY_PROCESS_NAMES=(
    "nc" "netcat" "ncat" "socat"
    "meterpreter" "beacon" "cobaltstrike"
    "mimikatz" "procdump"
    "rootkit" "backdoor"
    "webshell" "reverse" "bind"
    "hydra" "john" "sqlmap" "nikto"
)

WHITELIST_IPS=(
   "208.67.222.222" "208.67.220.220" "151.101.2.132" 
   "151.101.66.132" "151.101.130.132" "151.101.194.132"
)

DNSLESS_WHITELIST=(
   "208.67.222.222" "208.67.220.220"

)

# V54: Önceden boş bırakılmıştı (sadece yorum satırında "buraya eklenir"
# yazıyordu, gerçek veri hiç girilmemişti). 29-30 Ağustos gece logunun
# analizinde alarm üreten 76 benzersiz IP'nin 72'sinin (%94) şu 4
# sağlayıcıya ait olduğu doğrulandı: Google, Cloudflare, Facebook/Meta,
# Amazon CloudFront. Bu önekler hem DNS-less testinde hem de Suricata
# Priority 3+ eşik mantığında (aşağıda is_trusted_cdn_ip()) kullanılıyor -
# bilinen CDN trafiği ne kadar uzun sürerse sürsün eşik sayacına hiç
# girmez, sadece gerçekten sınıflandırılamayan IP'ler sayaca tabi kalır.
# Tam/kapsayıcı bir liste değildir - CDN'ler zamanla yeni aralıklar
# ekler; yeni bir false-positive kaynağı fark edersen buraya ekle.
DNSLESS_TRUSTED_PREFIXES=(

 

)

# ==============================================================================
# 4. GLOBAL DEĞİŞKENLER
# ==============================================================================
declare -A OTX_CACHE=()
declare -A BLOCKED_IP_CACHE=()
declare -A DNSLESS_LOGGED=()
declare -A BLOCKED_SUBNET_CACHE=()
declare -A SUBNET_CONNECTIONS=()
declare -A SUBNET_PIDS=()
declare -A SUBNET_SAMPLE_IPS=()
declare -A SUBNET_ALL_IPS=()
declare -A SUBNET_TRUSTED=()   # V52.9: APP_WHITELIST eşleşen bağlantılar - dashboard'da GÖRÜNÜR ama tehdit değerlendirmesine girmez
declare -A DNS_CACHE=()
declare -A ANOMALY_SCORES=()
declare -A SUBNET_ESCALATION_LEVEL=()
declare -A SUBNET_ESCALATION_COOLDOWN=()
declare -A PROTECTED_IP_CACHE=()   # V52.9: meşru uzak erişim yazılımına (AnyDesk/RustDesk/vb) ait olduğu doğrulanan IP'ler
declare -A DNSLESS_PERSISTENCE_CACHE=()   # V52.9: IP -> kaç ardışık taramada PTR'siz görüldü

OTX_CACHE_COUNT=0
TOTAL_BLOCKS=0
SURICATA_BLOCKS=0
CLAMAV_BLOCKS=0
OTX_BLOCKS=0
DNSLESS_BLOCKS=0
ROOTKIT_DETECTIONS=0
ANOMALY_DETECTIONS=0
AIDE_ALERTS=0
RKHUNTER_ALERTS=0
AUDITD_EVENTS=0
LAST_AIDE_CHECK=0
LAST_RKHUNTER_CHECK=0
SCAN_COUNT=0
TOTAL_CONNECTIONS=0
UNIQUE_SUBNETS=0
START_TIME=$(date +%s)
TOTAL_CONNECTIONS_KILLED=0
SURICATA_INITIAL_SCAN_DONE=true

declare -a ACTIVITY_LOGS=()
LAST_SURICATA_SCAN_INFO=""
MAX_LOG_HISTORY=30
declare -a SURICATA_ALERTS=()
MAX_SURICATA_ALERTS=50

# ==============================================================================
# 5. TEMEL FONKSİYONLAR
# ==============================================================================
prune_ip_caches() {
    local total=$(( ${#OTX_CACHE[@]} + ${#DNS_CACHE[@]} \
                   + ${#PROTECTED_IP_CACHE[@]} + ${#ANOMALY_SCORES[@]} \
                   + ${#BLOCKED_IP_CACHE[@]} + ${#BLOCKED_SUBNET_CACHE[@]} \
                   + ${#SUBNET_ESCALATION_LEVEL[@]} + ${#SUBNET_ESCALATION_COOLDOWN[@]} ))

    OTX_CACHE=()
    DNS_CACHE=()
    ANOMALY_SCORES=()
    PROTECTED_IP_CACHE=()
    BLOCKED_IP_CACHE=()
    BLOCKED_SUBNET_CACHE=()
    SUBNET_ESCALATION_LEVEL=()
    SUBNET_ESCALATION_COOLDOWN=()

    add_activity_log "${C_YELLOW}[BAKIM]${C_RESET} IP/subnet önbellekleri budandı (önceki toplam: $total girdi)"
}

cache_needs_early_prune() {
    local size
    for size in "${#OTX_CACHE[@]}" "${#DNS_CACHE[@]}" \
                "${#PROTECTED_IP_CACHE[@]}" "${#ANOMALY_SCORES[@]}" \
                "${#BLOCKED_IP_CACHE[@]}" "${#BLOCKED_SUBNET_CACHE[@]}" \
                "${#SUBNET_ESCALATION_LEVEL[@]}" "${#SUBNET_ESCALATION_COOLDOWN[@]}"; do
        [[ $size -ge $MAX_CACHE_ENTRIES ]] && return 0
    done
    return 1
}

add_activity_log() {
    local msg="$1"
    local timestamp
    timestamp=$(date +'%H:%M:%S')
    ACTIVITY_LOGS=("$timestamp | $msg" "${ACTIVITY_LOGS[@]}")
    if [ ${#ACTIVITY_LOGS[@]} -gt $MAX_LOG_HISTORY ]; then
        ACTIVITY_LOGS=("${ACTIVITY_LOGS[@]:0:$MAX_LOG_HISTORY}")
    fi
    echo "$(date -Iseconds) | $msg" >> "$LOG_FILE" 2>/dev/null || true
}

log_event() {
    local level="$1"
    local message="$2"
    echo "{\"timestamp\":\"$(date -Iseconds)\",\"level\":\"$level\",\"message\":\"$message\"}" >> "$AUDIT_LOG" 2>/dev/null || true
}

log_block() {
    local ip="$1"
    local reason="$2"
    local process="$3"
    log_event "BLOCK" "IP:$ip, REASON:$reason, PROCESS:$process"
    add_activity_log "${C_RED}[BLOK]${C_RESET} $ip - $reason"
}

validate_ip() {
    local ip="$1"
    # V62: baştaki sıfır ("08") bazı ayrıştırıcılarda sekizlik sayılır -> tamamen reddedilir
    [[ ! "$ip" =~ ^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$ ]] && return 1
    local o1 o2 o3 o4
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    # V62: "08"/"09" gibi sekizlik hatası aritmetik hata verip geçerli sayılıyordu; 10# ile ondalık zorlanır.
    (( 10#$o1 > 255 || 10#$o2 > 255 || 10#$o3 > 255 || 10#$o4 > 255 )) && return 1
    return 0
}

is_local_ip() {
    local ip="$1"
    [[ "$ip" =~ ^127\. ]] && return 0
    [[ "$ip" =~ ^10\. ]] && return 0
    [[ "$ip" =~ ^192\.168\. ]] && return 0
    [[ "$ip" =~ ^172\.1[6-9]\. ]] && return 0
    [[ "$ip" =~ ^172\.2[0-9]\. ]] && return 0
    [[ "$ip" =~ ^172\.3[0-1]\. ]] && return 0
    [[ "$ip" =~ ^0\. ]] && return 0
    return 1
}

# V52.9: Bu IP, korunan VM'in sanal ağına mı ait?
# Evetse hiçbir blok/kill mekanizması bu IP'ye dokunmamalı.
is_vm_ip() {
    local ip="$1"
    [[ -z "$VM_SUBNET" ]] && return 1
    validate_ip "$ip" || return 1
    ip_in_cidr "$ip" "$VM_SUBNET" && return 0
    return 1
}

# V60: Process names are not identities. Any exemption based on a process name
# must also have a live PID whose executable resolves to a non-transient path.
# Return 0 => suspicious/unverifiable, return 1 => path looks stable.
is_process_path_suspicious() {
    local pid="$1"
    [[ -z "$pid" ]] || [[ ! "$pid" =~ ^[0-9]+$ ]] && return 0
    [[ "$pid" -le 1 ]] && return 1

    local exe_link exe_path
    exe_link=$(readlink "/proc/${pid}/exe" 2>/dev/null) || return 0
    [[ -z "$exe_link" ]] && return 0
    [[ "$exe_link" == *" (deleted)" ]] && return 0

    exe_path=$(readlink -f "/proc/${pid}/exe" 2>/dev/null) || return 0
    [[ -z "$exe_path" ]] && return 0
    [[ "$exe_path" =~ ^/tmp/ ]] && return 0
    [[ "$exe_path" =~ ^/dev/shm/ ]] && return 0
    [[ "$exe_path" =~ ^/var/tmp/ ]] && return 0
    [[ "$exe_path" =~ ^/run/user/ ]] && return 0
    [[ "$exe_path" =~ ^/home/[^/]+/(Downloads|\.cache)/ ]] && return 0

    # Exemptions are intended for installed software, not arbitrary executables
    # launched from writable user locations.
    case "$exe_path" in
        /usr/bin/*|/usr/sbin/*|/usr/local/bin/*|/usr/local/bin/*|/bin/*|/sbin/*|/opt/*)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

# V62: Bir sürecin çalıştırılabilir dosyası güvenilir bir kurulum yolunda mı, root'a
# ait mi ve grup/diğer tarafından yazılamaz mı? (/proc/PID/comm sahte olabilir,
# bu yüzden isim tek başına hiçbir muafiyet sağlamaz.)
is_trusted_exe_path() {
    local pid="${1:-}" link exe owner mode
    [[ "$pid" =~ ^[0-9]+$ ]] && [[ "$pid" -gt 0 ]] || return 1
    link=$(readlink "/proc/${pid}/exe" 2>/dev/null) || return 1
    [[ -n "$link" && "$link" != *" (deleted)" ]] || return 1
    exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null) || return 1
    case "$exe" in
        /usr/bin/*|/usr/sbin/*|/usr/local/bin/*|/usr/local/bin/*|/bin/*|/sbin/*|\
        /usr/lib/*|/usr/lib64/*|/usr/libexec/*|/lib/*|/lib64/*|/opt/*|/snap/*|/var/lib/flatpak/*) ;;
        *) return 1 ;;
    esac
    read -r owner mode < <(stat -c '%u %a' -- "$exe" 2>/dev/null) || return 1
    [[ "$owner" == "0" ]] || return 1
    (( (8#$mode & 8#022) == 0 )) || return 1
    return 0
}

# V62: APP_WHITELIST artık alt dize (*app*) ile değil, tam isim (veya >=5 karakterlik
# adlarda önek) ile eşleşir VE çalıştırılabilir dosya yolu doğrulanır.
is_trusted_app_process() {
    local name="${1:-}" pid="${2:-}" app
    [[ -n "$name" && "$name" != "unknown" ]] || return 1
    for app in "${APP_WHITELIST[@]}"; do
        if [[ "$name" == "$app" ]] || { (( ${#app} >= 5 )) && [[ "$name" == "$app"* ]]; }; then
            is_trusted_exe_path "$pid" && return 0
            return 1
        fi
    done
    return 1
}

is_legit_remote_process() {
    local proc_name="$1"
    local pid="${2:-}"
    [[ -z "$proc_name" ]] && return 1

    local matched=1
    for sw in "${LEGIT_REMOTE_SOFTWARE[@]}"; do
        if [[ "$proc_name" =~ $sw ]]; then
            matched=0
            break
        fi
    done
    [[ "$matched" -ne 0 ]] && return 1

    # V60 fail-closed exemption: a name alone can never bypass protection.
    [[ -z "$pid" ]] && return 1
    is_process_path_suspicious "$pid" && return 1
    is_trusted_exe_path "$pid" || return 1

    return 0
}


get_process_for_ip() {
    local ip="$1"
    local pid=""
    [[ -z "$ip" ]] && { echo ""; return 1; }

    if command -v ss &>/dev/null; then
        local line
        line=$(ss -tunap 2>/dev/null | grep -F "$ip" | head -1)
        if [[ "$line" =~ pid=([0-9]+) ]]; then
            pid="${BASH_REMATCH[1]}"
        fi
    fi

    [[ -z "$pid" ]] && { echo ""; return 1; }
    get_process_name "$pid"
    return 0
}

# get_process_for_ip fonksiyonunun PID döndüren eşleniği
# doğrulaması için gerekli.
get_pid_for_ip() {
    local ip="$1"
    [[ -z "$ip" ]] && { echo ""; return 1; }

    if command -v ss &>/dev/null; then
        local line
        line=$(ss -tunap 2>/dev/null | grep -F "$ip" | head -1)
        if [[ "$line" =~ pid=([0-9]+) ]]; then
            echo "${BASH_REMATCH[1]}"
            return 0
        fi
    fi
    echo ""
    return 1
}

# ==============================================================================
# 6. AĞ ARABİRİM TESPİTİ
# ==============================================================================
detect_network_interfaces() {
    echo -e "${C_CYAN}[*] Ağ arayüzleri taranıyor...${C_RESET}"

    WAN_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "$WAN_INTERFACE" ]]; then
        WAN_INTERFACE=$(ip -o link show | grep -E 'enp|ens|enx|eth|wl' | head -1 | awk -F': ' '{print $2}')
    fi

    if [[ -n "$WAN_INTERFACE" ]]; then
        local wan_ip
        wan_ip=$(ip -4 addr show "$WAN_INTERFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        echo -e "  ${C_GREEN}[✓] WAN: $WAN_INTERFACE${C_RESET} -> ${wan_ip:-BULUNAMADI}"
    else
        echo -e "  ${C_RED}[✗] WAN arayüzü bulunamadı!${C_RESET}"
        return 1
    fi

    echo -e "  ${C_GREEN}[✓] Ağ tespiti tamamlandı${C_RESET}"
    return 0
}

# ==============================================================================
# 7. NFTABLES KURULUMU
# ==============================================================================
init_nftables() {
    echo -e "${C_CYAN}[*] NFTables kuralları oluşturuluyor...${C_RESET}"

    command -v nft >/dev/null || { echo "nft kurulu değil; otomatik indirme kapalı" >&2; return 1; }
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 &>/dev/null
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 &>/dev/null
    sysctl -w net.ipv4.ip_forward=0 >/dev/null || return 1
    # Loose reverse-path checking is compatible with WireGuard policy routing.
    # It rejects unroutable sources; it cannot authenticate every public IP.
    sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null || return 1
    sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null || return 1
    sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null || return 1
    sysctl -w net.ipv4.conf.all.accept_source_route=0 >/dev/null || return 1
    sysctl -w net.ipv4.conf.default.accept_source_route=0 >/dev/null || return 1
    sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null || return 1
    sysctl -w net.ipv4.conf.default.accept_redirects=0 >/dev/null || return 1
    sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null || return 1
    local conf control
    for conf in /proc/sys/net/ipv4/conf/*; do
        for control in accept_source_route accept_redirects send_redirects; do
            sysctl -w "net/ipv4/conf/${conf##*/}/$control=0" >/dev/null || return 1
        done
    done
    cat > /etc/sysctl.d/90-satsuma-security.conf <<'SATSUMA_SYSCTL'
net.ipv4.ip_forward=0
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.conf.all.src_valid_mark=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
SATSUMA_SYSCTL
    [[ $? -eq 0 ]] || return 1

    

    local staged
    staged=$(mktemp /etc/.satsuma-nft-init.XXXXXX) || return 1
    cat > "$staged" << 'EOF'
#!/usr/sbin/nft -f
add table inet satsuma_filter
delete table inet satsuma_filter
table inet satsuma_filter {
    # V54: Başlangıç seed listesi TEMİZLENDİ. Eskiden burada 45.83.0.0/16,
    # 192.178.0.0/16 (Google'ın tamamı), 142.251.38.0/24, 172.217.112.0/24,
    # 172.217.118.0/23 gibi devasa aralıklar sabit kodluydu - bunlar
    # kullanıcının bilinçli eklediği "bilinen kötü" IP'ler değil, script'in
    # kendisinin (önceki bir düzenleme sırasında) eklediği kalıntı girişlerdi
    # ve büyük ölçüde meşru CDN/bulut altyapısıyla çakışıyordu. Artık set
    # boş başlıyor; gerçek tehditler script'in kendi tespit döngüsü
    # (Suricata/OTX/rootkit/vb.) tarafından çalışma zamanında /32 olarak
    # eklenecek.
    set blocked_ips {
        type ipv4_addr
        flags interval
        auto-merge;
        comment "Satsuma Sentinel Blocked IPs/Subnets"
        
	}




    # Queue verdicts run in later base chains, after firewall policy.
    chain ips_input { type filter hook input priority 10; policy accept; }
    chain ips_forward { type filter hook forward priority 10; policy accept; }
    chain ips_output { type filter hook output priority 10; policy accept; }
    chain input {
        type filter hook input priority 0; policy drop;
        ip saddr @blocked_ips drop
        meta nfproto ipv6 counter drop
        ct state invalid drop
        iif "lo" accept
        udp sport 67 udp dport 68 counter accept
        # Ingress claiming loopback, this host, multicast or unroutable source.
        ip saddr { 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4, 240.0.0.0/4 } counter drop
        fib saddr type local counter drop
        fib saddr . mark oif missing counter drop
        ct state established,related accept
        udp dport 51820 counter accept
        ip protocol icmp drop
        tcp dport { 22, 23, 4444, 5555, 6666, 7777, 8888, 9999, 31337, 1337 } drop
        udp dport { 137, 138, 139, 445, 135, 2049, 111, 548, 631  } drop
        tcp dport { 137, 138, 139, 445, 135, 2049, 111, 548, 631  } drop
        limit rate 5/second burst 20 packets log prefix "SATSUMA-DROP-IN: " counter drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        limit rate 5/second burst 20 packets log prefix "SATSUMA-DROP-FWD: " counter drop
    }

    chain output {
        type filter hook output priority 0; policy drop;
        meta nfproto ipv6 counter drop
        ip daddr @blocked_ips drop
        tcp dport { 9001, 9030, 9040, 9050, 9051, 9150 } counter drop
        oif "lo" accept
        ip saddr 0.0.0.0 udp sport 68 udp dport 67 counter accept
        udp sport 68 udp dport 67 counter accept
        # Never emit IPv4 packets with a source not assigned to this host.
        fib saddr type != local counter drop
        ip daddr 208.67.222.222 udp dport 53 ct state new accept
        ct state established,related accept
        # 853 (DNS over TLS) is never allowed: C2 over 853 was proven on this machine;
        # DNS is plain (satsuma_plain_dns). 853 asla izinli değil; DNS düz.
        tcp dport 853 counter drop
        udp dport 853 counter drop
        tcp dport {53, 2690, 443} ct state new accept
        udp dport {51820, 53} ct state new accept
        udp dport 123 ct state new accept
        # V55.3: Zenarmor'a özel VIP IP izni (35.184.76.118, 104.26.9.148,
        # 172.67.74.209 - port 2096 Zenarmor bulut yönetimine aitti)
        # kaldırıldı, uygulama artık kullanılmıyor.
        tcp dport { 22, 23, 4444, 5555, 6666, 7777, 8888, 9999, 31337, 1337 } drop
        udp dport { 137, 123, 138, 139, 445, 135, 2049, 111, 548, 631 } drop
        tcp dport { 137, 138, 139, 445, 135, 2049, 111, 548, 631 } drop
        limit rate 5/second burst 20 packets log prefix "SATSUMA-DROP-OUT: " counter drop
    }
}
EOF

    if nft -c -f "$staged" && nft -f "$staged"; then
        rm -f -- "$staged"
        echo -e "  ${C_GREEN}[✓] NFTables kuralları uygulandı${C_RESET}"
    else
        rm -f -- "$staged"
        echo -e "  ${C_RED}[✗] NFTables kuralları uygulanamadı!${C_RESET}"
        return 1
    fi


    echo -e "  ${C_GREEN}[✓] NFTables - Maksimum Güvenlik Aktif!${C_RESET}"
    echo -e "  ${C_RED}   SSH (22) PORTU KAPALI${C_RESET}"
    echo -e "  ${C_RED}   TÜM AĞ PAYLAŞIM PORTLARI KAPALI${C_RESET}"
    echo -e "  ${C_GREEN}   OUTBOUND: TCP 53/2690/443; UDP DNS/NTP/WireGuard ve DHCP istemcisi açık; 853 kapalı${C_RESET}"

    return 0
}

# V52.9: Suricata'yı geçerli ağ arayüzüne göre otomatik yeniden yapılandırır
# ve isteğe bağlı olarak IPS (inline engelleme) moduna geçirir.
#
# "Suricata hiç tepki vermiyor" sorununun en olası nedeni: konfigürasyonda
# yazılı arayüz (interface) artık gerçek trafiği taşımıyor - özellikle
# ağ topolojisi değiştiyse (yeni NIC, bridge/VM geçişi, pfSense arkasına
# geçiş vb.). Bu fonksiyon WAN_INTERFACE'i (script'in kendi tespit ettiği
# güncel arayüz) alıp Suricata'ya yazar.

configure_suricata() {
    [[ "$ENABLE_SURICATA_AUTOCONFIG" == true && "$ENABLE_SURICATA_IPS" == true ]] || {
        echo "Bu kurulum doğrulanmış NFQUEUE IPS modu gerektirir." >&2; return 1;
    }
    [[ "$SURICATA_NFQUEUE_NUM" =~ ^(0|[1-9][0-9]{0,4})$ ]] &&
        (( SURICATA_NFQUEUE_NUM <= 65535 )) || return 1
    [[ "$SURICATA_YAML" == /etc/suricata/suricata.yaml ]] || return 1
    local binary staged i bound=false
    binary=$(command -v suricata) || return 1
    # -q tests the actual capture mode, not just an unrelated AF_PACKET config.
    "$binary" -T --init-errors-fatal -q "$SURICATA_NFQUEUE_NUM" -c "$SURICATA_YAML" -S /var/lib/satsuma-rules/suricata.rules -v \
        > "$SATSUMA_RUN_DIR/suricata_test.out" 2>&1 || return 1
    grep -Eq '[1-9][0-9]* rules successfully loaded' "$SATSUMA_RUN_DIR/suricata_test.out" || {
        echo "Yüklenmiş Suricata imzaları doğrulanamadı; sıfır kuralla IPS başarılı sayılmadı." >&2; return 1;
    }
    install -d -m 755 /etc/systemd/system/suricata.service.d || return 1
    cat > /etc/systemd/system/suricata.service.d/satsuma-nfqueue.conf <<EOF
[Service]
Type=simple
ExecStart=
ExecStart=$binary -c /etc/suricata/suricata.yaml -q $SURICATA_NFQUEUE_NUM -S /var/lib/satsuma-rules/suricata.rules
Restart=on-failure
RestartSec=3
EOF
    restorecon -v /etc/suricata/suricata.yaml /etc/systemd/system/suricata.service.d/satsuma-nfqueue.conf || return 1
    systemctl daemon-reload && systemctl enable suricata && systemctl restart suricata || return 1
    for ((i=0; i<15; i++)); do
        if awk -v q="$SURICATA_NFQUEUE_NUM" '$1==q {ok=1} END {exit !ok}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null; then
            bound=true; break
        fi
        sleep 1
    done
    [[ "$bound" == true ]] || { echo "NFQUEUE tüketicisi yok; IPS doğrulanmadı." >&2; return 1; }
    staged=$(mktemp /etc/.satsuma-nft-ips.XXXXXX) || return 1
    for i in input forward output; do
        printf 'flush chain inet satsuma_filter ips_%s
' "$i"
        printf 'add rule inet satsuma_filter ips_%s counter queue num %s
' "$i" "$SURICATA_NFQUEUE_NUM"
    done > "$staged"
    if ! nft -c -f "$staged" || ! nft -f "$staged"; then
        rm -f -- "$staged"; return 1
    fi
    rm -f -- "$staged"
    satsuma_verify_ips "$SURICATA_NFQUEUE_NUM" || return 1
    save_persistent_nftables || return 1
    echo "IPS yapısı doğrulandı. Bypass yok: tüketici durursa kuyruktaki trafik düşer (fail-closed)."
    echo "Gerçek paket engelleme teyidi ayrıca kontrollü drop kuralı ve trafik testi gerektirir."
}

# No service restarts run at source-load time; all service changes occur only
# inside the explicitly confirmed --full setup.

save_persistent_nftables() {
    local tmp
    tmp=$(mktemp /etc/.satsuma-nft.XXXXXXXX) || return 1
    {
        printf 'add table inet satsuma_filter
delete table inet satsuma_filter
'
        nft list table inet satsuma_filter
    } > "$tmp" || { rm -f -- "$tmp"; return 1; }
    nft -c -f "$tmp" || { rm -f -- "$tmp"; return 1; }
    chmod 600 "$tmp" && mv -f -- "$tmp" /etc/nftables.conf || return 1
    # A dedicated boot unit loads exactly this file on Fedora and Debian.
    local nft_binary
    nft_binary=$(command -v nft) || return 1
    cat > /etc/systemd/system/satsuma-firewall.service <<EOF
[Unit]
Description=Satsuma endpoint firewall and NFQUEUE rules
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=$nft_binary -f /etc/nftables.conf
ExecStart=/usr/local/bin/satsuma-mini --network-enforce-state
ExecReload=$nft_binary -f /etc/nftables.conf
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
    restorecon -v /etc/nftables.conf /etc/systemd/system/satsuma-firewall.service || return 1
    systemctl daemon-reload && systemctl enable satsuma-firewall.service
}


declare -A NFT_FAIL_UNTIL=()
NFT_MISSING_WARN_AT=-1000
add_subnet_to_blocklist() {
   local subnet="$1"
    [[ -z "$subnet" ]] && return 1
    validate_ip "${subnet%/*}" || return 1
    if [[ "$subnet" == */* ]]; then
        [[ "${subnet#*/}" =~ ^(0|[1-9]|[12][0-9]|3[0-2])$ ]] || return 1
    fi
    [[ -n "${BLOCKED_SUBNET_CACHE[$subnet]:-}" ]] && return 0
    # V62.3: başarısız denemeyi her taramada tekrarlama (5 dk bekle)
    (( ${NFT_FAIL_UNTIL[$subnet]:-0} > SECONDS )) && return 1


    if [[ "$subnet" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        subnet="${subnet}/32"
    elif [[ ! "$subnet" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        return 1
    fi

    local nft_error
    nft_error=$(nft add element inet satsuma_filter blocked_ips { "$subnet" } 2>&1)
 
    if [[ $? -eq 0 ]]; then
        BLOCKED_SUBNET_CACHE["$subnet"]="true"
        save_persistent_nftables
        return 0
    fi

    echo "$(date -Iseconds) | NFT-HATA | subnet=$subnet | $nft_error" >> "${AUDITD_ALERT_LOG:-/var/log/satsuma_nft_errors.log}" 2>/dev/null || true
    NFT_FAIL_UNTIL["$subnet"]=$((SECONDS + 300))
    if ! nft list set inet satsuma_filter blocked_ips &>/dev/null; then
        if (( SECONDS - NFT_MISSING_WARN_AT > 300 )); then
            NFT_MISSING_WARN_AT=$SECONDS
            add_activity_log "${C_BG_RED}${C_WHITE}[NFT-YOK]${C_RESET} inet satsuma_filter/blocked_ips bulunamadı: güvenlik duvarı kuralları YÜKLÜ DEĞİL! Betiği --full ile yeniden çalıştırın."
        fi
    else
        add_activity_log "${C_RED}[NFT-HATA]${C_RESET} $subnet: ${nft_error%%$'\n'*}"
    fi
    return 1
}

# ==============================================================================
# 8. SSH KAPATMA
# ==============================================================================
disable_unneeded_local_services() {
    # Local workstation policy: remote login, printer discovery, and file-sharing
    # services are stopped and prevented from starting automatically.
    # This intentionally blocks SSH access; do not run remotely.
    local svc
    local services=(
        ssh.service sshd.service ssh.socket sshd.socket
        cups.service cups.socket cups.path cups-browsed.service
        avahi-daemon.service avahi-daemon.socket
        smbd.service nmbd.service samba.service nfs-server.service
    )
    for svc in "${services[@]}"; do
        if systemctl cat "$svc" >/dev/null 2>&1; then
            systemctl stop "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            case "$svc" in
                ssh.service|sshd.service|ssh.socket|sshd.socket|\
                cups.service|cups.socket|cups.path|cups-browsed.service|\
                avahi-daemon.service|avahi-daemon.socket|\
                smbd.service|nmbd.service|samba.service|nfs-server.service)
                    systemctl mask "$svc" 2>/dev/null || true ;;
            esac
        fi
    done
    add_activity_log "[LOCAL-HARDENING] SSH/CUPS/Avahi/Samba/NFS servisleri durdurulup devre disi birakildi (varsa)."
}

# ==============================================================================
# 9. SURICATA ALERT İŞLEME
# ==============================================================================
# NOT (V52.9): Bu fonksiyonun eskiden burada, kapanışından hemen sonra,
# fonksiyon tanımı OLMADAN script gövdesine sızmış ~350 satırlık bir
# "hayalet" ikinci kopyası vardı. O kod her script başlangıcında (henüz
# auto_setup_wizard bile çağrılmadan) top-level olarak bir kez çalışıyor,
# içindeki ENABLE_SURICATA guard'ı yanlışlıkla yorum satırı yapılmış
# olduğundan atlanamıyor, henüz tanımlanmamış fonksiyonları (is_whitelisted_ip,
# kill_connections_for_ip) çağırmaya çalışıyor ve en önemlisi state dosyasını
# güncelleyerek asıl döngüdeki gerçek process_suricata_alerts çağrısının
# "yeni satır yok" sanmasına yol açıyordu. Bu, "Suricata anlık log basıyor
# ama script görmüyor" şikayetinin kök nedeniydi. O blok tamamen kaldırıldı;
# aşağıdaki tek ve doğru fonksiyon tanımı yeterli.
process_suricata_alerts() {
    [[ "$ENABLE_SURICATA" != "true" ]] && return 0

    if [[ ! -f "$SURICATA_LOG" ]]; then
        return 0
    fi

    if ! command -v jq &>/dev/null; then
        add_activity_log "${C_YELLOW}[SURICATA]${C_RESET} jq bulunamadı!"
        return 0
    fi

    local udp_review_count=0
    local state_dir
    state_dir="$(dirname "$SURICATA_STATE_FILE")"
    mkdir -p "$state_dir" 2>/dev/null || true

    _process_single_suricata_alert() {
        local json_line="$1"
        [[ -z "$json_line" ]] && return 0

        # V52.9: İnceleme modunda Suricata yolu da blok/kill yapmasın,
        # ama alert'i yine de görünür kılmak için loglasın.
        if [[ -f "$PAUSE_FILE" ]]; then
            return 0
        fi

        # An attacker can spoof UDP source addresses and payload-triggered
        # signatures. Such alerts must never create a persistent source-IP ban.
        [[ ${#json_line} -le 65536 ]] || return 0
        jq -e '.event_type == "alert" and (.alert | type == "object")' >/dev/null 2>&1 <<< "$json_line" || return 0
        local protocol
        protocol=$(jq -r '.proto // ""' <<< "$json_line") || return 0
        if [[ "$protocol" != TCP ]]; then
            if (( udp_review_count < 5 )); then
                add_activity_log "[SURICATA-INCELEME] TCP dışı alarm: otomatik IP engeli yok; IPS paket kararı korunur."
            fi
            udp_review_count=$((udp_review_count + 1))
            return 0
        fi
        # A payload signature alone does not prove the claimed peer identity.
        jq -e '(.flow.pkts_toserver // 0) > 0 and (.flow.pkts_toclient // 0) > 0' >/dev/null 2>&1 <<< "$json_line" || return 0
        local src_ip dest_ip sig_msg sig_id sig_severity target_ip

        src_ip=$(jq -r '.src_ip // empty' <<< "$json_line" 2>/dev/null || true)
        dest_ip=$(jq -r '.dest_ip // empty' <<< "$json_line" 2>/dev/null || true)
        sig_msg=$(jq -r '.alert.signature // "Tehdit"' <<< "$json_line" 2>/dev/null || echo "Tehdit")
        sig_id=$(jq -r '.alert.signature_id // 0' <<< "$json_line" 2>/dev/null || echo "0")
        sig_severity=$(jq -r '.alert.severity // 3' <<< "$json_line" 2>/dev/null || echo "3")
        [[ "$sig_severity" =~ ^[0-9]+$ ]] || sig_severity=3

        target_ip=""

        if [[ -n "$src_ip" ]] && is_local_ip "$src_ip"; then
            target_ip="$dest_ip"
        elif [[ -n "$dest_ip" ]] && is_local_ip "$dest_ip"; then
            target_ip="$src_ip"
        else
            target_ip="$src_ip"
        fi

        validate_ip "$target_ip" || return 0
        # Corroborate against a local established TCP socket before IP-wide action.
        local peers
        peers=$(ss -Htn state established 2>/dev/null) || return 0
        awk -v ip="$target_ip" '{peer=$4; sub(/:[0-9]+$/, "", peer); if (peer==ip) ok=1} END {exit !ok}' <<< "$peers" || return 0
        is_local_ip "$target_ip" && return 0
        is_whitelisted_ip "$target_ip" && return 0
        [[ -n "${BLOCKED_IP_CACHE[$target_ip]:-}" ]] && return 0

        # V52.9: VM koruması - VM_SUBNET içindeki hiçbir IP'ye Suricata
        # tetiklese dahi dokunulmaz.
        if is_vm_ip "$target_ip"; then
            add_activity_log "${C_BLUE}[VM-KORUMA]${C_RESET} $target_ip - Suricata: $sig_msg (VM subnetinde, dokunulmadı)"
            return 0
        fi

        # V55.3: KALDIRILDI - AnyDesk/RustDesk/TeamViewer muafiyeti Suricata
        # tetiklemesi için artık uygulanmıyor. Karar: Suricata imza tabanlı
        # (Priority 1-2) bir eşleşme üretiyorsa, trafiğin hangi süreçle
        # ilişkili olduğu önemli değil - zaten bir sorun yaşanmıştır demektir
        # (ör. kötü niyetli bir müşteri AnyDesk oturumu üzerinden gerçek bir
        # rootkit/exploit göndermiş olabilir). Bu yüzden Suricata NE OLURSA
        # OLSUN bloklar. Meşru uzak erişim muafiyeti (PROTECT_LEGIT_REMOTE)
        # sadece OTX ve DNS-less gibi daha düşük güvenilirlikli, imza
        # tabanlı OLMAYAN sezgisel tespitlerde kullanılmaya devam ediyor -
        # oralarda dokunulmadı.

        # V54: SADELEŞTİRİLDİ. Eşik/sayaç mantığı tamamen kaldırıldı -
        # önceki tasarımda "eşik ne kadar yüksek olursa olsun sabit bir CDN
        # IP'sine yeterince uzun süre (saatler) trafik gidince eninde
        # sonunda aşılıyordu" sorunu vardı, bu da öngörülemez şekilde
        # gerçek bağlantıları (Claude.ai/Cloudflare dahil) kesiyordu.
        # Artık kural kesin ve basit: Priority 1-2 (gerçek imza eşleşmesi,
        # örn. ET Trojan/Exploit) HER ZAMAN bloklanır. Priority 3+ (Generic
        # Protocol Command Decode - "excessive different SYN/ACKs",
        # "invalid timestamp" gibi düşük güvenilirlikli protokol anomalileri)
        # KAYNAK NE OLURSA OLSUN, NE KADAR TEKRAR EDERSE ETSİN asla blok/kill
        # tetiklemez - sadece bilgi amaçlı loglanır. Gerçek tehditler zaten
        # neredeyse hiçbir zaman sadece Priority 3 sınıfında kalmaz.
        if [[ "$sig_severity" -gt 3 ]]; then
            add_activity_log "${C_DIM}[SURICATA-LOG]${C_RESET} $target_ip - $sig_msg (Priority ${sig_severity} - göz ardı edildi, sadece P1/P2/P3 işlenir)"
            return 0
        fi

        if add_subnet_to_blocklist "${target_ip}/32" 2>/dev/null; then
            BLOCKED_IP_CACHE["$target_ip"]="true"

            SURICATA_BLOCKS=$((SURICATA_BLOCKS + 1))
            TOTAL_BLOCKS=$((TOTAL_BLOCKS + 1))

            local killed=0
            killed=$(kill_connections_for_ip "$target_ip" 2>/dev/null || echo 0)
            [[ "$killed" =~ ^[0-9]+$ ]] || killed=0

            TOTAL_CONNECTIONS_KILLED=$((TOTAL_CONNECTIONS_KILLED + killed))

            add_activity_log \
                "${C_RED}[SURICATA-BLOK]${C_RESET} $target_ip - $sig_msg"

            log_block "$target_ip" \
                "Suricata: $sig_msg [SID:$sig_id]" \
                "suricata"

            SURICATA_ALERTS=(
                "${C_RED}$target_ip - $sig_msg${C_RESET}"
                "${SURICATA_ALERTS[@]}"
            )

            [[ ${#SURICATA_ALERTS[@]} -gt $MAX_SURICATA_ALERTS ]] &&
                SURICATA_ALERTS=("${SURICATA_ALERTS[@]:0:$MAX_SURICATA_ALERTS}")
        fi

        return 0
    }

    local current_inode current_lines
    local last_inode=0
    local last_line=0

    current_inode=$(stat -c '%i' "$SURICATA_LOG" 2>/dev/null || echo 0)
    current_lines=$(wc -l < "$SURICATA_LOG" 2>/dev/null || echo 0)

    if [[ -f "$SURICATA_STATE_FILE" ]]; then
        read -r last_inode last_line < "$SURICATA_STATE_FILE" 2>/dev/null || true
    fi

    [[ "$last_inode" =~ ^[0-9]+$ ]] || last_inode=0
    [[ "$last_line" =~ ^[0-9]+$ ]] || last_line=0

    # İlk çalışma: mevcut geçmişi tara
    if [[ ! -f "$SURICATA_STATE_FILE" ]]; then
        add_activity_log \
            "${C_YELLOW}[SURICATA]${C_RESET} İlk çalışma - geçmiş loglar taranıyor..."

        while IFS= read -r json_line; do
            [[ -n "$json_line" ]] &&
                _process_single_suricata_alert "$json_line"
        done < <(
            jq -c 'select(.event_type == "alert")' \
                "$SURICATA_LOG" 2>/dev/null
        )

        printf '%s %s\n' "$current_inode" "$current_lines" \
            > "$SURICATA_STATE_FILE" 2>/dev/null || true

        unset -f _process_single_suricata_alert 2>/dev/null || true
        return 0
    fi

    # Log rotate / truncate
    if [[ "$current_inode" != "$last_inode" ]] ||
       [[ "$current_lines" -lt "$last_line" ]]; then

        add_activity_log \
            "${C_YELLOW}[SURICATA]${C_RESET} Log rotate/truncate tespit edildi."

        last_line=0
    fi

    if [[ "$current_lines" -le "$last_line" ]]; then
        unset -f _process_single_suricata_alert 2>/dev/null || true
        return 0
    fi

    local new_lines

    new_lines=$((current_lines - last_line))
    # V54: Bu rutin "X satır tarandı" mesajı artık CANLI GUVENLIK OLAY
    # AKISI'na eklenmiyor - her birkaç saniyede bir tetiklendiği için asıl
    # önemli olayları (blok/kill/alarm) anında listeden itip çıkarıyordu.
    # Artık ayrı, tek satırlık bir durum göstergesinde tutuluyor.
    LAST_SURICATA_SCAN_INFO="${new_lines} yeni satır (son: $(date +%H:%M:%S))"

    while IFS= read -r json_line; do
        [[ -n "$json_line" ]] &&
            _process_single_suricata_alert "$json_line"
    done < <(
        tail -n "$new_lines" "$SURICATA_LOG" 2>/dev/null |
        jq -c 'select(.event_type == "alert")' 2>/dev/null
    )

    printf '%s %s\n' "$current_inode" "$current_lines" \
        > "$SURICATA_STATE_FILE" 2>/dev/null || true

    unset -f _process_single_suricata_alert 2>/dev/null || true
    return 0
}

# ==============================================================================
# 10. AĞ FONKSİYONLARI
# ==============================================================================

ip_to_subnet() {
    local ip="$1"
    local mask="${2:-32}"
    [[ "$mask" =~ ^(0|[1-9]|[12][0-9]|3[0-2])$ ]] || return 1
    validate_ip "$ip" || { echo "$ip"; return; }

    # /32 için direkt IP’yi döndür
    if [[ $mask -eq 32 ]]; then
        echo "${ip}/32"
        return
    fi

    local o1 o2 o3 o4
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    if [[ $mask -ge 24 ]]; then
        echo "${o1}.${o2}.${o3}.0/${mask}"
    elif [[ $mask -ge 16 ]]; then
        echo "${o1}.${o2}.0.0/${mask}"
    elif [[ $mask -ge 8 ]]; then
        echo "${o1}.0.0.0/${mask}"
    else
        echo "0.0.0.0/${mask}"
    fi
}

get_next_subnet() {
    local subnet="$1"
    local network="${subnet%/*}"
    local mask="${subnet#*/}"

    [[ "$mask" =~ ^[0-9]+$ ]] || return 1

    local new_mask

    new_mask=$((mask - 8))
    if [[ $new_mask -lt $MAX_SUBNET_MASK ]]; then
        new_mask=$MAX_SUBNET_MASK
    fi

    if [[ $new_mask -ge $mask ]]; then
        # Zaten en üst eskalasyon seviyesindeyiz, daha fazla genişletilemez
        return 1
    fi

    local ip="${network}"
    ip_to_subnet "$ip" "$new_mask"
    return 0
}

ip_in_cidr() {
    local ip="$1"
    local cidr="$2"
    local network="${cidr%/*}"
    local mask="${cidr#*/}"
    validate_ip "$network" || return 1
    [[ "$mask" =~ ^(0|[1-9]|[12][0-9]|3[0-2])$ ]] || return 1
    validate_ip "$ip" || return 1

    local i1 i2 i3 i4 n1 n2 n3 n4
    IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
    IFS='.' read -r n1 n2 n3 n4 <<< "$network"

    local ip_int

    ip_int=$(( (i1 << 24) + (i2 << 16) + (i3 << 8) + i4 ))
    local net_int
    net_int=$(( (n1 << 24) + (n2 << 16) + (n3 << 8) + n4 ))
    local mask_int
    mask_int=$(( 0xFFFFFFFF ^ ((1 << (32 - mask)) - 1) ))
    [ $((ip_int & mask_int)) -eq $((net_int & mask_int)) ] && return 0
    return 1
}

# V62: Suricata alarmı kaynak IP'si sahte (spoof) olabilir; saldırgan varsayılan ağ geçidini
# veya DNS çözücüleri blokla­tarak ağı kesebilirdi. Bunlar artık asla bloklanmaz.
DYN_WHITELIST_TS=-1000
DYN_WHITELIST=()
refresh_dynamic_whitelist() {
    (( SECONDS - DYN_WHITELIST_TS < 60 )) && return 0
    DYN_WHITELIST_TS=$SECONDS
    DYN_WHITELIST=()
    local x
    while read -r _wg_peer _wg_endpoint; do
        local _wg_ip="${_wg_endpoint%:*}"
        validate_ip "$_wg_ip" && DYN_WHITELIST+=("$_wg_ip")
    done < <(wg show all endpoints 2>/dev/null | awk '{print $2, $3}')
    while read -r x; do
        validate_ip "$x" && DYN_WHITELIST+=("$x")
    done < <(
        { ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}'
          awk '$1=="nameserver"{print $2}' /etc/resolv.conf 2>/dev/null; } | sort -u
    )
}

is_whitelisted_ip() {
    local ip="$1"
    validate_ip "$ip" || return 1

    # V62.2: Yönlendirilemez/özel amaçlı adresler asla bloklanmaz (0.0.0.0 UDP dinleyicileri,
    # multicast, yayın, link-local). Önceden "0.0.0.0 - Aşırı bağlantı" olarak bloklanıyordu.
    [[ "$ip" =~ ^0\. ]] && return 0
    [[ "$ip" =~ ^(22[4-9]|23[0-9]|24[0-9]|25[0-5])\. ]] && return 0
    [[ "$ip" =~ ^169\.254\. ]] && return 0

    refresh_dynamic_whitelist
    local d
    for d in "${DYN_WHITELIST[@]}"; do
        [[ "$ip" == "$d" ]] && return 0
    done

    [[ "$ip" =~ ^127\. ]] && return 0
    [[ "$ip" =~ ^10\. ]] && return 0
    [[ "$ip" =~ ^192\.168\. ]] && return 0
    [[ "$ip" =~ ^172\.1[6-9]\. ]] && return 0
    [[ "$ip" =~ ^172\.2[0-9]\. ]] && return 0
    [[ "$ip" =~ ^172\.3[0-1]\. ]] && return 0

    for w in "${WHITELIST_IPS[@]}"; do
        if [[ "$ip" == "$w" ]]; then
            return 0
        elif [[ "$w" == */* ]]; then
            ip_in_cidr "$ip" "$w" && return 0
        fi
    done

    return 1
}

kill_connections_for_ip() {
    local ip="$1"
    local killed=0

    # V62: geçersiz IP ile asla conntrack/ss çalıştırma (seçenek enjeksiyonu / joker eşleşme)
    validate_ip "$ip" || { echo 0; return 0; }

    # V52.9: VM'e ait bir IP ise dokunma, hiçbir şey öldürme.
    if is_vm_ip "$ip"; then
        echo 0
        return 0
    fi

    # V54: KILL_CONNECTIONS artık GERÇEKTEN kontrol ediliyor. Eskiden bu
    # değişken sadece tanımlanıyordu, script'in hiçbir yerinde okunmuyordu -
    # "false" yapsan da yapmasan da davranış AYNIYDI. Şimdi false ise: IP
    # nftables tarafından bloklanır (yeni bağlantılar/paketler durur) ama
    # HÂLİHAZIRDA KURULU bağlantılar zorla kesilmez - uygulama o bağlantıyı
    # doğal şekilde kapatana/timeout olana kadar sürdürür, "aniden kapandı"
    # hissi vermez. true ise: mevcut bağlantılar da conntrack ile anında
    # düşürülür (eski davranış).
    if [[ "$KILL_CONNECTIONS" != "true" ]]; then
        echo 0
        return 0
    fi

    if command -v ss &>/dev/null; then
        # V62: eskiden grep "$ip" düzenli ifadeydi (noktalar joker, alt dize eşleşir:
        # 10.0.0.5 -> 110.0.0.55). Artık tam IP:port eşleşmesi aranır.
        local pids ip_re="${ip//./\\.}"
        pids=$(ss -tunap 2>/dev/null | grep -E "(^|[^0-9.])${ip_re}:[0-9]+([^0-9]|\$)" | grep -oP 'pid=\K[0-9]+' | sort -u)
        for pid in $pids; do
            if [[ -n "$pid" ]] && [[ "$pid" =~ ^[0-9]+$ ]]; then
                # V52.9: Bu PID meşru uzak erişim yazılımıysa (AnyDesk/
                # RustDesk/TeamViewer/vb) kullanıcının izni olmadan kesme.
                # Binary yolu da doğrulanıyor - sadece isim eşleşmesi
                # yetmiyor artık.
                if [[ "$PROTECT_LEGIT_REMOTE" == "true" ]]; then
                    local pname
                    pname=$(get_process_name "$pid")
                    if is_legit_remote_process "$pname" "$pid"; then
                        PROTECTED_IP_CACHE["$ip"]="true"
                        add_activity_log "${C_GREEN}[MUAF]${C_RESET} $ip - PID $pid ($pname) kullanıcı onaylı, kesilmedi"
                        echo 0
                        return 0
                    fi
                fi
            fi
        done
    fi

    # V54: "killed" artık GERÇEKTEN sayılıyor. Eskiden bu değişken hiç
    # artırılmıyordu, fonksiyon her zaman "0" döndürüyordu - dashboard'daki
    # "Bağlantı Kes" istatistiği bu yüzden hep anlamsızdı. conntrack -D
    # çıktısındaki "N flow entries have been deleted" satırından gerçek
    # sayı parse ediliyor.
    if command -v conntrack &>/dev/null; then
        local out n
        out=$(conntrack -D -d "$ip" 2>&1)
        n=$(grep -oP '\K[0-9]+(?= flow entries have been deleted)' <<< "$out" 2>/dev/null || echo 0)
        [[ "$n" =~ ^[0-9]+$ ]] && killed=$((killed + n))

        out=$(conntrack -D -s "$ip" 2>&1)
        n=$(grep -oP '\K[0-9]+(?= flow entries have been deleted)' <<< "$out" 2>/dev/null || echo 0)
        [[ "$n" =~ ^[0-9]+$ ]] && killed=$((killed + n))
    fi

    echo "$killed"
    return 0
}

get_process_name() {
    local pid="$1"
    local proc_name="unknown"

    if [[ -n "$pid" ]] && [[ "$pid" =~ ^[0-9]+$ ]] && [[ "$pid" -gt 0 ]] && [[ -f "/proc/${pid}/comm" ]]; then
        proc_name=$(cat "/proc/${pid}/comm" 2>/dev/null | head -1)
        [[ -z "$proc_name" ]] && proc_name="PID:${pid}"
    fi

    echo "$proc_name"
}

# ==============================================================================
# 11. BAĞLANTI TOPLAMA
# ==============================================================================
get_connections() {
    SUBNET_CONNECTIONS=()
    SUBNET_PIDS=()
    SUBNET_SAMPLE_IPS=()
    SUBNET_ALL_IPS=()
    SUBNET_TRUSTED=()

    local total=0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        [[ ! "$line" =~ ^tcp ]] && continue

        [[ "$line" =~ 127\.0\.0\.1 ]] && continue
        [[ "$line" =~ ::1 ]] && continue

        local -a fields
        read -ra fields <<< "$line"
        [[ "${fields[1]:-}" == ESTAB ]] || continue
        local remote=""

        if [[ "${fields[0]}" == "tcp" ]] || [[ "${fields[0]}" == "tcp6" ]]; then
            remote="${fields[5]}"
        elif [[ "${fields[0]}" == "udp" ]] || [[ "${fields[0]}" == "udp6" ]]; then
            remote="${fields[4]}"
        else
            continue
        fi

        local ip=""
        if [[ "$remote" =~ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]]; then
            ip="${BASH_REMATCH[1]}"
        else
            continue
        fi

        validate_ip "$ip" || continue

        is_whitelisted_ip "$ip" && continue

        # V52.9: VM'e ait IP - hiçbir zaman değerlendirmeye alma
        is_vm_ip "$ip" && continue

        # V52.9: Daha önce meşru uzak erişim yazılımı olduğu doğrulanmış IP
        [[ -n "${PROTECTED_IP_CACHE[$ip]:-}" ]] && continue

        [[ -n "${BLOCKED_IP_CACHE[$ip]:-}" ]] && continue

        local blocked=false
        for subnet in "${!BLOCKED_SUBNET_CACHE[@]}"; do
            if ip_in_cidr "$ip" "$subnet"; then
                blocked=true
                break
            fi
        done
        [[ "$blocked" == "true" ]] && continue

        local pid=""
        if [[ "$line" =~ pid=([0-9]+) ]]; then
            pid="${BASH_REMATCH[1]}"
        fi

        local proc_name

        proc_name=$(get_process_name "$pid")
        # V52.9: is_legit_remote_process() artık PID de alıp binary yolunu
        # doğruluyor - sadece isim eşleşmesi (spoof edilebilir) yetmiyor.
        # Eşleşirse bu IP kalıcı olarak muaf listesine de ekleniyor, böylece
        # Suricata tarafı da tekrar sorgulamadan doğrudan geçer.
        if is_legit_remote_process "$proc_name" "$pid"; then
            PROTECTED_IP_CACHE["$ip"]="true"
            continue
        fi

        # V52.9: ARTIK APP_WHITELIST eşleşenler (chromium, firefox, systemd,
        # nft, vb.) dashboard'dan TAMAMEN gizlenmiyor - eskiden `continue`
        # ile atlanıyorlardı, yani tarayıcının açtığı onlarca bağlantı
        # dashboard'da hiç görünmüyordu ("script IP'leri çekemiyor" şikayeti
        # buydu). Artık bu bağlantılar YİNE GÖRÜNÜYOR ama "güvenilir" olarak
        # işaretleniyor (SUBNET_TRUSTED) - tehdit değerlendirme döngüsü
        # bunları atlayacak (yanlış pozitif riski yok), ama gözünün önünde
        # duracaklar.
        local is_trusted_app=0
        is_trusted_app_process "$proc_name" "$pid" && is_trusted_app=1

      local subnet

      subnet=$(ip_to_subnet "$ip" "$INITIAL_SUBNET_MASK")
local current_mask="${SUBNET_ESCALATION_LEVEL[$subnet]:-$INITIAL_SUBNET_MASK}"
subnet=$(ip_to_subnet "$ip" "$current_mask")

        if [[ -n "${SUBNET_CONNECTIONS[$subnet]:-}" ]]; then
            SUBNET_CONNECTIONS[$subnet]=$((SUBNET_CONNECTIONS[$subnet] + 1))
            if [[ ",${SUBNET_ALL_IPS[$subnet]:-}," != *",${ip},"* ]]; then
                SUBNET_ALL_IPS[$subnet]="${SUBNET_ALL_IPS[$subnet]},$ip"
            fi
            # V52.9: PID GÜNCELLEME HATASI DÜZELTİLDİ - eskiden bir subnet'e
            # ait İLK bağlantının PID'i (boş bile olsa) kalıcı olarak
            # saklanıyordu, sonraki bağlantılar PID'i düzgün çözse bile
            # güncellenmiyordu ("unknown" olarak takılı kalma sorunu buydu).
            # Artık mevcut PID boşsa ve yeni gelen dolu ise güncelleniyor.
            if [[ -z "${SUBNET_PIDS[$subnet]:-}" ]] && [[ -n "$pid" ]]; then
                SUBNET_PIDS[$subnet]="$pid"
            fi
        else
            SUBNET_CONNECTIONS[$subnet]=1
            SUBNET_PIDS[$subnet]="$pid"
            SUBNET_SAMPLE_IPS[$subnet]="$ip"
            SUBNET_ALL_IPS[$subnet]="$ip"

            if [[ -z "${SUBNET_ESCALATION_LEVEL[$subnet]:-}" ]]; then
                SUBNET_ESCALATION_LEVEL[$subnet]=$INITIAL_SUBNET_MASK
                SUBNET_ESCALATION_COOLDOWN[$subnet]=0
            fi
        fi

        [[ "$is_trusted_app" -eq 1 ]] && SUBNET_TRUSTED[$subnet]="true"

        total=$((total + 1))

    done < <(ss -tunap 2>/dev/null | grep -v '127.0.0.1' | grep -v '::1')

    TOTAL_CONNECTIONS=$total
    UNIQUE_SUBNETS=${#SUBNET_CONNECTIONS[@]}
}

# ==============================================================================
# 12. TEHDİT TESPİT FONKSİYONLARI
# ==============================================================================
# V54: is_trusted_cdn_ip() - DNSLESS_TRUSTED_PREFIXES listesini genel amaçlı
# kullanılabilir hale getiren yardımcı fonksiyon. Eskiden bu liste sadece
# test_dnsless_ip() içinde gömülü kullanılıyordu; artık Suricata Priority 3+
# eşik mantığı da AYNI listeyi kullanıyor - tek bir yerden yönetiliyor.
is_trusted_cdn_ip() {
    local ip="$1"
    for prefix in "${DNSLESS_TRUSTED_PREFIXES[@]}"; do
        [[ "$ip" == "$prefix"* ]] && return 0
    done
    return 1
}

test_dnsless_ip() {
    local ip="$1"
    [[ "$ENABLE_DNSLESS" != "true" ]] && return 1
    validate_ip "$ip" || return 1

    for w in "${DNSLESS_WHITELIST[@]}"; do
        [[ "$ip" == "$w" ]] && return 1
        [[ "$w" == */* ]] && ip_in_cidr "$ip" "$w" && return 1
    done

    for prefix in "${DNSLESS_TRUSTED_PREFIXES[@]}"; do
        [[ "$ip" == "$prefix"* ]] && return 1
    done

    is_local_ip "$ip" && return 1
    [[ -n "${DNS_CACHE[$ip]:-}" ]] && return 1

    # V60: distinguish "query succeeded and PTR is absent" from
    # "the resolver/query itself failed". Only the former is a DNS-less signal.
    local ptr="" query_ok=false rc=1

    if command -v dig &>/dev/null; then
        ptr=$(dig -x "$ip" +short +timeout=2 +tries=1 2>/dev/null)
        rc=$?
        if [[ "$rc" -eq 0 ]]; then
            query_ok=true
            ptr=$(printf '%s\n' "$ptr" | sed '/^[[:space:]]*$/d' | head -1 | sed 's/\.$//')
        fi
    fi

    if [[ "$query_ok" != "true" ]] && command -v nslookup &>/dev/null; then
        local nsout=""
        nsout=$(nslookup -timeout=2 "$ip" 2>/dev/null)
        rc=$?
        if [[ "$rc" -eq 0 ]]; then
            query_ok=true
            ptr=$(printf '%s\n' "$nsout" | awk 'BEGIN{IGNORECASE=1} /name = / {print $NF; exit}' | sed 's/\.$//')
        fi
    fi

    # No successful DNS transaction: fail open for this heuristic, but do not
    # manufacture a "PTR missing" finding from a resolver outage.
    [[ "$query_ok" != "true" ]] && return 1

    [[ -z "$ptr" ]] && return 0
    [[ "$ptr" == "$ip" ]] && return 0
    [[ "$ptr" =~ (unavailable|unknown|not\.found) ]] && return 0

    DNS_CACHE["$ip"]="$ptr"
    return 1
}

test_otx() {
    local ip="$1"
    [[ -z "$ip" ]] && return 1
    [[ "$ENABLE_OTX" != "true" ]] && return 1
    [[ -z "$OTX_API_KEY" ]] && return 1
    [[ -n "${OTX_CACHE[$ip]:-}" ]] && { [[ "${OTX_CACHE[$ip]}" == "true" ]] && return 0 || return 1; }
    [[ $OTX_CACHE_COUNT -ge $OTX_CACHE_SIZE ]] && return 1

    command -v curl &>/dev/null || return 1

    validate_ip "$ip" || return 1
    # V62: API anahtarı komut satırında (ps / /proc/PID/cmdline) görünmesin diye stdin'den config ile verilir.
    local response
    response=$(printf 'header = "X-OTX-API-KEY: %s"\n' "$OTX_API_KEY" | \
        curl -q -s --proto '=https' --connect-timeout 3 -m "${OTX_TIMEOUT:-5}" -K - \
        "https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/general" 2>/dev/null)

    if [[ -z "$response" ]] || ! echo "$response" | jq empty &>/dev/null; then
        OTX_CACHE["$ip"]="false"
        OTX_CACHE_COUNT=$((OTX_CACHE_COUNT + 1))
        return 1
    fi

    local pulse_count

    pulse_count=$(echo "$response" | jq -r '.pulse_info.count // 0' 2>/dev/null)
    [[ ! "$pulse_count" =~ ^[0-9]+$ ]] && pulse_count=0

    if [[ $pulse_count -ge $OTX_THRESHOLD ]]; then
        OTX_CACHE["$ip"]="true"
        OTX_CACHE_COUNT=$((OTX_CACHE_COUNT + 1))
        return 0
    else
        OTX_CACHE["$ip"]="false"
        OTX_CACHE_COUNT=$((OTX_CACHE_COUNT + 1))
        return 1
    fi
}


QUARANTINE_DIR="/var/log/satsuma/quarantine"

quarantine_process() {
    local pid="$1"
    local reason="$2"
    [[ -z "$pid" ]] || [[ ! "$pid" =~ ^[0-9]+$ ]] && return 1
    [[ ! -d "/proc/${pid}" ]] && return 1

    local qdir
    satsuma_secure_dir "$QUARANTINE_DIR" || return 1
    qdir=$(mktemp -d "$QUARANTINE_DIR/process-${pid}.XXXXXXXX") || return 1
    cp "/proc/${pid}/exe" "${qdir}/binary" 2>/dev/null || true
    cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ' > "${qdir}/cmdline.txt" 2>/dev/null || true
    cat "/proc/${pid}/status" > "${qdir}/status.txt" 2>/dev/null || true
    ls -la "/proc/${pid}/fd" > "${qdir}/open_fds.txt" 2>/dev/null || true
    cat "/proc/${pid}/maps" > "${qdir}/maps.txt" 2>/dev/null || true
    readlink -f "/proc/${pid}/cwd" > "${qdir}/cwd.txt" 2>/dev/null || true
    echo "$reason" > "${qdir}/reason.txt" 2>/dev/null || true

    add_activity_log "${C_YELLOW}[KANIT]${C_RESET} PID $pid kanıtı kaydedildi: $qdir"
    echo "$qdir"
    return 0
}

test_rootkit_indicators() {
    local process_name="$1"
    local pid="$2"
    [[ "$ENABLE_ROOTKIT_CHECK" != "true" ]] && return 1
    [[ -z "$pid" ]] || [[ "$pid" -eq 0 ]] && return 1

    # V60: whitelist names are hints only. Exempt only when the executable
    # path is independently verifiable and not transient/user-writable.
    local whitelist_name_match=false
    for app in "${APP_WHITELIST[@]}"; do
        if [[ "$process_name" == *"$app"* ]]; then
            whitelist_name_match=true
            break
        fi
    done
    if [[ "$whitelist_name_match" == "true" ]] && ! is_process_path_suspicious "$pid"; then
        return 1
    fi

    for rp in "${ROOTKIT_PROCESSES[@]}"; do
        local matched=false

        # V52.9: Kısa/genel isimler (nc, bind, reverse, john) SADECE tam
        # eşleşmede tetiklenir. Diğerleri (meterpreter, cobaltstrike, vb.)
        # yine substring ile aranır çünkü bunlar kendine has isimlerdir.
        local is_exact_only=false
        for eo in "${ROOTKIT_EXACT_ONLY[@]}"; do
            [[ "$rp" == "$eo" ]] && is_exact_only=true && break
        done

        if [[ "$is_exact_only" == "true" ]]; then
            [[ "$process_name" == "$rp" ]] && matched=true
        else
            [[ "$process_name" == "$rp" ]] || [[ "$process_name" == *"$rp"* ]] && matched=true
        fi

        if [[ "$matched" == "true" ]]; then
            local cmdline=""
            [[ -f "/proc/${pid}/cmdline" ]] && cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ')

            # V52.9: Öldürmeden önce kanıtı sakla - araştırma için gerekli.
            quarantine_process "$pid" "Rootkit imza eşleşmesi: $rp ($process_name)" >/dev/null 2>&1

            if [[ -n "$cmdline" ]] && ([[ "$cmdline" =~ /tmp/ ]] || [[ "$cmdline" =~ /dev/shm/ ]] || [[ "$cmdline" =~ /var/tmp/ ]]); then
                ROOTKIT_DETECTIONS=$((ROOTKIT_DETECTIONS + 1))
                return 0
            fi
            ROOTKIT_DETECTIONS=$((ROOTKIT_DETECTIONS + 1))
            return 0
        fi
    done
    return 1
}

calculate_anomaly_score() {
    local process_name="$1"
    local connections="$2"
    local pid="$3"
    local score=0

    if [[ $connections -gt 20 ]]; then
        score=$((score + 30))
    elif [[ $connections -gt 10 ]]; then
        score=$((score + 20))
    elif [[ $connections -gt 5 ]]; then
        score=$((score + 10))
    fi

    local known=0
    local name_matched=0
    for app in "${APP_WHITELIST[@]}"; do
        if [[ "$process_name" == *"$app"* ]]; then
            name_matched=1
            break
        fi
    done

    if [[ "$name_matched" -eq 1 ]]; then
        if [[ -n "$pid" ]] && ! is_process_path_suspicious "$pid"; then
            known=1
        else
            # Familiar name with an unverifiable/transient executable is not trusted.
            score=$((score + 15))
        fi
    fi

    if [[ $known -eq 0 ]]; then
        score=$((score + 20))
    fi

    if [[ -f "/proc/${pid}/cmdline" ]]; then
        local cmdline
        cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ')
        if [[ "$cmdline" =~ /tmp/ ]] || [[ "$cmdline" =~ /dev/shm/ ]]; then
            score=$((score + 25))
        fi
    fi

    ANOMALY_SCORES["$process_name"]=$score

    if [[ $score -gt 70 ]]; then
        ANOMALY_DETECTIONS=$((ANOMALY_DETECTIONS + 1))
        add_activity_log "${C_RED}[ANOMALI]${C_RESET} $process_name (PID:$pid) - Skor:$score"
        echo "$(date -Iseconds) | $process_name | $pid | $score" >> "$ANOMALY_LOG" 2>/dev/null || true
        return 0
    fi

    return 1
  }


process_proto_anomaly_events() {
    [[ "$ENABLE_PROTO_ANOMALY" != "true" ]] && return 0
    [[ ! -f "$SURICATA_LOG" ]] && return 0

    # V54: Zeek'in notice.log'u yerine, Suricata'nın AYNI eve.json'undaki
    # "anomaly" event tipi okunuyor. Suricata zaten alert taraması için
    # tail ediliyor - burada da aynı dosya, ayrı bir byte-offset ile takip
    # ediliyor (process_suricata_alerts'ın kendi offset'iyle çakışmaz).
    local current_inode current_lines last_inode=0 last_line=0
    current_inode=$(stat -c '%i' "$SURICATA_LOG" 2>/dev/null || echo 0)
    current_lines=$(wc -l < "$SURICATA_LOG" 2>/dev/null || echo 0)
    if [[ -f "$ANOMALY_OFFSET_FILE" ]]; then
        read -r last_inode last_line < "$ANOMALY_OFFSET_FILE" 2>/dev/null || true
    fi
    [[ "$last_inode" =~ ^[0-9]+$ ]] || last_inode=0
    [[ "$last_line" =~ ^[0-9]+$ ]] || last_line=0

    [[ "$current_inode" != "$last_inode" || "$current_lines" -lt "$last_line" ]] && last_line=0
    [[ "$current_lines" -le "$last_line" ]] && return 0

    tail -n $((current_lines - last_line)) "$SURICATA_LOG" 2>/dev/null | \
        jq -c 'select(.event_type=="anomaly")' 2>/dev/null | \
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local src atype aevent
        src=$(jq -r '.src_ip // empty' <<< "$line" 2>/dev/null)
        atype=$(jq -r '.anomaly.type // "unknown"' <<< "$line" 2>/dev/null)
        aevent=$(jq -r '.anomaly.event // .anomaly.reason // "anomali"' <<< "$line" 2>/dev/null)
        if [[ -n "$src" ]]; then
            PROTO_ANOMALY_COUNT=$((PROTO_ANOMALY_COUNT + 1))
            echo "$(date -Iseconds) | $src | $atype | $aevent" >> "$PROTO_ANOMALY_LOG" 2>/dev/null || true
            add_activity_log "${C_CYAN}[ANOMALİ]${C_RESET} $src - $atype: ${aevent:0:60}"
            PROTO_ANOMALY_ALERTS=("${C_CYAN}$src - $atype: ${aevent:0:40}${C_RESET}" "${PROTO_ANOMALY_ALERTS[@]:0:$ANOMALY_MAX_ALERTS}")
        fi
    done
    LAST_PROTO_ANOMALY_SCAN=$(date +%s)
    echo "$current_inode $current_lines" > "$ANOMALY_OFFSET_FILE" 2>/dev/null || true
}

# ==============================================================================
# 12b. EK GÜVENLİK KATMANI FONKSİYONLARI (V52.9)
# ==============================================================================

# AIDE: dosya bütünlük kontrolü. Değişen/eklenen dosyaları activity log'a
# ve AIDE_LOG'a yazar. Kripto virüsün toplu dosya değiştirme/oluşturma
# davranışını yakalamak için tasarlandı.
# V52.9: run_aide_check ve run_rkhunter_check artık arka planda (&) çağrılıyor.
# Bash'te "fonksiyon &" AYRI BİR SUBSHELL'de çalışır - içindeki değişken
# atamaları (AIDE_ALERTS=... gibi) ana script'e ASLA geri dönmez. Eskiden
# bu yüzden AIDE/RKHunter gerçek tehdit bulsa bile dashboard sayaçları hiç
# artmıyordu. Çözüm: subshell sonucu bir dosyaya yazıyor, ana döngü (fore-
# ground) her taramada bu dosyayı okuyup GERÇEK global değişkenleri güncel-
# liyor (collect_aide_result / collect_rkhunter_result).
AIDE_RESULT_FILE="$SATSUMA_RUN_DIR/aide_result"
AIDE_LOCK_FILE="$SATSUMA_RUN_DIR/aide.lock"
RKHUNTER_RESULT_FILE="$SATSUMA_RUN_DIR/rkhunter_result"
RKHUNTER_LOCK_FILE="$SATSUMA_RUN_DIR/rkhunter.lock"

# Satsuma's own narrow AIDE profile for live sessions. Files Satsuma itself
# rewrites while it runs are excluded, so its own work never raises an alarm.
# Canlı oturum için dar AIDE profili; Satsuma'nın çalışırken yazdığı dosyalar hariç.
# Two versions in one script (user request 2026-11-11): on a live session the
# AIDE rule of 2026-11-10 applies (a difference stops setup); on an installed
# system a difference is an alarm, protections keep running and the earlier
# reference is kept until the user approves it (satsuma-aide onayla).
# Tek betikte iki sürüm (kullanıcı isteği 2026-11-11): canlı oturumda
# 2026-11-10 AIDE kuralı geçerlidir (fark kurulumu durdurur); kurulu sistemde
# fark alarmdır, korumalar çalışmaya devam eder ve önceki örnek kullanıcı
# onaylayana kadar korunur (satsuma-aide onayla).
satsuma_install_mode() {
    case "${SATSUMA_MODE:-}" in
        live|kurulu) echo "$SATSUMA_MODE"; return 0 ;;
    esac
    if [[ -d /run/initramfs/live || -d /run/live/medium ]] ||
       grep -qwE 'rd\.live\.image|boot=live' /proc/cmdline 2>/dev/null; then
        echo live
    else
        echo kurulu
    fi
}

satsuma_aide_record_difference() {
    local report="$1" rc="$2" stamp dir="/var/log/satsuma/aide-fark" file
    stamp=$(date +%Y%m%d-%H%M%S)
    install -d -m 0700 -o root -g root "$dir" || return 1
    file="$dir/fark-$stamp.txt"
    ( umask 077; printf '%s\n' "$report" > "$file" ) || return 1
    ( umask 077; printf '%s\n' "$file" > "$AIDE_DIR/onay-bekliyor" ) || return 1
    printf '%s\n' "$report" | tail -n 40 >&2
    echo "ALARM: AIDE - sistem onaylı örnekten farklı (kod $rc). Korumalar çalışmaya devam ediyor." >&2
    echo "Tam rapor: $file | İncelemek: satsuma-aide | İnceleyip onaylamak: satsuma-aide onayla" >&2
    echo "Önceki örnek siz onaylayana kadar değiştirilmez." >&2
}

satsuma_aide_live_config() {
    install -d -m 0700 -o root -g root "$AIDE_DIR" || return 1
    local staged="$AIDE_CONF.tmp" path
    {
        echo "# Satsuma Mini live-session AIDE profile. Generated; do not edit."
        echo "database_in=file:$AIDE_DB"
        echo "database_out=file:$AIDE_DB_NEW"
        echo "gzip_dbout=yes"
        echo "SATSUMA_LIVE = p+u+g+n+s+m+c+i+sha256"
        echo '!/etc/nftables\.conf$'
        echo '!/etc/aide\.conf$'
        echo '!/etc/mtab$'
        echo '!/etc/adjtime$'
        echo '!/etc/ld\.so\.cache$'
        for path in "${AIDE_WATCH[@]}"; do
            echo "$path SATSUMA_LIVE"
        done
    } > "$staged" || return 1
    chmod 0600 "$staged" && mv -f -- "$staged" "$AIDE_CONF" || return 1
    aide --config "$AIDE_CONF" --config-check >/dev/null || { echo "AIDE profili geçersiz: $AIDE_CONF" >&2; return 1; }
}

# Take the live-session reference, or confirm an earlier one of this session.
# An earlier reference is never silently reused or overwritten: if the machine
# differs from it, setup stops and shows the difference.
# Canlı oturum referansını alır ya da bu oturumdaki öncekini doğrular; fark
# varsa kurulum durur ve farkı gösterir, önceki referansın üzerine yazılmaz.
satsuma_aide_live_init() {
    command -v aide >/dev/null || { echo "AIDE kurulu değil" >&2; return 1; }
    satsuma_aide_live_config || return 1
    if [[ -s "$AIDE_DB" ]]; then
        local report rc
        report=$(aide --config "$AIDE_CONF" --check 2>&1); rc=$?
        if (( rc == 0 )); then
            echo -e " ${C_GREEN}[✓] AIDE: bu oturumun örneği var ve sistem onunla aynı${C_RESET}"
            return 0
        fi
        if [[ "$(satsuma_install_mode)" == kurulu ]]; then
            satsuma_aide_record_difference "$report" "$rc" || return 1
            return 0
        fi
        printf '%s\n' "$report" | tail -n 40 >&2
        echo "AIDE: sistem bu oturumun önceki örneğinden farklı (kod $rc). Önce farkı inceleyin;" >&2
        echo "yeni örnek için bilerek silin: sudo rm $AIDE_DB" >&2
        return 1
    fi
    echo -e " ${C_YELLOW}[*] AIDE örneği alınıyor: yalnızca ${AIDE_WATCH[*]}${C_RESET}"
    rm -f -- "$AIDE_DB_NEW"
    aide --config "$AIDE_CONF" --init > /var/log/satsuma/aide-init.log 2>&1 &
    local aide_init_pid=$!
    while kill -0 "$aide_init_pid" 2>/dev/null; do
        echo "AIDE örneği hazırlanıyor; ayrıntılar /var/log/satsuma/aide-init.log"
        sleep 5
    done
    wait "$aide_init_pid" || { tail -n 25 /var/log/satsuma/aide-init.log; return 1; }
    [[ -s "$AIDE_DB_NEW" ]] && mv -f -- "$AIDE_DB_NEW" "$AIDE_DB" && chmod 0600 "$AIDE_DB" || return 1
    restorecon -R "$AIDE_DIR" >/dev/null 2>&1 || true
    echo -e " ${C_GREEN}[✓] AIDE örneği hazır (kurulumun son durumu; önceden temiz olduğunu kanıtlamaz)${C_RESET}"
}

run_aide_check() {
    [[ "$ENABLE_AIDE" != "true" ]] && return 0
    command -v aide &>/dev/null || return 0
    [[ ! -f "$AIDE_DB" ]] && return 0
    satsuma_lock_active "$AIDE_LOCK_FILE" && return 0   # önceki tarama hâlâ sürüyor, üst üste binme

    touch "$AIDE_LOCK_FILE" 2>/dev/null || true

    local output
    output=$(aide --config "$AIDE_CONF" --check 2>/dev/null)
    local changed
    changed=$(echo "$output" | grep -cE '^(File|Directory|added|removed|changed)' 2>/dev/null || echo 0)
    [[ "$changed" =~ ^[0-9]+$ ]] || changed=0

    {
        echo "=== $(date -Iseconds) ==="
        echo "$output"
    } >> "$AIDE_LOG" 2>/dev/null || true

    echo "CHANGED=${changed}" > "$AIDE_RESULT_FILE" 2>/dev/null || true
    rm -f "$AIDE_LOCK_FILE" 2>/dev/null || true
    return 0
}

# Ana döngüde (foreground) her taramada çağrılır - ucuz bir dosya kontrolü.
# run_aide_check'in arka planda bıraktığı sonucu asıl global sayaçlara işler.
collect_aide_result() {
    [[ -f "$AIDE_RESULT_FILE" ]] || return 0

    local changed
    changed=$(grep -oP 'CHANGED=\K[0-9]+' "$AIDE_RESULT_FILE" 2>/dev/null)
    rm -f "$AIDE_RESULT_FILE" 2>/dev/null || true
    [[ "$changed" =~ ^[0-9]+$ ]] || return 0

    LAST_AIDE_CHECK=$(date +%s)

    if [[ "$changed" -gt 0 ]]; then
        AIDE_ALERTS=$((AIDE_ALERTS + changed))
        add_activity_log "${C_RED}[AIDE]${C_RESET} ${changed} dosya değişikliği tespit edildi! Detay: $AIDE_LOG"

        if [[ "$changed" -ge "$RANSOMWARE_BURST_THRESHOLD" ]]; then
            RANSOMWARE_BURST_DETECTED=true
            add_activity_log "${C_BG_RED}${C_WHITE}[RANSOMWARE-ALARM]${C_RESET} ${changed} dosya AYNI ANDA değişti! Aktif şifreleme şüphesi!"
            send_critical_alert "SATSUMA ACİL: ${changed} dosya aynı anda değişti - aktif ransomware/şifreleme şüphesi! Hemen kontrol et."
        fi
    fi
    return 0
}

# rkhunter + chkrootkit: host seviyesi rootkit taraması.
run_rkhunter_check() {
    [[ "$ENABLE_RKHUNTER" != "true" ]] && return 0
    satsuma_lock_active "$RKHUNTER_LOCK_FILE" && return 0

    # V60: private temporary evidence file; preserve stdout and stderr verbatim.
    local tmp_out
    tmp_out=$(mktemp /tmp/.satsuma_rkhunter_out.XXXXXX) || return 1
    chmod 600 "$tmp_out" 2>/dev/null || true
    : > "$RKHUNTER_LOCK_FILE" 2>/dev/null || { rm -f "$tmp_out"; return 1; }

    {
        echo "=== $(date -Iseconds) ==="
        if command -v rkhunter &>/dev/null; then
            echo "--- rkhunter stdout+stderr ---"
            rkhunter --check --skip-keypress --report-warnings-only 2>&1
            echo "--- rkhunter rc=$? ---"
        fi
        if command -v chkrootkit &>/dev/null; then
            echo "--- chkrootkit stdout+stderr ---"
            chkrootkit 2>&1
            echo "--- chkrootkit rc=$? ---"
        fi
    } > "$tmp_out"

    local warnings
    warnings=$(grep -icE "warning|infected|suspicious|possible" "$tmp_out" 2>/dev/null || echo 0)
    [[ "$warnings" =~ ^[0-9]+$ ]] || warnings=0

    cat "$tmp_out" >> "$RKHUNTER_LOG" 2>/dev/null || true
    rm -f "$tmp_out" 2>/dev/null || true

    echo "WARNINGS=${warnings}" > "$RKHUNTER_RESULT_FILE" 2>/dev/null || true
    rm -f "$RKHUNTER_LOCK_FILE" 2>/dev/null || true
    return 0
}

collect_rkhunter_result() {
    [[ -f "$RKHUNTER_RESULT_FILE" ]] || return 0

    local warnings
    warnings=$(grep -oP 'WARNINGS=\K[0-9]+' "$RKHUNTER_RESULT_FILE" 2>/dev/null)
    rm -f "$RKHUNTER_RESULT_FILE" 2>/dev/null || true
    [[ "$warnings" =~ ^[0-9]+$ ]] || return 0

    LAST_RKHUNTER_CHECK=$(date +%s)

    if [[ "$warnings" -gt 0 ]]; then
        RKHUNTER_ALERTS=$((RKHUNTER_ALERTS + warnings))
        add_activity_log "${C_RED}[RKHUNTER]${C_RESET} ${warnings} uyarı tespit edildi! Detay: $RKHUNTER_LOG"
    fi
    return 0
}

# auditd: kritik dosya/exec olaylarını satır bazlı takip eder (Suricata'nın
# eve.json offset mantığıyla aynı yaklaşım - sadece yeni satırları okur).
check_audit_events() {
    [[ "$ENABLE_AUDITD" == true ]] || return 0
    local summary rc unique events critical
    summary=$(satsuma_audit_poll --threshold "$HOME_WRITE_BURST_THRESHOLD" --window 60)
    rc=$?
    [[ -n "$summary" ]] || { add_activity_log "[AUDIT-HATA] Özet alınamadı"; return 1; }
    printf '%s\n' "$summary" >> "$AUDITD_ALERT_LOG"
    if (( rc != 0 )); then
        add_activity_log "[AUDIT-EKSIK] Log aralığı tam değerlendirilemedi; temiz sonuç üretilmedi."
        return "$rc"
    fi
    unique=$(jq -r '.home_unique_paths // 0' <<< "$summary")
    events=$(jq -r '.home_events_in_window // 0' <<< "$summary")
    critical=$(jq -r '[.critical[] | .successful_events + .failed_events] | add // 0' <<< "$summary")
    if [[ "$critical" =~ ^[0-9]+$ ]] && (( critical>0 )); then
        add_activity_log "[AUDIT] Kritik izleme anahtarlarında $critical işlem kaydı; günlükte ayrıntılar var."
    fi
    if jq -e '.threshold_exceeded == true' >/dev/null <<< "$summary"; then
        add_activity_log "[AUDIT-YOGUNLUK] Son 60 saniyede $unique farklı /home yolu, $events başarılı işlem kaydı. İçerik değişikliği veya zararlı yazılım kanıtı değildir."
    fi
}

# V55.4: Suricata canlılık kontrolü + self-heal. Her ~10 dakikada bir
# (SURICATA_HEALTH_CHECK_INTERVAL) ana döngüden çağrılır. Servis düşmüşse
# önce stop+start ile kendini onarmayı dener; bu da işe yaramazsa
# add_activity_log ile açıkça haber verir (script kendi kendine sessizce
# vazgeçmez).
check_suricata_health() {
    [[ "$ENABLE_SURICATA" == true ]] || return 0
    if satsuma_verify_ips "$SURICATA_NFQUEUE_NUM" > "$SATSUMA_RUN_DIR/ips-health.json" 2>&1; then
        LAST_SURICATA_HEALTH_OK=$(date +%s)
        return 0
    fi
    add_activity_log "[IPS-HATA] Servis/queue/firewall doğrulaması başarısız; yerel raporu kontrol edin."
    systemctl restart suricata || return 1
    sleep 3
    satsuma_verify_ips "$SURICATA_NFQUEUE_NUM" || return 1
    LAST_SURICATA_HEALTH_OK=$(date +%s)
}

# ==============================================================================
# 12c. MITM / DNS ZEHİRLENMESİ TESPİT FONKSİYONLARI (V52.9)
# ==============================================================================

# Gateway'in ARP/MAC adresini izler. Bir saldırgan ARP spoofing ile trafiği
# kendi üzerinden geçiriyorsa, gateway IP'sinin MAC adresi normalde SABİT
# kalması gereken bir şey iken aniden değişir. Bu klasik ve çok güvenilir
# bir MITM belirtisidir.
check_gateway_arp() {
    [[ "$ENABLE_ARP_WATCH" != "true" ]] && return 0
    command -v ip &>/dev/null || return 0

    local gw_ip
    gw_ip=$(ip route | grep default | awk '{print $3}' | head -1)
    [[ -z "$gw_ip" ]] && return 0

    # ARP tablosunu güncel tut
    ping -c1 -W1 "$gw_ip" &>/dev/null || true

    local current_mac
    current_mac=$(ip neigh show "$gw_ip" 2>/dev/null | awk '{print $5}' | head -1)
    [[ -z "$current_mac" ]] && return 0

    if [[ -f "$GATEWAY_MAC_FILE" ]]; then
        local known_mac
        known_mac=$(cat "$GATEWAY_MAC_FILE" 2>/dev/null)

        if [[ -n "$known_mac" ]] && [[ "$known_mac" != "$current_mac" ]]; then
            ARP_MISMATCH_COUNT=$((ARP_MISMATCH_COUNT + 1))
            {
                echo "$(date -Iseconds) | GATEWAY: $gw_ip | ESKİ MAC: $known_mac | YENİ MAC: $current_mac"
            } >> "$ARP_MISMATCH_LOG" 2>/dev/null || true

            add_activity_log "${C_BG_RED}${C_WHITE}[ARP-MITM]${C_RESET} Gateway MAC değişti! $known_mac -> $current_mac - MITM ŞÜPHESİ"
            send_critical_alert "SATSUMA: Gateway MAC adresi değişti ($gw_ip): $known_mac -> $current_mac. MITM saldırısı olabilir!"

            # Yeni MAC'i kaydet ki her taramada tekrar tekrar alarm vermesin,
            # ama olay log'a düştü, geriye dönüp incelenebilir.
            echo "$current_mac" > "$GATEWAY_MAC_FILE" 2>/dev/null || true
        fi
    else
        # İlk çalışma: mevcut MAC'i güvenilir kabul et (baseline)
        echo "$current_mac" > "$GATEWAY_MAC_FILE" 2>/dev/null || true
        add_activity_log "${C_CYAN}[ARP]${C_RESET} Gateway MAC baseline kaydedildi: $current_mac"
    fi

    return 0
}

# Aynı domaini hem sistemin kendi DNS'inden hem de güvenilir, bağımsız bir
# dış resolver'dan (1.1.1.1, 9.9.9.9) sorgular. İki sonuç taban tabana zıtsa
# (ve aynı /24 veya bilinen CDN aralığında değilse) DNS zehirlenmesi/yönlen-
# dirme şüphesi olarak işaretler. Not: Büyük servisler CDN kullandığı için
# IP'lerin BİREBİR aynı olması beklenmez; burada asıl aranan şey sistemin
# döndürdüğü IP'nin dış resolver'ların döndürdüğü IP AİLESİYLE (ilk 2 oktet)
# hiç örtüşmemesi - bu çok daha güvenilir bir sinyal.
check_dns_consistency() {
    [[ "$ENABLE_DNS_CONSISTENCY" != "true" ]] && return 0
    command -v dig &>/dev/null || return 0

    for domain in "${DNS_CANARY_DOMAINS[@]}"; do
        local system_ip=""
        system_ip=$(dig +short +timeout=2 +tries=1 "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
        [[ -z "$system_ip" ]] && continue

        local mismatch_all=true
        local trusted_sample=""

        for resolver in "${TRUSTED_RESOLVERS[@]}"; do
            local trusted_ip=""
            trusted_ip=$(dig +short +timeout=2 +tries=1 "@${resolver}" "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
            [[ -z "$trusted_ip" ]] && continue
            [[ -z "$trusted_sample" ]] && trusted_sample="$trusted_ip"

            # İlk iki oktet örtüşüyorsa aynı CDN/sağlayıcı ağı kabul edilir
            local sys_prefix trusted_prefix
            sys_prefix=$(echo "$system_ip" | cut -d. -f1,2)
            trusted_prefix=$(echo "$trusted_ip" | cut -d. -f1,2)

            if [[ "$system_ip" == "$trusted_ip" ]] || [[ "$sys_prefix" == "$trusted_prefix" ]]; then
                mismatch_all=false
                break
            fi
        done

        if [[ "$mismatch_all" == "true" ]] && [[ -n "$trusted_sample" ]]; then
            DNS_MISMATCH_COUNT=$((DNS_MISMATCH_COUNT + 1))
            {
                echo "$(date -Iseconds) | DOMAIN: $domain | SISTEM: $system_ip | GÜVENİLİR(${TRUSTED_RESOLVERS[0]}): $trusted_sample"
            } >> "$DNS_MISMATCH_LOG" 2>/dev/null || true

            add_activity_log "${C_BG_RED}${C_WHITE}[DNS-ZEHIR]${C_RESET} $domain: sistem=$system_ip, güvenilir=$trusted_sample - UYUŞMUYOR"
            send_critical_alert "SATSUMA: DNS tutarsızlığı - $domain sistemde $system_ip, güvenilir resolver'da $trusted_sample. DNS zehirlenmesi şüphesi!"
        fi
    done

    return 0
}

# resolv.conf ve hosts dosyasını immutable (değiştirilemez) yapar. Birçok
# MITM/DNS hijack aracı bu dosyaları sessizce üzerine yazar; chattr +i bunu
# root bile olsa (önce chattr -i çalıştırmadan) engeller.
lock_dns_files() {
    [[ "$ENABLE_RESOLV_LOCK" != "true" ]] && return 0
    command -v chattr &>/dev/null || return 0

    for f in /etc/resolv.conf /etc/hosts; do
        [[ -f "$f" ]] || continue
        chattr +i "$f" 2>/dev/null || true
    done
    return 0
}

# Opsiyonel dış bildirim (webhook). Kritik bir olay (ransomware burst,
# ARP/DNS MITM) tespit edildiğinde, lokal ekranı göremeyeceğin bir durumda
# bile telefonuna/Discord'a haber gitsin diye.
send_critical_alert() {
    # Webhook removed. The caller already records each alarm locally.
    return 0
}

# ==============================================================================
# 13. DASHBOARD
# ==============================================================================
render_dashboard() {
    # As a service there is no screen: a full frame every SCAN_INTERVAL would only
    # flood the journal. The live view is satsuma-dashboard.
    # Serviste ekran yoktur: her SCAN_INTERVAL'da tam bir kare yalnızca journal'ı
    # doldurur. Canlı görünüm satsuma-dashboard'dur.
    [[ -t 1 ]] || return 0
    # Original colored event stream + connection table. Scanner data comes
    # from its persistent JSON files; no CPU/RAM/disk polling.
    local connections_json events_json alerts_json payload
    local subnet pid proc sample count n=0 trusted
    connections_json=$(
        for subnet in "${!SUBNET_CONNECTIONS[@]}"; do
            (( n >= 100 )) && break
            pid="${SUBNET_PIDS[$subnet]:-}"
            proc="$(get_process_name "$pid" 2>/dev/null)"
            [[ -n "$proc" ]] || proc="unknown"
            sample="${SUBNET_SAMPLE_IPS[$subnet]:-}"
            [[ -n "$sample" ]] || sample="${SUBNET_ALL_IPS[$subnet]:-}"
            sample="${sample%%,*}"
            count="${SUBNET_CONNECTIONS[$subnet]:-0}"
            trusted=false
            [[ -n "${SUBNET_TRUSTED[$subnet]:-}" ]] && trusted=true
            printf '%s\t%s\t%s\t%s\t%s\n' "$sample" "$subnet" "$count" "$proc" "$trusted"
            n=$((n + 1))
        done | jq -Rsc 'split("\n") | map(select(length > 0) | split("\t") |
            {ip: .[0], subnet: .[1], count: (.[2] | tonumber? // 0),
             process: .[3], trusted: (.[4] == "true")})'
    )
    # Preserve the original activity messages and their ANSI colors.
    events_json=$(printf '%s\n' "${ACTIVITY_LOGS[@]}" |
        jq -Rsc 'split("\n") | map(select(length > 0)) | .[:100]')
    alerts_json=$(printf '%s\n' "${SURICATA_ALERTS[@]}" "${PROTO_ANOMALY_ALERTS[@]}" |
        jq -Rsc 'split("\n") | map(select(length > 0)) | .[:12]')
    payload=$(jq -nc \
        --arg host "$(hostname)" \
        --arg ip "$(ip -4 addr show "$WAN_INTERFACE" 2>/dev/null | awk '/inet / {split($2,a,"/");print a[1];exit}')" \
        --arg wan "$WAN_INTERFACE" \
        --argjson connections "$connections_json" \
        --argjson events "$events_json" --argjson alerts "$alerts_json" \
        --argjson total "${TOTAL_BLOCKS:-0}" \
        --argjson suricata "${SURICATA_BLOCKS:-0}" \
        --argjson otx "${OTX_BLOCKS:-0}" \
        --argjson dnsless "${DNSLESS_BLOCKS:-0}" \
        --argjson anomaly "${ANOMALY_DETECTIONS:-0}" \
        --argjson connection_count "${TOTAL_CONNECTIONS:-0}" \
        --argjson connection_groups "${UNIQUE_SUBNETS:-0}" \
        --arg queue "$(awk '$1 == 0 {found=1} END {print found+0}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null)" \
        --arg suricata_state "$(systemctl is-active suricata 2>/dev/null || true)" \
        --arg scanner_state "$(systemctl is-active satsuma-file-scan 2>/dev/null || true)" \
        '{host:$host, ip:$ip, wan:$wan, connections:$connections, events:$events,
          alerts:$alerts, connection_count:$connection_count,
          connection_groups:$connection_groups, queue:($queue == "1"),
          blocks:{total:$total,suricata:$suricata,otx:$otx,dnsless:$dnsless,anomaly:$anomaly},
          services:{suricata:$suricata_state,"satsuma-file-scan":$scanner_state}}') || return 1
    [[ -t 1 ]] && printf '\033[H\033[2J'
    SATSUMA_SCREEN_DATA="$payload" satsuma_file_guard screen
}

# ==============================================================================
# 14. SİSTEM KURULUMU
# ==============================================================================
auto_setup_wizard() {
    [[ -t 1 ]] && clear
    # The scan holds the ClamAV lock for its whole cycle; the clamd configuration
    # step below waits only 30 s for it (field run 2026-11-11: setup stopped with
    # "Scanner/configuration busy"). Pause it here; it is started again below
    # and, if setup fails, at the call site.
    # Tarama, döngüsü boyunca ClamAV kilidini tutar; aşağıdaki clamd yapılandırma
    # adımı yalnızca 30 sn bekler (saha çalışması 2026-11-11: kurulum "Scanner/
    # configuration busy" ile durdu). Burada duraklatılır; aşağıda, kurulum
    # başarısız olursa da çağrıldığı yerde yeniden başlatılır.
    if systemctl is-active --quiet satsuma-file-scan.service 2>/dev/null; then
        SATSUMA_FILE_SCAN_PAUSED=1
        systemctl stop satsuma-file-scan.service || return 1
    fi
    echo -e "${C_CYAN}====================================================================================${C_RESET}"
    echo -e "${C_CYAN}${C_BG_RED}${C_WHITE}${C_BOLD}         🛡️ SATSUMA OMNI-SENTINEL V62                    ${C_RESET}${C_CYAN}"
    echo -e "${C_CYAN}====================================================================================${C_RESET}"

    echo -e " ${C_YELLOW}[*] Resmi depo paketleri ve motor imzaları kurulup yapılandırılıyor...${C_RESET}"
    echo -e " ${C_RED}[!] SSH/SSHD, CUPS, Avahi, Samba ve NFS servisleri (varsa) durdurulup maskelenecek.${C_RESET}"
    echo -e " ${C_GREEN}[!] Suricata NFQUEUE IPS AKTİF EDİLECEK!${C_RESET}"
    echo -e " ${C_GREEN}[!] Doğrulanmış P1/P2/P3 olayları yerel nftables ile işlenecek!${C_RESET}"

    if [[ -n "$OTX_API_KEY" ]]; then
        echo -e " ${C_GREEN}[✓] OTX API Key bulundu!${C_RESET}"
    else
        echo -e " ${C_YELLOW}[!] OTX API Key bulunamadı${C_RESET}"
        ENABLE_OTX=false
    fi

    satsuma_browser_harden --check || return 1
    if command -v getenforce >/dev/null; then
        satsuma_selinux_guard audit || return 1
        if command -v setsebool >/dev/null && command -v restorecon >/dev/null; then
            satsuma_selinux_guard enforce || return 1
        fi
    fi
    satsuma_scanner_packages || return 1
    satsuma_selinux_guard enforce || return 1
    satsuma_platform_config || return 1
    satsuma_report_optional_scanners
    satsuma_scanners_configure || return 1
    detect_network_interfaces || return 1
    # Load only the netfilter modules needed by this endpoint, before locking.
    for cmd in nf_conntrack nfnetlink_queue nft_queue nft_fib_inet wireguard; do
        modprobe "$cmd" || { echo "Gerekli modül yüklenemedi: $cmd" >&2; return 1; }
    done
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        echo -e " ${C_YELLOW}[!] firewalld aktif: nftables kuralları onunla birlikte çalışır; çakışma görürseniz 'systemctl disable --now firewalld' düşünün.${C_RESET}"
    fi

    # V54: Suricata'da "anomaly" event tipini etkinleştir (Zeek'in yerini
    # tutan process_proto_anomaly_events() için gerekli). Zaten etkinse
    # dokunma, değilse "- alert" satırından hemen sonra ekle.
    if [[ "$ENABLE_PROTO_ANOMALY" == "true" ]] && [[ -f "$SURICATA_YAML" ]]; then
        if ! grep -qE '^\s*-\s*anomaly\b' "$SURICATA_YAML" 2>/dev/null; then
            cp "$SURICATA_YAML" "${SURICATA_YAML}.satsuma.bak" 2>/dev/null || true
            sed -i '0,/^\s*-\s*alert\s*$/s//&\n      - anomaly/' "$SURICATA_YAML" 2>/dev/null || true
            echo -e " ${C_GREEN}[✓] Suricata'da 'anomaly' event tipi etkinleştirildi${C_RESET}"
            echo -e " ${C_YELLOW}    (etkinleşmezse elle kontrol et: ${SURICATA_YAML}, yedek: ${SURICATA_YAML}.satsuma.bak)${C_RESET}"
        fi
    fi

    satsuma_disable_tor || return 1
    disable_unneeded_local_services
    satsuma_plain_dns || return 1

    mkdir -p /var/log/suricata /var/log/satsuma "$QUARANTINE_DIR"
    touch "$SURICATA_LOG" "$LOG_FILE" "$AUDIT_LOG" 2>/dev/null || true

    init_nftables || return 1

    if command -v suricata &>/dev/null; then
        systemctl enable suricata 2>/dev/null || true
        # V52.9: Eskiden burada sadece "systemctl restart suricata"
        # çalıştırılıyordu - eski/geçersiz arayüz ayarıyla sessizce
        # yeniden başlıyordu, hiç trafik görmüyordu ("hiç tepki
        # vermiyor" sorununun kaynağı). configure_suricata() artık
        # arayüzü günceller, config'i test eder, yeniden başlatır ve
        # eve.json'un gerçekten büyüdüğünü doğrular.
        configure_suricata || return 1
    fi

    # --------------------------------------------------------------------
    # V52.9: AIDE - dosya bütünlük veritabanı ilk kurulum
    # --------------------------------------------------------------------
    # AIDE snapshot is taken last, after every change below (satsuma_aide_live_init).
    # AIDE örneği en son, aşağıdaki bütün değişikliklerden sonra alınır.

    # --------------------------------------------------------------------
    # V52.9: auditd - kernel seviyesi denetim
    # --------------------------------------------------------------------
    if [[ "$ENABLE_AUDITD" == true ]]; then
        satsuma_audit_setup || return 1
    fi

    # --------------------------------------------------------------------
    # V52.9: rkhunter - baseline (mevcut sistemi "temiz" kabul et)
    # --------------------------------------------------------------------
    # V52.9: DNS zehirlenmesine karşı resolv.conf/hosts'u immutable yap
    if [[ "$ENABLE_RESOLV_LOCK" == "true" ]]; then
        lock_dns_files
        echo -e " ${C_GREEN}[✓] /etc/resolv.conf ve /etc/hosts kilitlendi (chattr +i)${C_RESET}"
    fi

    satsuma_file_scanners_initialize || return 1
    satsuma_file_install_hourly || return 1
    satsuma_install_shortcuts || return 1
    satsuma_protection_units_install || return 1
    satsuma_ram35_setup || return 1
    systemctl start satsuma-memory-hardening.service || return 1
    satsuma_browser_harden || return 1
    clamdscan --config-file "$SATSUMA_CLAMD_CONF" --ping 1 || return 1
    satsuma_file_guard memory-scan --wait || { echo "Bellek dosyası taraması eksik; modül kilidi uygulanmadı." >&2; return 1; }
    satsuma_file_guard browser-audit || { echo "Tarayıcı güvenlik denetimi geçmedi; modül kilidi uygulanmadı." >&2; return 1; }
    satsuma_verify_ips "$SURICATA_NFQUEUE_NUM" || return 1
    if [[ "$ENABLE_RKHUNTER" == true ]]; then
        command -v rkhunter >/dev/null && command -v chkrootkit >/dev/null || return 1
    fi
    if [[ "$ENABLE_AUDITD" == true ]]; then
        systemctl is-active --quiet auditd || return 1
        auditctl -s | awk '$1=="enabled" && ($2==1 || $2==2) {ok=1} END {exit !ok}' || return 1
        auditctl -l | grep -q satsuma_identity || return 1
    fi
    systemctl start satsuma-memory-watch.service || return 1
    systemctl is-active --quiet satsuma-memory-watch.service || return 1
    echo "RAM35 izleyicisi başlatıldı; kapsama/erişim durumu --memory35-status ile okunur."
    # The unit allows 2 starts per hour; setup retries and the pause above count
    # as starts (field run 2026-11-11: start-limit-hit, unit "failed").
    # Birim saatte 2 başlatmaya izin verir; kurulum denemeleri ve yukarıdaki
    # duraklatma da sayılır (saha çalışması 2026-11-11: start-limit-hit, "failed").
    systemctl reset-failed satsuma-file-scan.service 2>/dev/null
    systemctl start satsuma-file-scan.service || return 1
    systemctl is-active --quiet satsuma-file-scan.service || return 1
    # Keyboard layout is a convenience, not a protection: a failure here must not
    # keep the network guard, AIDE and the module lock below from being set up
    # (field run 2026-11-11: setup stopped silently at this step as a service).
    # Klavye düzeni bir kolaylıktır, koruma değildir: buradaki hata aşağıdaki ağ
    # korumasını, AIDE'yi ve modül kilidini engellememeli (saha çalışması
    # 2026-11-11: servis olarak kurulum bu adımda sessizce durdu).
    satsuma_keyboard_trq || echo "UYARI: Klavye TR Q ayarlanamadı; kurulum korumalarla devam ediyor." >&2
    satsuma_tmp_harden && satsuma_tmp_install_service || return 1
    satsuma_network_guard enforce-state || return 1
    satsuma_network_install_service || return 1
    # Last change made; only now is the AIDE reference taken (user decision
    # 2026-11-10: a snapshot taken mid-setup would protect a half-configured
    # system and report Satsuma's own work as tampering).
    # Son değişiklik yapıldı; AIDE referansı ancak şimdi alınır.
    if [[ "$ENABLE_AIDE" == true ]]; then
        satsuma_aide_live_init || { echo "AIDE örneği hazır değil; modül kilidi uygulanmadı." >&2; return 1; }
    fi
    [[ "$(getenforce)" == Enforcing ]] || { echo "SELinux enforcing değil; modül kilidi uygulanmadı." >&2; return 1; }
    getsebool domain_can_mmap_files | grep -Eq '^domain_can_mmap_files[[:space:]]+-->[[:space:]]+off$' || return 1
    satsuma_ram35 preflight || return 1
    # Irreversible until reboot. All required modules must be loaded already.
    sysctl -w kernel.modules_disabled=1 || return 1
    [[ "$(cat /proc/sys/kernel/modules_disabled)" == 1 ]] || return 1
    echo "Yerel kontroller geçti; çekirdek modülü yükleme/kaldırma yeniden başlatmaya kadar kapalı."
}
# ==============================================================================
# 15. ANA DÖNGÜ
# ==============================================================================
set +H

SATSUMA_FILE_SCAN_PAUSED=0
auto_setup_wizard || {
    # Setup failed: do not leave the file scan stopped because setup paused it.
    # Kurulum başarısız: kurulumun duraklattığı dosya taraması kapalı bırakılmaz.
    if [[ "$SATSUMA_FILE_SCAN_PAUSED" == 1 ]] && ! systemctl is-active --quiet satsuma-file-scan.service; then
        systemctl reset-failed satsuma-file-scan.service 2>/dev/null
        systemctl start satsuma-file-scan.service || echo "Dosya taraması yeniden başlatılamadı: systemctl start satsuma-file-scan" >&2
    fi
    echo "Kurulum/doğrulama başarısız; ana döngü başlatılmadı." >&2
    exit 1
}
satsuma_file_scanners_initialize || true
satsuma_file_scheduler_start

add_activity_log "${C_RED}[!] MAKSİMUM GÜVENLİK MODU AKTİF${C_RESET}"
add_activity_log "${C_RED}[!] SSH (22) PORTU KAPALI${C_RESET}"
add_activity_log "${C_GREEN}[✓] SURICATA IDS AKTİF${C_RESET}"
add_activity_log "${C_GREEN}[✓] GEÇMİŞ LOGLAR TARANIYOR${C_RESET}"

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    echo -e "\n${C_GREEN}[*] Oturum sonlandırılıyor...${C_RESET}"
    save_persistent_nftables
    echo -e "${C_GREEN}[✓] Temizlik tamamlandı.${C_RESET}"
    set -H
    exit "$rc"   # V62: gerçek çıkış kodunu maskeleme
}

trap cleanup EXIT
trap 'exit 0' INT TERM

while true; do
    SCAN_COUNT=$((SCAN_COUNT + 1))

    process_suricata_alerts
    get_connections

    # ClamAV run on the independent hourly scheduler, not loop counters.
    # Reading the shared status does not block network monitoring.

# Protokol anomali olaylarını işle (her taramada)
process_proto_anomaly_events




    # V52.9: Arka planda biten AIDE/RKHunter sonuçlarını her taramada topla
    # (dosya kontrolü çok ucuz, döngüyü yavaşlatmaz)
    collect_aide_result
    collect_rkhunter_result

    # V52.9: Ek güvenlik katmanları - periyodik, arkaplanda (&), ana döngüyü bloklamaz
    if [[ $((SCAN_COUNT % AIDE_CHECK_INTERVAL)) -eq 0 ]]; then
        run_aide_check &
    fi

    if [[ $((SCAN_COUNT % RKHUNTER_CHECK_INTERVAL)) -eq 0 ]]; then
        run_rkhunter_check &
    fi

    if [[ $((SCAN_COUNT % AUDITD_CHECK_INTERVAL)) -eq 0 ]]; then
        check_audit_events
    fi

    # V55.4: Suricata canlılık kontrolü (~10 dakikada bir). Foreground -
    # self-heal denerken stop/start yapabildiği için arka plana atılırsa
    # birden fazla örneği çakışabilir, ayrıca LAST_SURICATA_HEALTH_OK gibi
    # değişkenler subshell'de kaybolur (AIDE/RKHunter'da yaşanan sorunun
    # aynısı).
    if [[ $((SCAN_COUNT % SURICATA_HEALTH_CHECK_INTERVAL)) -eq 0 ]]; then
        check_suricata_health
    fi

    # V52.9: ARP/DNS-MITM kontrolleri. Kısa sürdükleri (birkaç saniye içinde
    # timeout) için foreground'da çalıştırılıyor - arka plana atılırsa
    # AIDE/RKHunter'daki gibi subshell sorunu yaşanır (sayaçlar güncellenmez).
    if [[ $((SCAN_COUNT % ARP_CHECK_INTERVAL)) -eq 0 ]]; then
        check_gateway_arp
    fi

    if [[ $((SCAN_COUNT % DNS_CHECK_INTERVAL)) -eq 0 ]]; then
        check_dns_consistency
    fi

    # V56: Sınırsız büyüyen IP/subnet önbelleklerini buda - ya periyodik
    # olarak (CACHE_PRUNE_INTERVAL) ya da biri MAX_CACHE_ENTRIES'i erken
    # aşarsa (yoğun tarama trafiğinde 2 saat beklemeden).
    if [[ $((SCAN_COUNT % CACHE_PRUNE_INTERVAL)) -eq 0 ]] || cache_needs_early_prune; then
        prune_ip_caches
    fi

    # V52.9: İNCELEME MODU. Kullanıcı rootkit araştırırken (nc ile test,
    # strace, elle çalıştırdığı araçlar vb.) script'in kendi terminalini/
    # sürecini kesmesini istemiyorsa: touch /etc/satsuma/pause
    # Bu dosya varken izleme/loglama devam eder ama HİÇBİR blok veya kill
    # işlemi yapılmaz. İncelemeyi bitirince: rm /etc/satsuma/pause
    if [[ -f "$PAUSE_FILE" ]]; then
        add_activity_log "${C_YELLOW}[DURAKLATILDI]${C_RESET} İnceleme modu aktif ($PAUSE_FILE) - blok/kill devre dışı"
        render_dashboard
        sleep $SCAN_INTERVAL
        continue
    fi

    otx_queried=0
    processed_ips=()
    kills_this_scan=0

    for subnet in "${!SUBNET_CONNECTIONS[@]}"; do
        count=${SUBNET_CONNECTIONS[$subnet]}
        pid=${SUBNET_PIDS[$subnet]}
        sample_ip=${SUBNET_SAMPLE_IPS[$subnet]}
        all_ips=${SUBNET_ALL_IPS[$subnet]}
        current_mask="${SUBNET_ESCALATION_LEVEL[$subnet]:-$INITIAL_SUBNET_MASK}"

        if [[ ${SUBNET_ESCALATION_COOLDOWN[$subnet]:-0} -gt 0 ]]; then
            SUBNET_ESCALATION_COOLDOWN[$subnet]=$((SUBNET_ESCALATION_COOLDOWN[$subnet] - 1))
            continue
        fi

        [[ -n "${BLOCKED_SUBNET_CACHE[$subnet]:-}" ]] && continue

        # V52.9: DEĞİŞTİRİLDİ - "güvenilir" (APP_WHITELIST eşleşen)
        # bağlantılar artık tehdit değerlendirmesinden ATLANMIYOR. Eskiden
        # burada `continue` ile tamamen es geçiliyordu; bu "firefox açtı
        # diye güvenli sayılıyor" sorununun ikinci yarısıydı - süreç adı
        # whitelist'te değilse OTX/DNSLESS'e giriyordu ama whitelist'teyse
        # (systemd, NetworkManager, docker vb. dahil) hiç girmiyordu. Artık
        # SUBNET_TRUSTED SADECE dashboard'da görsel ayrım (soluk renk,
        # "güvenilir" etiketi) için kullanılıyor - hangi süreç olursa
        # olsun, HER bağlantı OTX + DNS-less + rootkit + anomali
        # taramasından geçiyor. Rootkit/anomali testleri zaten süreç adına
        # bakıyor (systemd/docker gibi isimler ROOTKIT_PROCESSES'e
        # eşleşmez), o yüzden bu değişiklik yanlış pozitif getirmiyor,
        # sadece OTX/DNSLESS sorgu kapsamını GERÇEKTEN tam yapıyor.

        proc_name=$(get_process_name "$pid")
        [[ -z "$proc_name" ]] && proc_name="PID:${pid:-unknown}"

        block=false
        reason=""
        escalate=false

        # V52.9: DNS-less tespiti artık "aynı anda kaç bağlantı" yerine
        # "kaç ARDIŞIK TARAMADA ısrarla PTR'siz görüldü" mantığına dayanıyor.
        # Önceki (V52.9) sürüm "aynı anda 2+ bağlantı" şartı koyuyordu, ama
        # gerçek C2/backdoor trafiğinin çoğu TEK ve kalıcı bir bağlantı
        # tutar - o şart bunları tamamen görünmez kılıyordu. Israr/kalıcılık
        # çok daha güvenilir bir sinyal: geçici bir CDN bağlantısı birkaç
        # saniyede biter ve cache'den düşer, gerçek tehdit taramalar boyunca
        # kalıcı kalıp eşiği (DNSLESS_PERSISTENCE_THRESHOLD) aşar.
        # V52.9 DÜZELTME: Sayaç artık BURADA artmıyor. Eskiden DNSLESS_BLOCKS
        # tespit anında (blok gerçekten başarılı olup olmadığına bakılmadan)
        # artıyordu. add_subnet_to_blocklist herhangi bir sebeple başarısız
        # olursa IP bir sonraki taramada hâlâ listede kalıyor, hâlâ PTR'siz
        # görünüyor, ısrar eşiği hâlâ aşılmış oluyor - ve sayaç HER TARAMADA
        # sonsuza kadar artmaya devam ediyordu, gerçek blok hiç gerçekleşmese
        # bile ("dns less kendiliğinden artıyor" sorunu buydu). Artık sayaç
        # sadece aşağıdaki add_subnet_to_blocklist GERÇEKTEN başarılı
        # olduğunda artıyor.
        if [[ "$ENABLE_DNSLESS" == "true" ]] && test_dnsless_ip "$sample_ip"; then
            DNSLESS_PERSISTENCE_CACHE["$sample_ip"]=$(( ${DNSLESS_PERSISTENCE_CACHE[$sample_ip]:-0} + 1 ))
            if [[ ${DNSLESS_PERSISTENCE_CACHE[$sample_ip]} -ge $DNSLESS_PERSISTENCE_THRESHOLD ]]; then
                if [[ "$DNSLESS_BLOCK_MODE" == "true" ]]; then
                    block=true
                    reason="DNS-Less IP (${DNSLESS_PERSISTENCE_CACHE[$sample_ip]} ardışık tarama, PTR yok)"
                elif [[ -z "${DNSLESS_LOGGED[$sample_ip]:-}" ]]; then
                    DNSLESS_LOGGED["$sample_ip"]=1
                    add_activity_log "${C_YELLOW}[DNS-LESS]${C_RESET} $sample_ip ($proc_name) PTR yok - bilgi amaçlı, bloklanmadı"
                fi
            fi
        else
            # PTR bulundu ya da devre dışı - ısrar sayacını sıfırla
            unset -v "DNSLESS_PERSISTENCE_CACHE[$sample_ip]" 2>/dev/null || true
        fi

        if [[ "$block" == "false" ]] && [[ "$ENABLE_ROOTKIT_CHECK" == "true" ]]; then
            if test_rootkit_indicators "$proc_name" "$pid"; then
                block=true
                reason="Rootkit"
            fi
        fi

        if [[ "$block" == "false" ]] && [[ "$ENABLE_AI_ANOMALY" == "true" ]]; then
            if calculate_anomaly_score "$proc_name" "$count" "$pid"; then
                block=true
                reason="AI Anomali"
            fi
        fi

        if [[ "$block" == "false" ]] && [[ $count -ge $MAX_CONNECTIONS ]]; then
            block=true
            reason="Aşırı bağlantı ($count)"
        fi

        if [[ "$block" == "false" ]] && [[ "$ENABLE_OTX" == "true" ]] && [[ $otx_queried -lt $MAX_OTX_QUERIES_PER_SCAN ]]; then
            if [[ " ${processed_ips[*]} " != *" ${sample_ip} "* ]]; then
                if test_otx "$sample_ip"; then
                    block=true
                    reason="OTX tehdit"
                fi
                processed_ips+=("$sample_ip")
                otx_queried=$((otx_queried + 1))
            fi
        fi

        if [[ "$ENABLE_SUBNET_ESCALATION" == "true" ]] && [[ "$block" == "false" ]] && [[ $count -ge $ESCALATION_THRESHOLD ]] && [[ $current_mask -gt $MAX_SUBNET_MASK ]]; then
            escalate=true
        fi

        if [[ "$escalate" == "true" ]]; then
            new_subnet=$(get_next_subnet "$subnet")
            if [[ $? -eq 0 ]] && [[ -n "$new_subnet" ]] && [[ -z "${BLOCKED_SUBNET_CACHE[$new_subnet]:-}" ]]; then
                if add_subnet_to_blocklist "$new_subnet"; then
                    SUBNET_ESCALATION_LEVEL["$subnet"]=$(echo "$new_subnet" | cut -d/ -f2)
                    SUBNET_ESCALATION_COOLDOWN[$subnet]=$ESCALATION_COOLDOWN

                    IFS=',' read -ra IP_ARRAY <<< "$all_ips"
                    for ip in "${IP_ARRAY[@]}"; do
                        ip="${ip//[[:space:]]/}"; validate_ip "$ip" || continue
                        [[ -z "$ip" ]] && continue
                        killed=$(kill_connections_for_ip "$ip")
                        [[ "$killed" =~ ^[0-9]+$ ]] && kills_this_scan=$((kills_this_scan + killed))
                    done
                fi
                continue
            fi
        fi

        if [[ "$block" == "true" ]]; then
            if add_subnet_to_blocklist "$subnet"; then
                TOTAL_BLOCKS=$((TOTAL_BLOCKS + 1))

                # V52.9 DÜZELTME: Sebep-bazlı sayaçlar (DNSLESS_BLOCKS,
                # OTX_BLOCKS) artık SADECE blok gerçekten başarılı olduğunda
                # burada artıyor - tespit anında değil. DNS-less için ısrar
                # cache'i de temizleniyor (artık gerçekten bloklandı, tekrar
                # sayılmasın).
                case "$reason" in
                    DNS-Less*)
                        DNSLESS_BLOCKS=$((DNSLESS_BLOCKS + 1))
                        unset -v "DNSLESS_PERSISTENCE_CACHE[$sample_ip]" 2>/dev/null || true
                        ;;
                    "OTX tehdit")
                        OTX_BLOCKS=$((OTX_BLOCKS + 1))
                        ;;
                esac

                # V52.9: "Rootkit" nedeniyle bloklanıyorsa, IP üzerindeki
                # HER prosesi değil, sadece işaretlenen PID'i doğrudan
                # öldür. Eskiden aynı uzak IP'ye tesadüfen bağlanan başka
                # (masum) prosesler de kill ediliyordu - bu yan hasarı
                # önlüyoruz. Diğer sebepler (OTX, DNS-less, aşırı bağlantı,
                # eskalasyon) hâlâ IP bazlı geniş temizlik yapıyor çünkü
                # onlarda tehdit prosesten değil, uzak taraftan geliyor.
                if [[ "$reason" == Rootkit* ]] && [[ -n "$pid" ]] && [[ "$pid" =~ ^[0-9]+$ ]]; then
                    if [[ -d "/proc/${pid}" ]]; then
                        add_activity_log "${C_YELLOW}[ROOTKIT-REVIEW]${C_RESET} PID $pid ($proc_name) işaretlendi; kanıt kaydedildi, otomatik proses sonlandırma kapalı"
                    fi
                    # Uzak IP yine de blocklist'e girsin (C2/reverse shell hedefi olabilir)
                    IFS=',' read -ra IP_ARRAY <<< "$all_ips"
                    for ip in "${IP_ARRAY[@]}"; do
                        ip="${ip//[[:space:]]/}"; validate_ip "$ip" || continue
                        [[ -z "$ip" ]] && continue
                        BLOCKED_IP_CACHE["$ip"]="true"
                    done
                else
                    IFS=',' read -ra IP_ARRAY <<< "$all_ips"
                    for ip in "${IP_ARRAY[@]}"; do
                        ip="${ip//[[:space:]]/}"; validate_ip "$ip" || continue
                        [[ -z "$ip" ]] && continue
                        BLOCKED_IP_CACHE["$ip"]="true"
                        killed=$(kill_connections_for_ip "$ip")
                        [[ "$killed" =~ ^[0-9]+$ ]] && kills_this_scan=$((kills_this_scan + killed))
                    done
                fi

                log_block "$sample_ip" "$reason" "$proc_name"
            else
                # V52.9: Eskiden blok başarısız olduğunda HİÇBİR ŞEY
                # loglanmıyordu, sessizce oluyordu - "neden sürekli aynı IP
                # tekrar tekrar görünüyor" sorusunun cevabı görünmüyordu.
                # Artık başarısızlık açıkça loglanıyor, nftables/izin
                # sorunlarını fark etmen kolaylaşır.
                add_activity_log "${C_BG_RED}${C_WHITE}[BLOK-HATA]${C_RESET} $sample_ip - $reason (nftables bloklama BAŞARISIZ oldu, tekrar denenecek)"
            fi
        fi
    done

    TOTAL_CONNECTIONS_KILLED=$((TOTAL_CONNECTIONS_KILLED + kills_this_scan))

    render_dashboard
    sleep $SCAN_INTERVAL
done

set -H

