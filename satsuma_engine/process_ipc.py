"""Unix datagram boundary between privileged flow collector and unprivileged deep engine.

Observational evidence only. Peer credentials checked; no action commands.
"""
import json
import os
import pwd
import socket
import struct
import time
from pathlib import Path
from .live_lane import DeepEvidenceLane

EVENT_SOCKET = '/run/satsuma-deep/events.sock'
# 2.2.38 (owner, 2026-11-18: "deep engine bağlantısı inactive kalıyor"): the
# results socket lives in the teams service's own runtime folder. Under
# ProtectSystem=strict /run is read-only for satsuma-teams except its own
# RuntimeDirectory, so binding in /run/satsuma-deep always failed (EROFS), and
# a socket left by a crashed teams made every later start fail with "already
# exists" until the deep engine was restarted.
# Sonuç soketi teams servisinin kendi çalışma klasöründedir: /run teams için
# salt okunurdu, bağlanma hep başarısız oluyordu.
RESULT_SOCKET = '/run/satsuma-deep-results/results.sock'
ENGINE_GROUP = 'satsuma-core'
MAX_PACKET = 8192


def _uid(name):
    return pwd.getpwnam(name).pw_uid


def _credentials(ancillary):
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) >= 12:
            return struct.unpack('3i', data[:12])
    return None


def _compact_event(event):
    if not isinstance(event, dict) or not isinstance(event.get('id'), (str, int)):
        return None
    allowed = ('id', 'timestamp', 'source', 'kind', 'action', 'category', 'pid',
               'starttime', 'boot_id', 'uid', 'ppid', 'cmd', 'exe', 'parent_cmd',
               'file_path', 'path', 'operation', 'lab_test_mode', 'src_ip', 'dest_ip', 'src_port',
               'dest_port', 'proto', 'file_sha256')
    return {key: value[:512] if isinstance(value, str) else value
            for key, value in event.items() if key in allowed
            and type(value) in (str, int, float, bool)}


def _remove_own_stale_socket(path):
    import stat
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
        raise RuntimeError('deep results path exists and is not our socket')
    os.unlink(path)


def _share_with_engine(path, group=ENGINE_GROUP):
    import grp
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        return False
    if gid not in os.getgroups() and gid != os.getegid():
        return False
    try:
        os.chown(path, -1, gid)
        parent = os.path.dirname(path)
        if os.stat(parent).st_uid == os.geteuid():
            os.chown(parent, -1, gid)
            os.chmod(parent, 0o750)
        return True
    except OSError:
        return False


class DeepProcessClient:
    """Drop rather than wait when server is down or busy."""
    def __init__(self, event_socket=EVENT_SOCKET, result_socket=RESULT_SOCKET,
                 expected_uid=None):
        self.event_socket = event_socket
        self.result_socket = result_socket
        self.expected_uid = _uid('satsuma-engine') if expected_uid is None else expected_uid
        self.in_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.in_sock.setblocking(False)
        self.out_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.out_sock.setblocking(False)
        self.out_sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        # Caller owns this socket and its parent. A socket of our own left by a
        # previous run of this service is removed; anything else is refused.
        _remove_own_stale_socket(result_socket)
        self.out_sock.bind(result_socket)
        os.chmod(result_socket, 0o660)
        # The rootless engine (group satsuma-core) must be able to send results:
        # the socket and its folder go to that group (the service is a member).
        _share_with_engine(result_socket)
        self.accepted = self.dropped = self.invalid = self.received = 0
        self._running = True

    def submit(self, event):
        obj = _compact_event(event)
        if obj is None:
            self.dropped += 1
            return False
        data = json.dumps(obj, separators=(',', ':')).encode()
        if len(data) > MAX_PACKET:
            self.dropped += 1
            return False
        try:
            self.in_sock.sendto(data, self.event_socket)
            self.accepted += 1
            return True
        except (OSError, BlockingIOError):
            self.dropped += 1
            return False

    def drain(self, limit=8):
        output = []
        for _ in range(max(0, min(int(limit), 64))):
            try:
                data, anc, flags, _ = self.out_sock.recvmsg(MAX_PACKET, socket.CMSG_SPACE(12))
            except (BlockingIOError, OSError):
                break
            creds = _credentials(anc)
            if flags & socket.MSG_TRUNC or not creds or creds[1] != self.expected_uid:
                self.invalid += 1
                continue
            try:
                obj = json.loads(data)
            except (ValueError, UnicodeError):
                self.invalid += 1
                continue
            if isinstance(obj, dict) and obj.get('authorization') == 'none' and obj.get('evidence_type') == 'deep_engine_observation':
                self.received += 1
                output.append({key: obj[key] for key in (
                    'finding_id', 'rule_id', 'rule_title', 'severity', 'classification',
                    'confidence', 'score', 'category', 'timestamp', 'event_source',
                    'event_kind', 'event_action', 'event_fingerprint', 'process', 'file',
                    'network', 'matched_conditions', 'mitre', 'evidence_type',
                    'authorization', 'window_events', 'test_rule', 'review_required'
                ) if key in obj})
            else:
                self.invalid += 1
        return output

    def health(self):
        return {'running': Path(self.event_socket).exists(), 'mode': 'unprivileged_process',
                'delivery_confirmed': self.received > 0, 'received': self.received,
                'accepted': self.accepted,
                'input_dropped': self.dropped, 'invalid_results': self.invalid,
                'note': 'send success does not prove deep engine processed event'}

    def close(self):
        self._running = False
        self.in_sock.close()
        self.out_sock.close()
        try:
            Path(self.result_socket).unlink()
        except FileNotFoundError:
            pass


def serve(event_socket=EVENT_SOCKET, result_socket=RESULT_SOCKET, stop=None,
          expected_uid=0, lane=None):
    """Run only under the dedicated satsuma-engine identity.

    Input sender must be the root-owned teams worker; rootless collector support
    requires an explicit future identity change, never a group-only bypass.
    """
    if os.geteuid() == 0:
        raise PermissionError('deep engine must not run as root')
    if os.geteuid() != _uid('satsuma-engine'):
        raise PermissionError('unexpected deep engine service identity')
    own_lane = lane is None
    lane = lane or DeepEvidenceLane.from_bundled_rules().start()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    sock.settimeout(0.1)
    sock.bind(event_socket)
    os.chmod(event_socket, 0o660)
    stop = stop or (lambda: False)
    try:
        while not stop():
            try:
                data, anc, flags, _ = sock.recvmsg(MAX_PACKET, socket.CMSG_SPACE(12))
            except socket.timeout:
                data = None
            if data is not None:
                creds = _credentials(anc)
                if creds and creds[1] == expected_uid and not flags & socket.MSG_TRUNC:
                    try:
                        event = json.loads(data)
                        if _compact_event(event) is not None:
                            lane.submit(event)
                    except (ValueError, UnicodeError):
                        pass
            for result in lane.drain(8):
                payload = json.dumps(result, separators=(',', ':')).encode()
                if len(payload) <= MAX_PACKET:
                    try:
                        sock.sendto(payload, result_socket)
                    except OSError:
                        # No client: drop evidence, never retry on the fast path.
                        pass
    finally:
        sock.close()
        if own_lane:
            lane.close()
        try:
            Path(event_socket).unlink()
        except FileNotFoundError:
            pass
