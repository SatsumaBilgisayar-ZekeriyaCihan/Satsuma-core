"""satsuma-privd: the one service that blocks addresses and stops processes.

Stage 1 of moving root work into a single gatekeeper (user decision
2026-10-26). Other services send an intent over a local socket instead of
running nft or sending signals themselves:

    block_ip    {ip, reason, manual}
    unblock_ip  {ip, reason, manual}
    terminate   {pid, reason, evidence, context}

The caller is identified by the kernel (SO_PEERCRED): root, or a member of
the satsuma-priv group. privd never takes the caller's configuration: it
loads its own (full protection) and runs Satsuma's own checks in its own
process — protected gateway/DNS/loopback targets, process identity
re-verification, operator pause. Every request, done or refused, is
recorded as privd_audit.

ResponseWorker hands these operations to privd when its socket exists; if
privd is not reachable it still acts itself, so protection never stops.
Stage 2 removes root from the calling services; only then can a taken-over
service no longer block or kill on its own.

satsuma-privd: adresleri engelleyen ve süreçleri durduran tek servis.

Root işlerini tek bir görevliye taşımanın 1. aşaması (kullanıcı kararı
2026-10-26). Diğer servisler nft ya da sinyal kullanmak yerine yerel bir
soketten niyet gönderir: block_ip, unblock_ip, terminate. Çağıran çekirdek
tarafından tanınır (SO_PEERCRED): root ya da satsuma-priv grubunun üyesi.
privd çağıranın ayarlarını almaz; kendi ayarını (tam koruma) yükler ve
Satsuma'nın kendi denetimlerini kendi sürecinde çalıştırır. Yapılan ya da
reddedilen her istek privd_audit olarak kaydedilir. privd'ye
ulaşılamazsa ResponseWorker işi kendisi yapar; koruma durmaz. 2. aşama
çağıran servislerden root'u kaldırır.
"""
import grp
import ipaddress
import json
import os
import socket
import struct
import time
from pathlib import Path

SOCKET_PATH = Path('/run/satsuma-privd/privd.sock')
GROUP = 'satsuma-priv'
SERVER_ENV = 'SATSUMA_PRIVD_SERVER'
MAX_REQUEST = 64 * 1024
OPERATIONS = {
    'block_ip': ({'ip', 'reason'}, {'manual', 'raw_id', 'duration'}),
    'unblock_ip': ({'ip', 'reason'}, {'manual'}),
    'terminate': ({'pid', 'reason'}, {'evidence', 'context'}),
}


class PrivdUnavailable(Exception):
    pass


def request(op, timeout=15, path=SOCKET_PATH, **params):
    """Send one intent to privd and return its answer."""
    payload = json.dumps({'op': op, **params}, ensure_ascii=False, default=str).encode()
    if len(payload) > MAX_REQUEST:
        raise ValueError('privd request too large')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(path))
            client.sendall(payload + b'\n')
            client.shutdown(socket.SHUT_WR)
            data = b''
            while len(data) <= MAX_REQUEST:
                chunk = client.recv(65536)
                if not chunk:
                    break
                data += chunk
    except OSError as exc:
        raise PrivdUnavailable(str(exc)) from exc
    try:
        return json.loads(data)
    except ValueError as exc:
        raise PrivdUnavailable('unreadable privd answer') from exc


def delegate(op, **params):
    """privd's answer, or None when this process must act itself."""
    if os.environ.get(SERVER_ENV) == '1' or not SOCKET_PATH.exists():
        return None
    try:
        return request(op, **params)
    except PrivdUnavailable:
        return None


def peer(connection):
    creds = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    pid, uid, gid = struct.unpack('3i', creds)
    return {'pid': pid, 'uid': uid, 'gid': gid}


def allowed(identity, group_lookup=grp.getgrnam):
    if identity['uid'] == 0:
        return True
    try:
        group = group_lookup(GROUP)
    except KeyError:
        return False
    return identity['gid'] == group.gr_gid


def validate(message):
    if not isinstance(message, dict) or message.get('op') not in OPERATIONS:
        raise ValueError('unknown operation')
    required, optional = OPERATIONS[message['op']]
    keys = set(message) - {'op'}
    if not required <= keys or keys - required - optional:
        raise ValueError('unexpected request keys')
    if 'ip' in message:
        message['ip'] = str(ipaddress.ip_address(message['ip']))
    if 'pid' in message and (type(message['pid']) is not int or message['pid'] <= 1):
        raise ValueError('invalid pid')
    if not isinstance(message['reason'], str) or len(message['reason']) > 500:
        raise ValueError('invalid reason')
    for key in ('manual',):
        if key in message and type(message[key]) is not bool:
            raise ValueError(key + ' must be boolean')
    if 'duration' in message and (type(message['duration']) is not int or not 0 <= message['duration'] <= 30 * 86400):
        raise ValueError('invalid duration')
    for key in ('evidence', 'context'):
        if key in message and message[key] is not None and not isinstance(message[key], dict):
            raise ValueError(key + ' must be an object')
    return message


def handle(message, identity, worker, audit):
    """Run one validated intent through Satsuma's own checks."""
    started = time.time()
    try:
        message = validate(message)
        if not allowed(identity):
            raise PermissionError('caller is not allowed to use privd')
        op = message['op']
        if op == 'block_ip':
            result = worker.block_ip(message['ip'], message['reason'], raw_id=message.get('raw_id'),
                                     manual=bool(message.get('manual')), duration=message.get('duration', 0))
        elif op == 'unblock_ip':
            result = worker.unblock_ip(message['ip'], message['reason'], manual=bool(message.get('manual')))
        else:
            result = worker.terminate_process(message['pid'], message['reason'], evidence=message.get('evidence'),
                                              context=message.get('context'))
    except (ValueError, PermissionError, TypeError) as exc:
        result = {'status': 'privd_refused', 'error': str(exc)[:300]}
    record = {'timestamp': started, 'op': (message or {}).get('op') if isinstance(message, dict) else None,
              'caller': identity, 'status': result.get('status'), 'target': (message or {}).get('ip') or
              (message or {}).get('pid') if isinstance(message, dict) else None}
    try:
        audit(record)
    except Exception:
        pass
    return result


def _worker():
    from .config import load_with_policy
    from .response import ResponseWorker
    from .store import Store
    config, _, _ = load_with_policy()
    store = Store()
    return store, ResponseWorker(store, config)


def serve(path=SOCKET_PATH, worker_factory=_worker, once=False):
    os.environ[SERVER_ENV] = '1'
    store, worker = worker_factory()
    path = Path(path)
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    os.chmod(path, 0o660)
    try:
        os.chown(path, 0, grp.getgrnam(GROUP).gr_gid)
    except (KeyError, PermissionError):
        pass
    server.listen(16)
    audit = lambda record: store.add('privd_audit', record)
    try:
        while True:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(15)
                try:
                    identity = peer(connection)
                    data = b''
                    while b'\n' not in data and len(data) <= MAX_REQUEST:
                        chunk = connection.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    try:
                        message = json.loads(data.split(b'\n', 1)[0])
                    except ValueError:
                        message = None
                    result = handle(message, identity, worker, audit)
                    connection.sendall(json.dumps(result, ensure_ascii=False, default=str).encode())
                except OSError:
                    pass
            if once:
                return
    finally:
        server.close()


if __name__ == '__main__':
    serve()
