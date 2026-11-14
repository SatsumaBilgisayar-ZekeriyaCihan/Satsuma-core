# -*- coding: utf-8 -*-
"""Satsuma Core — Reader API istemci."""
import json
import socket
import struct

SOCKET_PATH = '/run/satsuma-reader/reader.sock'


class ReaderClient:
    def __init__(self, socket_path=SOCKET_PATH, timeout=3):
        self.socket_path = socket_path
        self.timeout = timeout

    def call(self, method, **params):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Exact historical counts require a scan on legacy databases without
        # a normalized finding index. The Qt backend executes this off-thread.
        s.settimeout(max(self.timeout, 30) if method in ('findings', 'overview') else self.timeout)
        try:
            try:
                s.connect(self.socket_path)
            except FileNotFoundError as exc:
                raise ConnectionError(f'Reader bağlantısı yok: {self.socket_path}. sudo systemctl status satsuma-reader.service ile kontrol edin.') from exc
            except PermissionError as exc:
                raise PermissionError(f'Reader erişimi reddedildi: {self.socket_path}. sudo satsuma-setup --user KULLANICI ile masaüstü kullanıcısını kaydedip oturumu kapatıp açın.') from exc
            req = json.dumps(
                {'method': method, 'params': params}
            ).encode('utf-8')
            s.sendall(struct.pack('>I', len(req)) + req)

            header = b''
            while len(header) < 4:
                chunk = s.recv(4 - len(header))
                if not chunk:
                    raise ConnectionError('baglanti kesildi')
                header += chunk
            length = struct.unpack('>I', header)[0]
            if length > 10 * 1024 * 1024:
                raise RuntimeError('yanit cok buyuk')
            body = b''
            while len(body) < length:
                chunk = s.recv(length - len(body))
                if not chunk:
                    raise ConnectionError('baglanti kesildi')
                body += chunk
            resp = json.loads(body.decode('utf-8'))
            if 'error' in resp:
                raise RuntimeError(resp['error'])
            return resp.get('result')
        finally:
            s.close()

    def ping(self):
        return self.call('ping') == 'pong'
