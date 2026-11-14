"""Bounded, complete-line log reads using the trusted log source opener."""
import os
from .source_guard import open_eve


def read_batch(path, cursor=None, *, opener=open_eve, writer_uid=0, limit=1000):
    with opener(path, writer_uid) as stream:
        info = os.fstat(stream.fileno())
        cursor = cursor if isinstance(cursor, dict) else {}
        offset = cursor.get('offset', 0)
        if (cursor.get('inode'), cursor.get('device')) != (info.st_ino, info.st_dev) or not 0 <= offset <= info.st_size:
            offset = 0
        stream.seek(offset)
        lines = []
        for _ in range(limit):
            start = stream.tell()
            line = stream.readline(65537)
            if len(line) > 65536:
                raise ValueError('Oversized log line; cursor retained for operator review')
            if not line or not line.endswith(b'\n'):
                stream.seek(start)
                break
            lines.append(line.decode('utf-8', 'replace'))
        return lines, {'inode':info.st_ino, 'device':info.st_dev, 'offset':stream.tell()}
