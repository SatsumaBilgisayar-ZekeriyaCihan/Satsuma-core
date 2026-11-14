"""A rotated audit log is read to its end, then the new log is followed.

Döndürülen audit günlüğü sonuna kadar okunur, ardından yeni günlük izlenir.
"""
import os
import re

from satsuma.audit_host import AuditReader


class Store:
    def __init__(self):
        self.state, self.rows = {}, []

    def get(self, key, default=None):
        return self.state.get(key, default)

    def set(self, key, value):
        self.state[key] = value

    def add(self, kind, body):
        self.rows.append((kind, body))


def lines(start, count):
    return ''.join(f'type=SYSCALL msg=audit(1793020000.000:{i}): pid={i} comm="x"\n'
                   f'type=EOE msg=audit(1793020000.000:{i}): \n' for i in range(start, start + count))


def serials(store):
    return {int(n) for kind, body in store.rows if kind == 'audit' for n in re.findall(r':(\d+)\)', str(body))}


def test_rotation_while_behind_reads_old_then_new(tmp_path):
    log = tmp_path / 'audit.log'
    log.write_text(lines(0, 1000))           # more than one poll (500 lines)
    store = Store()
    reader = AuditReader(store, str(log))
    reader.poll()
    os.rename(log, tmp_path / 'audit.log.1')
    log.write_text(lines(5000, 10))
    for i in range(10):
        reader.poll()
        with log.open('a') as stream:
            stream.write(lines(6000 + i * 3, 3))
    reader.poll()
    seen = serials(store)
    assert set(range(1000)) <= seen                                # old file finished
    assert set(range(5000, 5010)) | set(range(6000, 6030)) <= seen  # new file followed
    assert not [b for k, b in store.rows if k == 'host_errors' and b.get('status') == 'AUDIT_TRUNCATED']


def test_real_truncation_of_the_same_file_is_still_reported(tmp_path):
    log = tmp_path / 'audit.log'
    log.write_text(lines(0, 100))
    store = Store()
    reader = AuditReader(store, str(log))
    reader.poll()
    with log.open('r+') as stream:
        stream.truncate(0)
    reader.poll()
    assert [b for k, b in store.rows if k == 'host_errors' and b.get('status') == 'AUDIT_TRUNCATED']
