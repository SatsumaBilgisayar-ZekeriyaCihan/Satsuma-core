"""The reader works right after installation, before any writer opens the database (2.2.38).

Owner's report: after the first install the panel did not work until
satsuma-reader was restarted. The reader's /var/lib is read-only
(ProtectSystem=strict); with no writer there is no -wal/-shm file and a
read-only WAL connection cannot create one. The test reproduces that with an
unprivileged process in a directory it cannot write.
İlk kurulumdan hemen sonra, yazar veritabanını açmadan önce de okuyucu çalışır.
"""
import os
import pwd
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
CODE = '''
import sys
sys.path.insert(0, sys.argv[1])
from satsuma import dashboard_api
try:
    with dashboard_api._connect_at(sys.argv[2]) as db:
        print('ok', db.execute("SELECT body FROM state WHERE key='k'").fetchone()[0])
except Exception as exc:
    print('error', type(exc).__name__, exc)
'''


@pytest.fixture
def database():
    if os.geteuid() != 0:
        pytest.skip('needs root to read as an unprivileged user')
    import shutil
    import tempfile
    folder = Path(tempfile.mkdtemp(prefix='satsuma-reader-', dir='/tmp'))
    os.chmod(folder, 0o755)   # readable, not writable, for the unprivileged reader
    path = folder / 'core.db'
    writer = sqlite3.connect(path)
    writer.execute('PRAGMA journal_mode=WAL')
    writer.execute('CREATE TABLE state(key TEXT PRIMARY KEY, body TEXT)')
    writer.execute("INSERT INTO state VALUES('k','first-install')")
    writer.commit()
    os.chmod(path, 0o644)
    yield path, writer
    writer.close()
    shutil.rmtree(folder, ignore_errors=True)


def read(path):
    nobody = pwd.getpwnam('nobody').pw_uid
    done = subprocess.run([sys.executable, '-I', '-B', '-c', CODE, str(ROOT), str(path)],
                          capture_output=True, text=True, preexec_fn=lambda: os.setuid(nobody), timeout=30)
    return (done.stdout or done.stderr).strip()


def test_reader_reads_while_no_writer_has_the_database_open(database):
    path, writer = database
    writer.close()                       # installation finished, core not started yet
    assert not Path(str(path) + '-wal').exists()
    plain = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
    plain.close()
    assert read(path) == 'ok first-install'


def test_reader_uses_the_normal_path_while_a_writer_is_open(database):
    path, writer = database
    for suffix in ('-wal', '-shm'):
        os.chmod(str(path) + suffix, 0o644)
    assert read(path) == 'ok first-install'


def test_missing_database_is_still_an_error(tmp_path):
    from satsuma import dashboard_api
    with pytest.raises(sqlite3.OperationalError):
        dashboard_api._connect_at(tmp_path / 'absent.db')
