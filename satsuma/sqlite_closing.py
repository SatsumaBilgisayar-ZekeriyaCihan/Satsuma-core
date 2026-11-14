"""SQLite connections that close when their ``with`` block ends.

sqlite3's own context manager only commits or rolls back; the connection
stays open until a cyclic garbage-collection pass. In long-running services
that leaked one core.db and one -wal descriptor per call until the reader
hit EMFILE (field log 2026-10-25). Pass ``factory=ClosingConnection`` to
``sqlite3.connect`` and ``with`` both ends the transaction and closes.

``with`` bloğu bitince kapanan SQLite bağlantıları.

sqlite3'ün kendi bağlam yöneticisi yalnızca işlemi onaylar ya da geri alır;
bağlantı döngüsel çöp toplamaya kadar açık kalır. Uzun çalışan servislerde
bu, her çağrıda bir core.db ve bir -wal tanıtıcısı sızdırdı ve okuyucu
EMFILE hatasına ulaştı (2026-10-25 saha kaydı). ``sqlite3.connect``'e
``factory=ClosingConnection`` verilince ``with`` hem işlemi bitirir hem
bağlantıyı kapatır.
"""
import sqlite3


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, *exc):
        try:
            return super().__exit__(*exc)
        finally:
            self.close()
