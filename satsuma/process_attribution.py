"""Satsuma — /proc uzerinden process attribution."""
import os
import time
import threading
from pathlib import Path


class ProcessCache:
    def __init__(self, ttl=5.0):
        self.ttl = ttl
        self._lock = threading.Lock()
        self._last = 0.0
        self._map = {}

    def _parse_net(self, path, proto):
        out = {}
        try:
            with open(path) as f:
                next(f)  # header
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    local = parts[1]
                    inode = parts[9]
                    if ":" not in local:
                        continue
                    _, port_hex = local.rsplit(":", 1)
                    try:
                        port = int(port_hex, 16)
                    except ValueError:
                        continue
                    out[(proto, port)] = inode
        except OSError:
            pass
        return out

    def _inode_to_pid(self):
        result = {}
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            pid = pid_dir.name
            fd_dir = pid_dir / "fd"
            try:
                for fd in fd_dir.iterdir():
                    try:
                        link = os.readlink(str(fd))
                    except OSError:
                        continue
                    if link.startswith("socket:["):
                        inode = link[8:-1]
                        result.setdefault(inode, pid)
            except OSError:
                continue
        return result

    def _read_comm(self, pid):
        try:
            return Path(f"/proc/{pid}/comm").read_text().strip()
        except OSError:
            return "?"

    def _refresh(self):
        net = {}
        net.update(self._parse_net("/proc/net/udp", "udp"))
        net.update(self._parse_net("/proc/net/udp6", "udp"))
        net.update(self._parse_net("/proc/net/tcp", "tcp"))
        net.update(self._parse_net("/proc/net/tcp6", "tcp"))

        inode_pid = self._inode_to_pid()

        new_map = {}
        for (proto, port), inode in net.items():
            pid = inode_pid.get(inode)
            if pid:
                new_map[(proto, port)] = {
                    "pid": int(pid),
                    "name": self._read_comm(pid),
                }

        with self._lock:
            self._map = new_map
            self._last = time.time()

    def lookup(self, port, proto="udp"):
        if not port:
            return None
        with self._lock:
            stale = (time.time() - self._last) > self.ttl
        if stale:
            self._refresh()
        with self._lock:
            return self._map.get((proto.lower(), int(port)))


_CACHE = ProcessCache()


def attribute(port, proto="udp"):
    """Port -> {"pid": int, "name": str} veya None."""
    try:
        return _CACHE.lookup(port, proto)
    except Exception:
        return None
