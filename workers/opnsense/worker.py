"""Satsuma Core — OPNsense log worker.

Modes:
  - file: tail a local log file that receives forwarded syslog
  - udp:  simple UDP syslog listener (bind 0.0.0.0:PORT)

Only collects + normalizes. No decisions.
"""
from __future__ import annotations

import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from workers.normalizer.opnsense.mapper import map_batch
from satsuma.opnsense_advisory import candidate, finding_for


class WorkerOpnsense:
    name = "opnsense"

    def __init__(self, store=None, config: Optional[dict] = None):
        self.store = store
        self.config = config or {}
        self.cursor_key = "worker.opnsense.cursor"
        self.health_key = "worker.opnsense.health"
        self.advisory_key = "worker.opnsense.advisory_state"
        self._sock: Optional[socket.socket] = None

    def _file_path(self) -> Path:
        path = self.config.get("opnsense_log_path") or "/var/log/satsuma-opnsense.log"
        return Path(path)

    def _collect_file(self, max_lines: int = 500) -> List[str]:
        path = self._file_path()
        if path.is_symlink() or not path.is_file():
            raise FileNotFoundError('OPNsense log unavailable or symlinked')
        try:
            # Track inode as well as offset so log rotation cannot skip events.
            info = path.stat()
            cursor = self.store.get(self.cursor_key, {}) if self.store is not None else {}
            if isinstance(cursor, dict):
                offset = int(cursor.get("offset", 0) or 0)
                if cursor.get("inode") != info.st_ino:
                    offset = 0
            else:
                offset = int(cursor or 0)  # old installations stored only an offset
            if offset < 0 or offset > info.st_size:
                offset = 0
            with path.open("r", encoding="utf-8", errors="replace") as f:
                if f.fileno() < 0 or f.seekable() is False:
                    return []
                if f.isatty():
                    return []
                f.seek(offset)
                lines = []
                for _ in range(max_lines):
                    start=f.tell()
                    line = f.readline(65537)
                    if len(line)>65536:
                        raise ValueError('OPNsense line exceeds capacity; cursor retained')
                    if not line:
                        break
                    if not line.endswith('\n'):
                        f.seek(start)
                        break
                    lines.append(line.rstrip("\n"))
                new_offset = f.tell()
            if self.store is not None:
                self.pending_cursor = {"inode": info.st_ino, "offset": new_offset}
            return lines
        except (OSError, ValueError, TypeError):
            raise

    def _collect_udp(self, max_packets: int = 200, timeout: float = 0.3) -> List[str]:
        port = int(self.config.get("opnsense_udp_port", 5514))
        if self._sock is None:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                bind_host = str(self.config.get("opnsense_udp_bind") or "127.0.0.1")
                s.bind((bind_host, port))
                s.settimeout(timeout)
                self._sock = s
            except OSError:
                s.close()
                raise
        lines = []
        try:
            for _ in range(max_packets):
                try:
                    data, _addr = self._sock.recvfrom(65535)
                    text = data.decode("utf-8", errors="replace").strip()
                    if text:
                        lines.append(text)
                except socket.timeout:
                    break
        except OSError:
            raise
        return lines

    def _record_advisories(self, events: List[dict]) -> int:
        """Repeated external drops are *recommendations*, never commands."""
        if self.store is None:
            return 0
        state = self.store.get(self.advisory_key, {}) or {}
        if not isinstance(state, dict):
            state = {}
        now = time.time()
        # Bound state growth and discard stale windows after one hour.
        state = {ip: item for ip, item in state.items()
                 if isinstance(item, dict) and now - item.get("last_seen", 0) < 3600}
        recommendations = 0
        for event in events:
            ip = candidate(event)
            if not ip:
                continue
            item = state.get(ip, {})
            if now - item.get("first_seen", 0) > 600:
                item = {"first_seen": now, "count": 0,
                        "last_recommended": item.get("last_recommended", 0)}
            item["count"] += 1
            item["last_seen"] = now
            if item["count"] >= 3 and now - item.get("last_recommended", 0) >= 3600:
                self.store.add("findings", finding_for(event, ip, item["count"], now))
                item["last_recommended"] = now
                recommendations += 1
            state[ip] = item
        # A remote syslog stream must not grow the state database without limit.
        if len(state) > 1024:
            state = dict(sorted(state.items(), key=lambda pair: pair[1]["last_seen"],
                                reverse=True)[:1024])
        self.store.set(self.advisory_key, state)
        return recommendations

    def collect(self) -> Dict[str, Any]:
        self.pending_cursor = None
        mode = (self.config.get("opnsense_mode") or "file").lower()
        try:
            if mode == "udp":
                raw_lines = self._collect_udp()
            elif mode == 'file':
                raw_lines = self._collect_file()
            else:
                raise ValueError('Unknown OPNsense input mode')
        except FileNotFoundError as exc:
            path = self._file_path()
            if mode == 'file' and not path.is_symlink() and not path.exists():
                # 2.2.42: no OPNsense on this network means no log file; that is
                # not a fault ("Sorunlu çalışıyor" in the panel). Ağda OPNsense yoksa arıza değildir.
                report={'timestamp':time.time(),'updated_at':time.time(),'status':'NOT_CONFIGURED','mode':mode,
                        'reason':'OPNsense kayıt dosyası yok: '+str(path)+' (ağda OPNsense yapılandırılmamış)','events':[]}
            else:
                report={'timestamp':time.time(),'status':'ERROR','mode':mode,'error':str(exc)[:300],'events':[]}
            if self.store is not None:self.store.set(self.health_key,report)
            return report
        except (OSError, ValueError, TypeError) as exc:
            report={'timestamp':time.time(),'status':'ERROR','mode':mode,'error':str(exc)[:300],'events':[]}
            if self.store is not None:self.store.set(self.health_key,report)
            return report

        source_host = self.config.get("opnsense_host") or "opnsense"
        events = map_batch(raw_lines, source_host=source_host)

        recommendations = 0
        if self.store is not None:
            try:
                for ev in events:
                    self.store.add("opnsense_events", ev)
                recommendations = self._record_advisories(events)
                if self.pending_cursor is not None:
                    self.store.set(self.cursor_key,self.pending_cursor)
                self.store.set(self.health_key, {
                    'status': 'RUNNING',
                    "timestamp": int(time.time()),
                    "mode": mode,
                    "lines": len(raw_lines),
                    "events": len(events),
                    "recommendations": recommendations,
                    "remote_write_enabled": False,
                })
            except Exception as exc:
                # Do not misreport a failed persistence step as a clean ingest.
                return {"timestamp": int(time.time()), "mode": mode,
                        "raw_count": len(raw_lines), "event_count": len(events),
                        "status": "ERROR", "error": str(exc)[:200], "events": []}

        return {
            "timestamp": int(time.time()),
            "mode": mode,
            "raw_count": len(raw_lines),
            "event_count": len(events),
            "recommendation_count": recommendations,
            "remote_write_enabled": False,
            "events": events[:50],  # sample
        }
