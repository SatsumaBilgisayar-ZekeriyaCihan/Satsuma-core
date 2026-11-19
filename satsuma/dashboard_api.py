# -*- coding: utf-8 -*-
"""Satsuma Core — Dashboard Reader API.

This service runs as root and serves READ-ONLY data to the dashboard client over
/run/satsuma-reader/reader.sock. core.db and host.db connections are separate;
both are opened with ``mode=ro`` and ``PRAGMA query_only=ON`` and are closed
when their ``with`` block ends. There are no schema migrations,
INSERT/UPDATE/DELETE statements or file writes.

Control-plane write capability is never added to this socket. Operator ticket
decisions need a separate, explicit, authorised and audited write channel.

records_overview and records_explained list every stored record kind, named
in plain Turkish by record_catalog; unknown kinds are shown, never hidden.

---

Bu servis root olarak çalışır ve /run/satsuma-reader/reader.sock üzerinden dashboard
istemcisine SALT-OKUNUR veri sunar. core.db ve host.db bağlantıları ayrıdır;
her ikisi de ``mode=ro`` ve ``PRAGMA query_only=ON`` ile açılır ve ``with``
bloğu bitince kapatılır. records_overview ve records_explained saklanan her
kayıt türünü record_catalog'daki Türkçe adıyla listeler; tanımsız türler
gizlenmez, gösterilir. Şema
migrasyonu, INSERT/UPDATE/DELETE veya dosya yazımı YOKTUR.

Kontrol düzlemi yazma yeteneği bu socket'e eklenmez. Operator ticket kararı
için açık, yetkilendirilmiş ve auditlenen ayrı bir yazma kanalı gerekir.
"""
import datetime
from contextlib import ExitStack
import heapq
import itertools
from .presentation import process_fields
import ipaddress
import json
import os
import re
import socketserver
import sqlite3
import struct
import sys
import time
import threading
from pathlib import Path

from .dashboard_api_client import SOCKET_PATH
SOCKET_GROUP = 'satsuma-reader'
SOCKET_MODE = 0o660
DB_PATH = '/var/lib/satsuma-core/core.db'
HOST_DB_PATH = '/var/lib/satsuma-core/host/host.db'
RULES_DIR = Path(__file__).resolve().parents[1] / 'rules'
FUTURE_SPECS_DIR = Path(__file__).resolve().parents[1] / 'future_specs'
OTX_CONFIG_PATH = '/etc/satsuma-core/otx.json'
INTEGRITY_MANIFEST_PATHS = (
    '/usr/share/satsuma-core/self-integrity.json',
    '/var/lib/satsuma-core/self-integrity.json',
)


# sqlite3's own ``with`` only ends the transaction; the connection would
# stay open until a cyclic GC pass (field log: 507 core.db fds, EMFILE).
from .sqlite_closing import ClosingConnection as _ClosingConnection


def _connect_at(path):
    # Reader control-plane yazma yapamaz: DB baglantisi daima read-only.
    db = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=2, factory=_ClosingConnection)
    db.execute('PRAGMA query_only=ON')
    try:
        db.execute('SELECT 1 FROM sqlite_master LIMIT 1').fetchone()
        return db
    except sqlite3.OperationalError as exc:
        db.close()
        # 2.2.38 (owner: the panel did not work after the first install until
        # satsuma-reader was restarted). The databases are in WAL mode and
        # /var/lib is read-only for this service (ProtectSystem=strict). While
        # no writer holds a database open there is no -wal/-shm file, and a
        # read-only connection cannot create the -shm: every call failed with
        # "attempt to write a readonly database" (reproduced in
        # tests/test_reader_first_install.py). That is exactly the state right
        # after installation, before satsuma-core opens core.db. With no -wal
        # file every committed page is in the main file, so it is read as an
        # immutable snapshot; with a -wal file the error is real and raised.
        # İlk kurulumda yazar yokken -wal/-shm yoktur, salt okunur bağlantı
        # -shm oluşturamaz ve her çağrı hata veriyordu. -wal yoksa tüm veri ana
        # dosyadadır; ana dosya değişmez anlık görüntü olarak okunur.
        message = str(exc).lower()
        if ('readonly' not in message and 'unable to open' not in message) or not os.path.exists(path) \
                or os.path.exists(str(path) + '-wal'):
            raise
    db = sqlite3.connect(f'file:{path}?mode=ro&immutable=1', uri=True, timeout=2, factory=_ClosingConnection)
    db.execute('PRAGMA query_only=ON')
    return db


def _connect():
    return _connect_at(DB_PATH)


def _connect_host():
    return _connect_at(HOST_DB_PATH)


def _decode(body):
    try:
        return json.loads(body)
    except Exception:
        return None


def _state(db, key, default=None):
    try:
        row = db.execute('SELECT body FROM state WHERE key=?', (key,)).fetchone()
    except sqlite3.Error:
        raise
    if not row:
        return default
    value = _decode(row[0])
    return default if value is None else value


def _rows(db, kind, limit=50):
    try:
        rows = db.execute(
            'SELECT id, created, body FROM records WHERE kind=? '
            'ORDER BY id DESC LIMIT ?',
            (kind, int(limit)),
        ).fetchall()
    except sqlite3.Error:
        raise
    out = []
    for rid, created, body in rows:
        item = _decode(body)
        if isinstance(item, dict):
            item.setdefault('_id', rid)
            item.setdefault('_record_created', created)
        out.append(item)
    return out


def _count(db, kind):
    try:
        return int(db.execute(
            'SELECT COUNT(*) FROM records WHERE kind=?', (kind,)
        ).fetchone()[0] or 0)
    except sqlite3.Error:
        raise


def _table_exists(db, name):
    try:
        return bool(db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (name,),
        ).fetchone())
    except sqlite3.Error:
        raise


def _epoch(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    try:
        if text.endswith('Z'):
            text = text[:-1] + '+00:00'
        return datetime.datetime.fromisoformat(text).timestamp()
    except (ValueError, TypeError):
        return None


def _tr_status(value):
    mapping = {
        'RUNNING': 'Çalışıyor',
        'DEGRADED': 'Sorunlu çalışıyor',
        'STOPPED': 'DURDU',
        'DISABLED': 'DEVRE DIŞI',
        'UNKNOWN': 'Veri alınamadı',
        'ACTIVE': 'AKTİF',
        'INACTIVE': 'PASİF',
        'FAILED': 'BAŞARISIZ',
        'NO_DATA': 'VERİ YOK',
        'ERROR': 'HATA',
        'OK': 'SAĞLIKLI',
        'WARN': 'UYARI',
        'KEY_MISSING': 'ANAHTAR EKSİK',
        'CONFIGURED': 'YAPILANDIRILMIŞ',
        'CONNECTING': 'BAĞLANIYOR',
        'NOT_CONFIGURED': 'Yapılandırılmamış',
    }
    return mapping.get(str(value).upper(), str(value))


def _source_label(finding, fallback='CORE'):
    explicit = str(finding.get('source') or '').lower()
    event = finding.get('event') if isinstance(finding.get('event'), dict) else {}
    event_source = str(event.get('source') or '').lower()
    text = explicit or event_source
    if 'opnsense' in text:
        return 'OPNSENSE'
    if 'clamav' in text or 'file_team' in text:
        return 'CLAMAV'
    if 'audit' in text or 'journal' in text:
        return 'AUDIT'
    if 'suricata' in text or 'eve' in text:
        return 'SURICATA'
    if 'dns' in text:
        return 'DNS'
    if 'sys_proc' in text or 'process' in text or 'kernel' in text:
        return 'PROCESS'
    return fallback


def _finding_title(finding):
    for key in ('rule_name', 'title', 'summary', 'type'):
        value = finding.get(key)
        if value:
            return str(value)[:300]
    return 'Bulgu'


def _finding_rule_id(finding):
    value = finding.get('rule_id')
    if value:
        return str(value)
    matched = finding.get('matched_rules')
    if isinstance(matched, list) and matched:
        return str(matched[0])
    return None


def _finding_event_type(finding):
    event = finding.get('event') if isinstance(finding.get('event'), dict) else {}
    return str(
        finding.get('type') or event.get('action') or finding.get('kind') or '-'
    )[:120]


def _finding_entities(finding):
    event = finding.get('event') if isinstance(finding.get('event'), dict) else {}
    raw = event.get('raw') if isinstance(event.get('raw'), dict) else {}
    file_info = finding.get('FILE') if isinstance(finding.get('FILE'), dict) else {}
    audit = finding.get('AUDIT') if isinstance(finding.get('AUDIT'), list) else []
    paths = list(finding.get('paths') or [])
    if file_info.get('path'):
        paths.append(file_info['path'])
    ips = []
    for source in (finding, event, raw):
        for key in ('src_ip', 'dest_ip', 'dst_ip', 'ip', 'target_ip'):
            if source.get(key):
                ips.append(str(source[key]))
    processes = []
    for key in ('pid', 'ppid', 'cmd', 'exe', 'comm', 'process'):
        value = finding.get(key) or raw.get(key) or event.get(key)
        if value not in (None, ''):
            processes.append(str(value))
    for item in audit[:3]:
        if isinstance(item, dict):
            for key in ('pid', 'ppid', 'exe', 'comm', 'cmd'):
                if item.get(key) not in (None, ''):
                    processes.append(str(item[key]))
    target = file_info.get('path') or (paths[0] if paths else None)
    sha256 = file_info.get('sha256')
    return {
        'paths': [str(x) for x in paths[:20]],
        'ips': list(dict.fromkeys(ips))[:20],
        'processes': list(dict.fromkeys(processes))[:20],
        'path': target,
        'sha256': sha256,
    }


def _ticket_rows(db):
    if not _table_exists(db, 'tickets'):
        return []
    try:
        cur = db.execute('SELECT * FROM tickets ORDER BY rowid DESC LIMIT 5000')
        cols = [item[0] for item in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
    except sqlite3.Error:
        return []


def _tickets_by_finding(db):
    out = {}
    for row in _ticket_rows(db):
        finding_id = row.get('finding_id')
        if finding_id:
            out[str(finding_id)] = row
    return out


def _ticket_link(ticket):
    if not ticket:
        return None
    return {
        'ticket_id': ticket.get('ticket_id'),
        'status': ticket.get('status'),
        'level': ticket.get('ticket_level'),
        'severity': ticket.get('severity'),
        'false_positive': bool(ticket.get('false_positive')),
        'occurrence_count': ticket.get('occurrence_count'),
    }


def _normalize_core_finding(body, row_id, ticket_map, summary_only=False):
    finding = body.get('metadata', {}).get('finding') if isinstance(body, dict) else None
    if not isinstance(finding, dict):
        return None
    event = body.get('event') if isinstance(body.get('event'), dict) else {}
    entities = {} if summary_only else _finding_entities(finding)
    finding_id = str(finding.get('finding_id') or f'core:{row_id}')
    ts = _epoch(next((value for value in (finding.get('timestamp'), event.get('timestamp'),
                                          body.get('_record_created')) if value is not None and value != ''), None))
    ticket = ticket_map.get(finding_id)
    return {
        'finding_id': finding_id,
        'timestamp': ts,
        'title': _finding_title(finding),
        'classification': str(finding.get('classification') or 'suspicious'),
        'severity': str(finding.get('severity') or 'medium'),
        'confidence': str(finding.get('confidence') or 'medium'),
        'rule_id': _finding_rule_id(finding),
        'source': _source_label(finding, 'CORE'),
        'event_type': _finding_event_type(finding),
        'status': str(finding.get('status') or 'NEW'),
        'entities': entities,
        'process_name': None if summary_only else process_fields({'event': event, 'finding': finding})[0],
        'pid': None if summary_only else process_fields({'event': event, 'finding': finding})[1],
        'ticket': _ticket_link(ticket),
        'occurrences': finding.get('occurrences'),
        'summary': finding.get('summary') or finding.get('rule_name'),
        'recommendation': finding.get('recommendation'),
        'target_scope': finding.get('target_scope'),
        'raw': finding,
        'origin': 'core',
        'record_id': row_id,
    }


def _normalize_host_finding(body, finding_id, ticket_map, summary_only=False):
    if not isinstance(body, dict):
        return None
    entities = {} if summary_only else _finding_entities(body)
    ts = _epoch(body.get('last_seen') if body.get('last_seen') is not None else body.get('first_seen'))
    source = 'CORE'
    if body.get('AUDIT'):
        source = 'AUDIT'
    link = ticket_map.get(str(finding_id)) or {}
    if not link:
        # Host tickets may use a fingerprint or type; match conservatively.
        for ticket in ticket_map.values():
            if ticket.get('finding_id') == finding_id:
                link = ticket
                break
    return {
        'finding_id': str(finding_id),
        'timestamp': ts,
        'title': _finding_title(body),
        'classification': str(body.get('classification') or 'suspicious'),
        'severity': str(body.get('severity') or 'medium'),
        'confidence': str(body.get('confidence') or 'medium'),
        'rule_id': _finding_rule_id(body),
        'source': source,
        'event_type': _finding_event_type(body),
        'status': str(body.get('status') or body.get('CORRELATION', {}).get('status') or 'NEW'),
        'entities': entities,
        'process_name': None if summary_only else process_fields(body)[0],
        'pid': None if summary_only else process_fields(body)[1],
        'ticket': _ticket_link(link),
        'occurrences': body.get('occurrences'),
        'summary': body.get('summary') or body.get('title'),
        'raw': body,
        'origin': 'host',
    }


def _dns_items(core_db, limit=500):
    return [item for item in _rows(core_db, 'dns', limit) if isinstance(item, dict)]


def _dns_summary_from(items):
    requests = responses = 0
    domains = set()
    anomalies = 0
    nxdomain = 0
    missing = 0
    for item in items:
        typ = str(item.get('type') or '').lower()
        if typ == 'request':
            requests += 1
        elif typ == 'response':
            responses += 1
        if item.get('query'):
            domains.add(str(item['query']).rstrip('.').lower())
        flags = item.get('flags') if isinstance(item.get('flags'), list) else []
        if flags:
            anomalies += 1
        if str(item.get('rcode') or '').upper() == 'NXDOMAIN':
            nxdomain += 1
        if 'QUERY_NAME_MISSING' in flags:
            missing += 1
    return {
        'record_count': len(items),
        'dns_records': len(items),
        'request_count': requests,
        'response_count': responses,
        'unique_domains': len(domains),
        'anomaly_count': anomalies,
        'nxdomain_count': nxdomain,
        'query_name_missing_count': missing,
    }


def _otx_config_status():
    config = {}
    try:
        with open(OTX_CONFIG_PATH, encoding='utf-8') as stream:
            loaded = json.load(stream)
        if isinstance(loaded, dict):
            config = loaded
    except (OSError, ValueError, TypeError):
        config = {}
    api_key = str(config.get('api_key') or '')
    configured = bool(api_key) and len(api_key) >= 16
    try:
        from .config import load_with_policy
        effective, _, _ = load_with_policy()
        enabled = bool(effective.get('otx_enabled', False))
    except (OSError, ValueError):
        enabled = False
    return enabled, configured


def _suricata_eve_state(health):
    reader = health.get('reader') if isinstance(health.get('reader'), dict) else {}
    if not reader:
        return 'NO_DATA'
    lag = reader.get('lag_bytes')
    modified = reader.get('modified_at')
    if modified and time.time() - float(modified) > 300:
        return 'STALE'
    if lag is None:
        return 'UNKNOWN'
    return 'FLOWING'


def _proc_running(name):
    """Return RUNNING only when a matching process is definitely present."""
    target = str(name).lower()
    try:
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():
                continue
            try:
                cmdline = (entry / 'cmdline').read_bytes().replace(b'\x00', b' ').decode('utf-8', 'replace').lower()
            except OSError:
                continue
            if target in cmdline:
                return 'RUNNING'
    except OSError:
        pass
    return 'UNKNOWN'


# ---------------------------------------------------------------------------
# Core reader methods (existing API contract)
# ---------------------------------------------------------------------------

def m_state(key, default=None):
    with _connect() as db:
        return _state(db, key, default)


def m_rows(kind, limit=8):
    with _connect() as db:
        out = _rows(db, kind, limit)
    return out


def m_tickets(limit=50, status=None, level=None):
    try:
        db = _connect()
    except Exception:
        return []
    with db:
        if not _table_exists(db, 'tickets'):
            return []
        sql = 'SELECT * FROM tickets WHERE 1=1'
        params = []
        if status:
            sql += ' AND status=?'
            params.append(status)
        if level:
            sql += ' AND ticket_level=?'
            params.append(level)
        sql += ' ORDER BY rowid DESC LIMIT ?'
        params.append(limit)
        try:
            cur = db.execute(sql, params)
            rows = cur.fetchall()
            cols = [item[0] for item in cur.description]
        except sqlite3.Error:
            return []
        out = []
        ticket_map = {}
        for row in rows:
            item = dict(zip(cols, row))
            finding_id = item.get('finding_id')
            related_rule = None
            related_finding = None
            classification = None
            confidence = None
            # Ticket evidence column contains the original finding JSON.  Extract
            # only linked metadata; never expose unrelated raw JSON in the UI.
            evidence = item.get('evidence')
            if isinstance(evidence, str):
                parsed = _decode(evidence)
                if isinstance(parsed, dict):
                    classification = parsed.get('classification')
                    confidence = parsed.get('confidence')
                    related_rule = parsed.get('rule_id') or parsed.get('matched_rules')
                    if isinstance(related_rule, list):
                        related_rule = related_rule[0] if related_rule else None
            if finding_id:
                related_finding = str(finding_id)
                try:
                    row2 = db.execute(
                        "SELECT body FROM records WHERE kind='events' "
                        "AND json_extract(body, '$.metadata.finding.finding_id')=?",
                        (finding_id,),
                    ).fetchone()
                    if row2:
                        body = _decode(row2[0]) or {}
                        finding = body.get('metadata', {}).get('finding', {})
                        related_rule = finding.get('rule_id') or finding.get('matched_rules') or related_rule
                        if isinstance(related_rule, list):
                            related_rule = related_rule[0] if related_rule else None
                        classification = finding.get('classification') or classification
                        confidence = finding.get('confidence') or confidence
                except sqlite3.Error:
                    pass
            item['related_finding'] = related_finding
            item['related_rule'] = related_rule
            item['classification'] = classification
            item['confidence'] = confidence
            out.append(item)
        return out


def m_tickets_stats():
    try:
        with _connect() as db:
            if not _table_exists(db, 'tickets'):
                return {'total': None, 'by_status': {}, 'by_level': {}, 'data_state': 'NO_DATA'}
            stats = {'total': 0, 'by_status': {}, 'by_level': {}, 'data_state': 'OK'}
            try:
                for status, cnt in db.execute(
                    'SELECT status, COUNT(*) FROM tickets GROUP BY status'
                ):
                    stats['by_status'][status] = cnt
                    stats['total'] += cnt
                for level, cnt in db.execute(
                    'SELECT ticket_level, COUNT(*) FROM tickets GROUP BY ticket_level'
                ):
                    stats['by_level'][str(level)] = cnt
            except sqlite3.Error:
                pass
        return stats
    except Exception as exc:
        return {'total': None, 'by_status': {}, 'by_level': {}, 'data_state': 'UNKNOWN', 'error': str(exc)[:300]}


def m_ticket_detail(ticket_id):
    try:
        db = _connect()
    except Exception as exc:
        return {'available': False, 'data_state': 'UNKNOWN', 'error': str(exc)[:300]}
    with db:
        if not _table_exists(db, 'tickets'):
            return {'available': False, 'data_state': 'UNKNOWN', 'error': 'tickets table unavailable'}
        try:
            cur = db.execute('SELECT * FROM tickets WHERE ticket_id=?', (ticket_id,))
            row = cur.fetchone()
            if not row:
                return {'available': False, 'data_state': 'NO_DATA', 'ticket_id': ticket_id}
            cols = [item[0] for item in cur.description]
        except sqlite3.Error as exc:
            return {'available': False, 'data_state': 'UNKNOWN', 'error': str(exc)[:300]}
    item = dict(zip(cols, row))
    related_findings = []
    finding_id = item.get('finding_id')
    if finding_id:
        found = m_finding(finding_id)
        if found.get('available'):
            related_findings.append(found)
    timeline = []
    for key in ('notes', 'review_history'):
        value = item.get(key)
        if isinstance(value, str):
            parsed = _decode(value)
            if isinstance(parsed, list):
                for entry in parsed:
                    if isinstance(entry, dict):
                        timeline.append(entry)
    item['related_findings'] = related_findings
    item['timeline'] = sorted(timeline, key=lambda x: x.get('timestamp') or 0)
    item['evidence_parsed'] = _decode(item.get('evidence')) if isinstance(item.get('evidence'), str) else item.get('evidence')
    item['response_state'] = item.get('resolution') or item.get('status')
    item['audit_state'] = {'timeline_entries': len(item['timeline']), 'notes_present': bool(item.get('notes'))}
    return item


# Components that work inside other services and write no heartbeat.
NO_HEARTBEAT = frozenset(('dns_monitor', 'evidence', 'response'))


def m_workers():
    """Çalışan application worker durumları.

    Core state ve host state ayrı açılır; ikisi de read-only.
    """
    out = {}
    config_workers = {}

    def merge(payload, key):
        if not isinstance(payload, dict):
            return
        raw = dict(payload)
        raw_status = str(raw.get('status') or 'UNKNOWN').upper()
        aliases = {
            'IDLE': 'RUNNING',
            'READING': 'RUNNING',
            'BASELINED': 'RUNNING',
            'WAITING': 'DEGRADED',
            'WAITING_FOR_HOST_DB': 'DEGRADED',
            'STARTING': 'UNKNOWN',
            'ACTIVE': 'RUNNING',
            'OK': 'RUNNING',
            'ERROR': 'DEGRADED',
            'FAILED': 'DEGRADED',
            'PARTIAL': 'DEGRADED',
            'KEY_MISSING': 'DEGRADED',
        }
        if raw_status == 'RETIRED':
            # 2.2.42: a component removed from the product (ram_v2, the RAM
            # ClamAV engine) is not listed as "Veri alınamadı". Kaldırılan bileşen listelenmez.
            return
        status = aliases.get(raw_status, raw_status)
        if status not in ('RUNNING', 'DEGRADED', 'STOPPED', 'DISABLED', 'UNKNOWN', 'NOT_CONFIGURED'):
            # 'ok' alani string/0 olabilir; truthy kontrolu yerine acikca yorumla.
            ok = raw.get('ok')
            if isinstance(ok, str):
                ok = ok.strip().lower() in ('1', 'true', 'yes', 'ok')
            else:
                ok = bool(ok)
            status = 'RUNNING' if ok else 'UNKNOWN'
        observed=raw.get('updated_at') or raw.get('checked_at') or raw.get('last_check') or raw.get('last_run')
        max_age=120 if key=='otx_service' else 90 if key in ('journal','systemd_dbus','kernel','audit_bridge','clamav') else 45
        if status=='RUNNING' and (not isinstance(observed,(int,float)) or not 0<=time.time()-observed<=max_age):
            status='DEGRADED'
            raw['degraded_reason']='Health heartbeat missing or stale'
        # Required dedicated state key aliases.
        processed = None
        for candidate in (
            'processed', 'event_count', 'events_count',
            'events', 'process_count', 'record_count', 'unit_count',
            'dbus_message_count', 'total_lines',
        ):
            if isinstance(raw.get(candidate), (int, float)):
                processed = int(raw[candidate])
                break
        errors = None
        for candidate in ('errors', 'errors_count', 'error_count'):
            value = raw.get(candidate)
            if isinstance(value, (int, float)):
                errors = int(value)
                break
        last_error = raw.get('last_error') or raw.get('error') or ''
        out[key] = {
            'name': key,
            'status': status,
            'status_tr': _tr_status(status),
            'last_run': observed,
            'last_successful_event': raw.get('last_event'),
            'processed_count': processed,
            'error_count': errors,
            'last_error': str(last_error)[:500] if last_error else None,
            'degraded_reason': raw.get('degraded_reason') or (str(last_error)[:300] if status == 'DEGRADED' and last_error else None),
            'raw': raw,
        }

    try:
        with _connect() as db:
            for key, body in db.execute(
                "SELECT key, body FROM state WHERE key LIKE 'worker.%.health'"
            ).fetchall():
                name = key.split('.')[1]
                merge(_decode(body), name)
            for name, key in (
                ('audit', 'audit_health'),
                ('finding', 'finding_health'),
                ('gateway', 'gateway_health'),
                ('sentinel', 'sentinel_health'),
                ('suricata', 'eve_source'),
                ('suricata_guard', 'suricata_guard_health'),
                ('otx_service', 'otx_health'),
                ('udev', 'udev_health'),
            ):
                payload = _state(db, key)
                if payload:
                    merge(payload, name)
            policy = _state(db, 'policy_effective') or _state(db, 'policy_applied') or {}
            workers = policy.get('workers') if isinstance(policy, dict) else {}
            if isinstance(workers, dict):
                config_workers.update(workers)
            corr = _state(db, 'correlation_manager.health')
            if corr:
                merge(corr, 'correlation_manager')
    except sqlite3.Error:
        pass

    try:
        with _connect_host() as hdb:
            for key, body in hdb.execute(
                "SELECT key, body FROM state WHERE key LIKE 'worker.%.health'"
            ).fetchall():
                merge(_decode(body), key.split('.')[1])
            for name, key in (
                ('audit', 'audit_health'),
                ('finding', 'finding_health'),
                ('gateway', 'gateway_health'),
                ('sentinel', 'sentinel_health'),
            ):
                payload = _state(hdb, key)
                if payload:
                    merge(payload, name)
            policy = _state(hdb, 'policy_effective') or _state(hdb, 'policy_applied') or {}
            workers = policy.get('workers') if isinstance(policy, dict) else {}
            if isinstance(workers, dict):
                config_workers.update(workers)
    except (sqlite3.Error, FileNotFoundError):
        pass

    known = {
        'sys_proc', 'memory', 'udev', 'suricata_guard', 'systemd_dbus', 'audit', 'audit_bridge', 'journal',
        'finding', 'suricata', 'kernel', 'clamav',
        'correlation_manager', 'gateway', 'sentinel', 'response',
        'evidence', 'dns_monitor', 'otx_service',
    }
    for name in sorted(known | set(out)):
        if name not in out:
            out[name] = {
                'name': name,
                'status': 'UNKNOWN',
                'status_tr': _tr_status('UNKNOWN'),
                'last_run': None,
                'last_successful_event': None,
                'processed_count': None,
                'error_count': None,
                'last_error': None,
                'degraded_reason': None,
                'raw': {},
            }
        enabled = None
        for cfg_key in (name, name.replace('_bridge', ''), 'suricata_collector' if name == 'suricata' else '', 'dns_monitor' if name == 'dns_monitor' else ''):
            if cfg_key and isinstance(config_workers.get(cfg_key), dict):
                enabled = config_workers[cfg_key].get('enabled')
                break
        out[name]['configuration_enabled'] = enabled
        if name == 'otx_service':
            enabled = None  # Dedicated service health is not the legacy worker toggle.
            out[name]['purpose'] = 'Ayrı OTX servisinin gözlenen durumu; guard OTX ve eski worker farklı bileşenlerdir'
        if name == 'response':
            enabled = True  # 2.2.10: full protection keeps responses on (satsuma.full_protection)
        if enabled is False:
            out[name]['status'] = 'DISABLED'
            out[name]['status_tr'] = _tr_status('DISABLED')
        elif name in NO_HEARTBEAT and not out[name]['raw']:
            # These run inside other services and never write a heartbeat of
            # their own; "no data" was shown as a fault although nothing failed.
            out[name]['status'] = 'ACTIVE'
            out[name]['status_tr'] = 'Etkin · ayrı durum sinyali üretmez'
        elif not out[name]['raw'] and out[name]['status'] == 'UNKNOWN':
            out[name]['status_tr'] = 'Veri alınamadı'
    purposes = {'dns_monitor':'DNS olaylarını değerlendirir; bağımsız heartbeat üretmiyor', 'evidence':'İstek üzerine kanıt toplar; sürekli servis değildir', 'response':'Politika izin verdiğinde müdahale eder; bağımsız heartbeat üretmiyor', 'gateway':'Olay girişini ve yönlendirmeyi yürütür', 'correlation_manager':'Takım bulgularını ilişkilendirir', 'otx_service':'Ayrı OTX servisinin gözlenen durumu; guard OTX ve eski worker ayrı bileşenlerdir', 'memory':'Ana executable RAM kodunu dosyasıyla karşılaştırır; doğrulanan kod farkı müdahale için değerlendirilir'}
    for name,item in out.items():
        item['purpose']=purposes.get(name, name+' olay toplayıcısı')
        if not item['raw'] and item['status'] != 'ACTIVE':
            item['degraded_reason']='Bu bileşen için durum kaydı üretilmemiş; çalışma doğrulanamadı'
    return out


def m_teams():
    out = {}
    for db in (_connect(),):
        try:
            for key, body in db.execute(
                "SELECT key, body FROM state WHERE key LIKE 'team.%.health'"
            ).fetchall():
                parts = key.split('.')
                if len(parts) >= 2:
                    out[parts[1]] = _decode(body) or {}
        except sqlite3.Error:
            pass
        finally:
            db.close()
    return out


def m_health():
    with _connect() as db:
        return _state(db, 'health', {}) or {}


# ---------------------------------------------------------------------------
# Final dashboard read-model methods
# ---------------------------------------------------------------------------

def m_overview():
    core_state = 'UNKNOWN'
    core_error = None
    system = {
        'core_status': 'UNKNOWN',
        'uptime_seconds': None,
        'last_event': None,
        'telemetry_health': 'NO_DATA',
        'db_status': 'UNKNOWN',
        'reader_status': 'UNKNOWN',
        'data_state': 'UNKNOWN',
    }
    protection = {
        'active_rule_count': None,
        'response_enabled': False,
        'destructive_response_policy': False,
        'integrity_state': 'UNKNOWN',
        'otx_state': 'KEY_MISSING',
        'suricata_state': 'NO_DATA',
        'audit_state': 'UNKNOWN',
        'data_state': 'UNKNOWN',
    }
    findings = {'total': None, 'last_24h': None, 'by_classification': {}, 'by_classification_24h': {}, 'data_state': 'UNKNOWN'}
    tickets = {'total': None, 'by_status': {}, 'by_level': {}, 'data_state': 'UNKNOWN'}
    dns = {'record_count': None, 'request_count': None, 'response_count': None, 'unique_domains': None, 'anomaly_count': None, 'nxdomain_count': None, 'query_name_missing_count': None, 'data_state': 'UNKNOWN'}
    last_findings = []
    services = {'items': [], 'data_state': 'UNKNOWN'}
    try:
        with _connect() as db:
            core_state = 'OK'
            health = _state(db, 'health', {}) or {}
            early = _state(db, 'early_boot', {}) or {}
            protection['early_boot_state'] = early.get('state', 'UNKNOWN')
            protection['application_integrity'] = (_state(db, 'integrity_runtime', {}) or {}).get('status', 'UNKNOWN')
            critical = _state(db, 'critical_integrity', {}) or {}
            system['critical_integrity'] = critical
            auto_policy = _state(db, 'auto_action_policy', {}) or {}
            protection['auto_action_network_enabled'] = bool(auto_policy.get('network_enabled'))
            policy = _state(db, 'policy_effective') or _state(db, 'policy_applied') or {}
            workers = policy.get('workers') if isinstance(policy, dict) else {}
            if not isinstance(workers, dict):
                workers = {}
            reader = health.get('reader') if isinstance(health.get('reader'), dict) else {}
            system.update({
                'core_status': str(health.get('status') or 'UNKNOWN').upper(),
                'last_event': health.get('last_event'),
                'telemetry_health': _suricata_eve_state(health),
                'db_status': 'OK',
                'reader_status': 'OK' if health.get('reader') else ('NO_DATA' if not health else 'UNKNOWN'),
                'data_state': 'OK',
            })
            system['version'] = health.get('version')
            system['updated_at'] = health.get('updated_at')
            response_cfg = workers.get('response') if isinstance(workers.get('response'), dict) else {}
            protection.update({
                'response_enabled': bool(health.get('response_enabled') or response_cfg.get('enabled')),
                'otx_state': m_otx().get('status', 'UNKNOWN'),
                'suricata_state': _suricata_eve_state(health),
                'data_state': 'OK',
            })
            stats = m_tickets_stats()
            tickets.update(stats)
            tickets['data_state'] = 'OK'
            dns_items = _dns_items(db, 5000)
            dns.update(_dns_summary_from(dns_items))
            dns['data_state'] = 'OK'
    except Exception as exc:
        core_state = 'ERROR'
        core_error = str(exc)[:300]
        for item in (system, protection, findings, tickets, dns):
            item['data_state'] = 'UNKNOWN'

    result = m_findings(limit=5)
    if result['counts'] is not None:
        findings.update(result['counts'])
    findings['data_state'] = result['data_state']
    findings['sources'] = result['sources']
    findings['error'] = result['error']
    last_findings = result['items']
    audit = m_audit()
    protection['audit_state'] = audit.get('status', 'UNKNOWN')

    try:
        rules = m_rules()
        protection['active_rule_count'] = rules.get('active_total')
        protection['data_state'] = 'OK'
    except Exception:
        pass
    try:
        integrity = m_integrity()
        protection['integrity_state'] = integrity.get('status', 'UNKNOWN')
    except Exception:
        pass
    try:
        services = m_services()
    except Exception:
        services = {'items': [], 'data_state': 'UNKNOWN'}
    for service in (services.get('items') or []):
        name = str(service.get('name') or service.get('service') or '')
        if name == 'satsuma-core':
            system['uptime_seconds'] = service.get('uptime_seconds')
            system['service_status'] = service.get('status')
        elif name == 'satsuma-reader':
            system['reader_service_status'] = service.get('status')
    return {
        'health_summary': m_health_summary(),
        'system': system,
        'protection': protection,
        'findings': findings,
        'tickets': tickets,
        'dns': dns,
        'last_findings': last_findings,
        'services': services,
        'data_state': core_state,
        'error': core_error,
    }


def _finding_query(db, origin, filters=None):
    """Normalize inside SQLite; callers filter/order before applying LIMIT.

    Keep only the last row in the UDF cache: SQLite may evaluate the expression
    repeatedly for WHERE/ORDER BY, but we never retain the database in Python.
    No temporary tables, schema changes or writable connections are needed.
    """
    cached = [None, None]

    def normalize(body, rid, created, kind):
        key = (body, rid, created, kind)
        if key == cached[0]:
            return cached[1]
        data = _decode(body)
        item = None
        if isinstance(data, dict):
            if origin == 'host':
                data.setdefault('last_seen', created)
                item = _normalize_host_finding(data, rid, {}, summary_only=True)
            elif kind == 'events':
                event = data.get('event')
                if isinstance(event, dict) and event.get('category') == 'finding':
                    data['_record_created'] = created
                    item = _normalize_core_finding(data, rid, {}, summary_only=True)
            else:
                data.setdefault('classification', 'indicator')
                data.setdefault('severity', 'low')
                data.setdefault('type', data.get('kind') or 'finding')
                item = _normalize_core_finding(
                    {'metadata': {'finding': data}, '_record_created': created}, rid, {}, summary_only=True)
        if item is not None:
            item['record_key'] = json.dumps([origin, kind, rid], separators=(',', ':'))
            item['record_kind'] = kind
            item['record_id'] = rid
            from .presentation import SEVERITY, CLASSIFICATION, epoch
            item['_sort'] = (SEVERITY.get(item['severity'].lower(), 5),
                             CLASSIFICATION.get(item['classification'].lower(), 4),
                             -epoch(item['timestamp']))
            item.pop('raw', None)
        result = json.dumps(item, ensure_ascii=False) if item is not None else None
        cached[:] = [key, result]
        return result

    db.create_function('reader_finding', 4, normalize)
    db.create_function('reader_lower', 1, lambda value: str(value).lower() if value is not None else None)
    if origin == 'core':
        # JSON guards exclude ordinary events before expensive normalization.
        query = """SELECT reader_finding(body,id,created,kind) AS item FROM records
            WHERE kind='findings' OR (kind='events' AND
            CASE WHEN json_valid(body) THEN json_extract(body,'$.event.category')='finding' ELSE 0 END)"""
    else:
        query = "SELECT reader_finding(body,finding_id,last_seen,'findings') AS item FROM findings"
    filters = filters or {}
    if filters.get('_memory_family'):
        from .finding_index import restrict
        predicates=restrict(db,origin)
        if origin=='core':
            select="SELECT reader_finding(body,id,created,kind) AS item FROM records INDEXED BY reader_core_rule_v1 WHERE "
        else:
            select="SELECT reader_finding(body,finding_id,last_seen,'findings') AS item FROM findings INDEXED BY reader_host_rule_v1 WHERE "
        query=' UNION ALL '.join(select+predicate for predicate in predicates)
    record_key = filters.get('record_key')
    finding_id = filters.get('finding_id')
    if record_key:
        try:
            key_origin, kind, rid = json.loads(record_key)
        except (ValueError, TypeError):
            raise ValueError('invalid record_key')
        if key_origin != origin:
            query = 'SELECT NULL AS item WHERE 0'
        else:
            db.create_function('reader_identity', 0, lambda: rid)
            db.create_function('reader_kind', 0, lambda: kind)
            if origin == 'host':
                query += " WHERE finding_id=reader_identity() AND reader_kind()='findings'"
            else:
                query = """SELECT reader_finding(body,id,created,kind) AS item
                    FROM records WHERE id=reader_identity() AND kind=reader_kind()"""
    elif finding_id is not None:
        db.create_function('reader_identity', 0, lambda: str(finding_id))
        if origin == 'host':
            query += ' WHERE finding_id=reader_identity()'
        else:
            query = """SELECT reader_finding(body,id,created,kind) AS item FROM records
                WHERE kind IN ('events','findings') AND CASE WHEN json_valid(body) THEN
                coalesce(CASE WHEN kind='events' THEN json_extract(body,'$.metadata.finding.finding_id')
                ELSE json_extract(body,'$.finding_id') END, 'core:' || id)=reader_identity()
                ELSE 0 END"""
    return 'WITH normalized AS (' + query + ') '


def _finding_where(filters):
    clauses, params = ['item IS NOT NULL'], []
    for key in ('classification', 'severity', 'source', 'rule_id', 'status', 'finding_id', 'record_key'):
        if filters.get(key) is not None and filters[key] != '':
            clauses.append(("json_extract(item, '$." + key + "') = ?") if key in ('finding_id', 'record_key')
                           else ("reader_lower(json_extract(item, '$." + key + "')) = reader_lower(?)"))
            params.append(str(filters[key]))
    for key, op in (('date_from', '>='), ('date_to', '<=')):
        if filters.get(key) is not None:
            clauses.append("json_extract(item, '$.timestamp') " + op + ' ?')
            params.append(filters[key])
    if filters.get('text'):
        keys = ('finding_id', 'title', 'classification', 'severity', 'rule_id',
                'source', 'event_type', 'status', 'summary')
        text = " || ' ' || ".join("coalesce(json_extract(item, '$." + k + "'), '')" for k in keys)
        clauses.append('instr(reader_lower(' + text + '), reader_lower(?)) > 0')
        params.append(str(filters['text']))
    return ' AND '.join(clauses), params


def _query_findings(filters, limit, offset=0, include_raw=False):
    # Stable ordering for unchanged sources. Snapshots are per database, not
    # atomic across core/host. OFFSET pages can shift when telemetry changes.
    limit = min(2000, max(0, int(limit)))
    offset = max(0, int(offset))
    sources, streams = {}, []
    counts = {'total': 0, 'last_24h': 0,
              'by_classification': dict.fromkeys(('indicator', 'suspicious', 'likely', 'confirmed'), 0),
              'by_classification_24h': dict.fromkeys(('indicator', 'suspicious', 'likely', 'confirmed'), 0)}
    matched = 0
    where, params = _finding_where(filters)
    with ExitStack() as connections:
        for origin, connect, table in (('core', _connect, 'records'), ('host', _connect_host, 'findings')):
            try:
                db = connections.enter_context(connect())
                db.execute('BEGIN')
                if not _table_exists(db, table):
                    raise sqlite3.OperationalError(table + ' table unavailable')
                cte = _finding_query(db, origin, filters)
                summary = [] if include_raw else db.execute(cte + """SELECT
                    reader_lower(json_extract(item,'$.classification')), count(*),
                    sum(CASE WHEN json_extract(item,'$.timestamp') >= ? THEN 1 ELSE 0 END),
                    sum(CASE WHEN """ + where + """ THEN 1 ELSE 0 END)
                    FROM normalized WHERE item IS NOT NULL
                    GROUP BY reader_lower(json_extract(item,'$.classification'))""", [time.time() - 86400] + params).fetchall()
                cursor = db.execute(cte + 'SELECT item FROM normalized WHERE ' + where + """
                    ORDER BY json_extract(item,'$._sort[0]'), json_extract(item,'$._sort[1]'),
                    json_extract(item,'$._sort[2]'), json_extract(item,'$.record_key') LIMIT ?""",
                    params + [offset + limit]) if limit else iter(())
                streams.append((origin, db, cursor))
                for cls, total, recent, filtered in summary:
                    counts['total'] += total
                    matched += filtered or 0
                    if cls in counts['by_classification']:
                        counts['by_classification'][cls] += total
                        counts['by_classification_24h'][cls] += recent or 0
                        counts['last_24h'] += recent or 0
                sources[origin] = {'data_state': 'OK'}
            except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
                sources[origin] = {'data_state': 'UNKNOWN', 'error': str(exc)[:300]}

        def rows(origin, cursor):
            try:
                for row in cursor:
                    yield json.loads(row[0])
            except (sqlite3.Error, ValueError, TypeError) as exc:
                sources[origin] = {'data_state': 'UNKNOWN', 'error': str(exc)[:300]}

        # Merge ordered SQLite cursors lazily: Python retains one row per source
        # and the requested page, even for deep offsets.
        ordered = heapq.merge(*(rows(origin, cursor) for origin, _, cursor in streams),
                              key=lambda item: (*item['_sort'], item['record_key']))
        items = list(itertools.islice(ordered, offset, offset + limit))
        items = [item for item in items if sources[item['origin']]['data_state'] == 'OK']
        databases = {origin: db for origin, db, _ in streams}
        for item in items:
            db = databases[item['origin']]
            if item['origin'] == 'host':
                row = db.execute('SELECT body FROM findings WHERE finding_id=?', (item['record_id'],)).fetchone()
                raw = _decode(row[0]) if row else None
                full = _normalize_host_finding(raw, item['record_id'], {})
            else:
                row = db.execute('SELECT body,created FROM records WHERE id=?', (item['record_id'],)).fetchone()
                raw = _decode(row[0]) if row else None
                if item['record_kind'] == 'events':
                    full = _normalize_core_finding(raw, item['record_id'], {})
                    raw = raw.get('metadata', {}).get('finding')
                else:
                    full = _normalize_core_finding({'metadata': {'finding': raw}}, item['record_id'], {})
            for key in ('entities', 'process_name', 'pid'):
                item[key] = full[key]
            if include_raw:
                item['raw'] = raw
    for item in items:
        item.pop('_sort', None)
    ready = sum(value['data_state'] == 'OK' for value in sources.values())
    return {'items': items, 'counts': counts if ready else None,
            'total_count': counts['total'] if ready else None,
            'filtered_count': matched if ready else None, 'shown_count': len(items),
            'offset': offset, 'limit': limit, 'has_more': offset + len(items) < matched,
            'data_state': 'OK' if ready == 2 else ('PARTIAL' if ready else 'UNKNOWN'),
            'sources': sources, 'filters': filters,
            'error': '; '.join(k + ': ' + v['error'] for k, v in sources.items() if 'error' in v) or None}


def m_findings(class_filter=None, severity=None, source=None, rule_id=None,
               date_from=None, date_to=None, text=None, limit=200, **kwargs):
    filters = {
        'classification': class_filter or kwargs.get('classification'),
        'severity': severity, 'source': source,
        'rule_id': rule_id or kwargs.get('rule') or kwargs.get('rule_name'),
        'status': kwargs.get('status'),
        'date_from': _epoch(date_from if date_from is not None else kwargs.get('start', kwargs.get('from'))),
        'date_to': _epoch(date_to if date_to is not None else kwargs.get('end', kwargs.get('to'))),
        'text': text or kwargs.get('search') or kwargs.get('q'),
    }
    return _query_findings(filters, limit, kwargs.get('offset', 0))


def m_finding(finding_id, record_key=None):
    if finding_id is None or finding_id == '':
        return {'available': False, 'data_state': 'NO_DATA', 'finding_id': finding_id}
    result = _query_findings({'finding_id': finding_id, 'record_key': record_key}, 1, include_raw=True)
    for item in result['items']:
        detail = dict(item)
        raw = item.get('raw') if isinstance(item.get('raw'), dict) else {}
        detail.update({
            'available': True,
            'data_state': result['data_state'],
            'source_states': result['sources'],
            'error': result['error'],
            'what_happened': item.get('summary') or item.get('title'),
            'why_flagged': raw.get('analysis') or raw.get('CORRELATION') or raw.get('rule_name'),
            'evidence': raw.get('evidence') or raw.get('AUDIT'),
            'sources': [item.get('source')] if item.get('source') else [],
            'related_rule': item.get('rule_id'),
            'correlation': raw.get('CORRELATION') or raw.get('analysis'),
            'ticket': item.get('ticket'),
            'action': raw.get('action') or raw.get('actions'),
            'recommendation': raw.get('recommendation'),
            'target_scope': raw.get('target_scope'),
            'last_status': item.get('status'),
        })
        if item.get('origin')=='core':
            from .process_followup import read as read_followup,evidence_summary
            with _connect() as db:
                detail['process_followup']=read_followup(db,finding_id,details=True)
                detail['process_followup'].setdefault('evidence_summary',evidence_summary(raw))
        return detail
    return {'available': False, 'data_state': result['data_state'] if result['error'] else 'NO_DATA',
            'finding_id': finding_id, 'error': result['error'], 'sources': result['sources']}

def m_dns(limit=500):
    try:
        with _connect() as db:
            if not _table_exists(db, 'records'):
                return {'record_count': None, 'request_count': None, 'response_count': None,
                        'unique_domains': None, 'anomaly_count': None, 'nxdomain_count': None,
                        'query_name_missing_count': None, 'items': [], 'data_state': 'UNKNOWN',
                        'error': 'records table unavailable'}
            items = _dns_items(db, limit)
    except Exception as exc:
        return {'record_count': None, 'request_count': None, 'response_count': None,
                'unique_domains': None, 'anomaly_count': None, 'nxdomain_count': None,
                'query_name_missing_count': None, 'items': [], 'data_state': 'UNKNOWN',
                'error': str(exc)[:300]}
    result = _dns_summary_from(items)
    result['items'] = [{
        'timestamp': item.get('timestamp'),
        'domain': item.get('query'),
        'query': item.get('query'),
        'rrtype': item.get('rrtype'),
        'direction': item.get('type') or ('response' if item.get('answers') else 'request'),
        'resolver': item.get('resolver'),
        'result_ips': item.get('ips') or [a.get('data') for a in (item.get('answers') or []) if isinstance(a, dict)],
        'rcode': item.get('rcode'),
        'flags': item.get('flags') or [],
        'source': 'DNS',
    } for item in items]
    result['data_state'] = 'OK'
    return result


def m_dns_summary(limit=5000):
    result = m_dns(limit=limit)
    for key in ('items',):
        result.pop(key, None)
    return result


def m_dns_records(limit=500):
    return m_dns(limit=limit)


def m_otx():
    enabled, configured = _otx_config_status()
    result = {
        'configured': configured,
        'enabled': enabled,
        'status': 'KEY_MISSING' if not configured else 'DISABLED' if not enabled else 'CONFIGURED',
        'status_tr': None,
        'last_successful_update': None,
        'last_attempt': None,
        'indicator_count': None,
        'cache_count': None,
        'last_error': None,
        'api_key_exposed': False,
        'data_state': 'OK',
    }
    try:
        with _connect() as db:
            override = _state(db, 'operator_otx_policy', {}) or {}
            if type(override.get('enabled')) is bool:
                enabled = override['enabled']
                result['enabled'] = enabled
            health = _state(db, 'otx_health', {}) or {}
            cache = _state(db, 'otx_cache')
            result['last_successful_update'] = health.get('last_success') or (
                health.get('updated_at') if str(health.get('status')) == 'active' else None
            )
            result['last_attempt'] = health.get('updated_at')
            # Bounded evidence window; indicator downloads are not block evidence.
            from .presentation import action_view, epoch
            evidence=[]
            for item in _rows(db, 'otx', 200):
                view=dict(item);view['timestamp']=view.get('timestamp') or view.get('_record_created')
                view['target']=view.get('indicator') or view.get('ip') or view.get('domain')
                view['outcome']='OTX sorgu sonucu; engelleme doğrulanmadı'
                evidence.append(view)
            for item in _rows(db, 'actions', 500):
                if item.get('reason')=='otx_confirmed' or item.get('source')=='otx' or str(item.get('action','')).startswith('otx.'):evidence.append(action_view(item))
            evidence.sort(key=lambda x:epoch(x.get('timestamp')),reverse=True)
            result['items']=evidence[:200]
            result['match_count']=sum(1 for x in evidence if x.get('reason')=='otx_confirmed' or x.get('event')=='otx_confirmed')
            result['verified_block_count']=sum(1 for x in evidence if x.get('traffic_drop_verified') is True)
            result['counts_scope']='Son 200 OTX kaydı ve 500 aksiyon içindeki kanıtlar; toplam ömür sayacı değildir'
            result['historical_error']=health.get('last_error') if not health.get('error') else None
            if isinstance(cache, dict):
                result['cache_count'] = len(cache)
                result['indicator_count'] = len(cache)
            try:
                otx_records = _count(db, 'otx')
                if otx_records and otx_records > int(result['indicator_count'] or 0):
                    result['indicator_count'] = otx_records
            except Exception:
                pass
            error = health.get('error') if str(health.get('status')).lower() in ('error','failed','fail') else None
            if error:
                result['last_error'] = re.sub(r'(api[_-]?key|token|secret)\s*[=:]\s*\S+', r'\1=***', str(error))[:500]
            state = str(health.get('status') or '').lower()
            if configured and enabled:
                if state in ('active', 'idle'):
                    result['status'] = 'ACTIVE'
                elif state in ('error', 'failed', 'fail'):
                    result['status'] = 'ERROR'
                elif state in ('starting', 'connecting', 'loading'):
                    result['status'] = 'CONNECTING'
                else:
                    result['status'] = 'CONFIGURED'
            elif configured and not enabled:
                result['status'] = 'DISABLED'
            else:
                result['status'] = 'KEY_MISSING'
            result['status_tr'] = {
                'KEY_MISSING': 'ANAHTAR EKSİK',
                'CONFIGURED': 'YAPILANDIRILMIŞ',
                'CONNECTING': 'BAĞLANIYOR',
                'ACTIVE': 'AKTİF',
                'ERROR': 'HATA',
                'DISABLED': 'DEVRE DIŞI',
            }.get(result['status'], result['status'])
    except Exception as exc:
        result['data_state'] = 'UNKNOWN'
        result['error'] = str(exc)[:300]
    if not result['status_tr']:
        result['status_tr'] = result['status']
    return result


def m_services():
    try:
        try:
            from .service_health import service_status
        except ImportError:
            # Script olarak calistirildiginda (python3 dashboard_api.py)
            # paket baglami olmaz; paket kokunu sys.path'e ekleyip absolute import.
            _pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if _pkg_root not in sys.path:
                sys.path.insert(0, _pkg_root)
            from satsuma.service_health import service_status
        services = service_status()
        return {'items': services, 'data_state': 'OK' if services else 'NO_DATA'}
    except Exception as exc:
        required = [
            'satsuma-core.service', 'satsuma-core-audit.service',
            'satsuma-core-finding.service',
            'satsuma-core-gateway.service', 'satsuma-core-sentinel.service',
            'satsuma-core-otx.service', 'satsuma-teams.service',
            'satsuma-reader.service',
        ]
        return {
            'items': [{
                'service': name,
                'name': name[:-8] if name.endswith('.service') else name,
                'status': 'UNKNOWN', 'status_tr': 'BİLİNMİYOR',
                'active': None, 'pid': None, 'uptime_seconds': None,
                'last_failure': None, 'restart_count': None,
            } for name in required],
            'data_state': 'UNKNOWN',
            'error': str(exc)[:300],
        }


def m_rules():
    try:
        try:
            from .smart_rules import SmartRuleEngine
        except ImportError:
            _pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if _pkg_root not in sys.path:
                sys.path.insert(0, _pkg_root)
            from satsuma.smart_rules import SmartRuleEngine
        engine = SmartRuleEngine(RULES_DIR, include_managed=True)
        stats = engine.stats()
        from .action_contract import canonical_action, DESTRUCTIVE_ACTIONS
        from .rule_response import CATALOG_PATH
        try:
            catalog = {r['rule_id']: r for r in json.loads(CATALOG_PATH.read_text())['rules']}
        except (OSError, ValueError, KeyError):
            catalog = {}
        policies, verdicts, outcomes, runtime = {}, {}, {}, {}
        try:
            with _connect() as db:
                policies = _state(db, 'rule_response_requirements', {}) or {}
                verdicts = _state(db, 'rule_response_verdicts', {}) or {}
                outcomes = _state(db, 'rule_intervention_latest', {}) or {}
                runtime = _state(db, 'deepseek_runtime', {}) or {}
        except (OSError, sqlite3.Error):
            pass
        active = []
        for rule in engine.rules:
            stop_actions=[action for action in engine._normalize_actions(rule.get('actions') or [])
                          if canonical_action(action) in DESTRUCTIVE_ACTIONS]
            rid = rule.get('_id') or rule.get('id')
            from .enforcement import eligible
            central_candidate = not rule.get('_ai_package_digest') and eligible({**rule, 'rule_id':rid})
            proposal = rule.get('_response_proposal') or (catalog.get(rid) or {}).get('proposed_response') or {}
            verdict = verdicts.get(rid) or {}
            current = 0 <= time.time() - verdict.get('checked_at', 0) <= 60
            outcome = outcomes.get(rid)
            active.append({
                'rule_id': rid,
                'detection_state': 'loader_accepted',
                'central_policy_candidate': bool(central_candidate),
                'candidate_scope': 'eligibility only; authorization and verified exit are separate',
                'required_evidence_count': max((policies.get(rid) or {}).get('minimum_sources', 1), proposal.get('minimum_sources',1) if rule.get('_ai_package_digest') else 1),
                'proposed_evidence_count': proposal.get('minimum_sources'),
                'verified_evidence_count': verdict.get('verified') if current else None,
                'missing_conditions': verdict.get('missing') if current else ['No current authoritative evidence verdict'],
                'response_proposal': proposal,
                'policy_decision': verdict.get('policy_decision') if current else 'not_evaluated',
                'signature_state': 'trusted_package_verified' if rule.get('_ai_package_digest') else 'legacy_baseline_transition_pending',
                'activation_state': 'loader_accepted_runtime_unknown',
                'intervention_result': outcome or {'status': 'UNKNOWN', 'executed': None},
                'name': rule.get('name'),
                'classification': rule.get('classification'),
                'severity': rule.get('severity'),
                'source': rule.get('category') or rule.get('_file'),
                'category': rule.get('category'),
                'actions': rule.get('actions') or [],
                'direct_stop_actions': stop_actions,
                'direct_stop_defined': bool(stop_actions),
                'behavior': __import__('satsuma.presentation',fromlist=['rule_behavior']).rule_behavior(rule.get('actions') or []),
                'enabled': True,
                'active': True,
                'implementation_status': rule.get('implementation_status', 'CURRENT_TELEMETRY'),
                'file': rule.get('_file'),
            })
        future = []
        try:
            import yaml
            for path in sorted(FUTURE_SPECS_DIR.glob('*.yaml')):
                loaded = yaml.safe_load(path.read_text(encoding='utf-8')) or []
                for spec in loaded:
                    if not isinstance(spec, dict):
                        continue
                    future.append({
                        'rule_id': spec.get('id'),
                        'name': spec.get('name'),
                        'classification': spec.get('classification_ceiling') or 'indicator',
                        'severity': spec.get('severity'),
                        'source': 'FUTURE_TELEMETRY',
                        'actions': spec.get('actions') or [],
                        'enabled': False,
                        'active': False,
                        'implementation_status': spec.get('implementation_status', 'NEEDS_TELEMETRY'),
                    })
        except Exception:
            future = []
        return {
            'active_total': int(stats.get('total_rules') or 0),
            'direct_stop_total': sum(row['direct_stop_defined'] for row in active),
            'central_policy_candidate_total': sum(row['central_policy_candidate'] for row in active),
            'without_direct_stop_total': sum(not row['direct_stop_defined'] for row in active),
            'native_prevention_verified_total': None,
            'classification_counts': stats.get('classifications') or {},
            'category_counts': stats.get('categories') or {},
            'invalid_files': stats.get('invalid_files') or 0,
            'load_errors': stats.get('load_errors') or [],
            'rules': active,
            'future_total': len(future),
            'future': future,
            'future_active': 0,
            'data_state': 'OK' if not stats.get('load_errors') else 'DEGRADED',
        }
    except Exception as exc:
        return {
            'active_total': None, 'classification_counts': {}, 'rules': [],
            'future_total': None, 'future': [], 'future_active': 0,
            'data_state': 'UNKNOWN', 'error': str(exc)[:300],
        }




def m_audit(limit=50):
    result = {
        'status': 'UNKNOWN', 'status_tr': 'BİLİNMİYOR',
        'recent_events': [], 'privilege_escalation_observations': [],
        'file_process_evidence': [], 'correlation_result': None,
        'related_finding': None, 'related_ticket': None,
        'data_state': 'UNKNOWN',
    }
    state_db = None
    try:
        try:
            state_db = _connect_host()
        except FileNotFoundError:
            state_db = _connect()
        health = _state(state_db, 'audit_health', {}) or {}
        raw_status = str(health.get('status') or 'UNKNOWN').upper()
        aliases = {'READING': 'RUNNING', 'STARTING': 'UNKNOWN', 'IDLE': 'RUNNING', 'ERROR': 'DEGRADED', 'FAILED': 'DEGRADED'}
        result['status'] = aliases.get(raw_status, raw_status) if raw_status else 'UNKNOWN'
        result['status_tr'] = _tr_status(result['status'])
        result['last_run'] = health.get('updated_at')
        result['last_error'] = health.get('last_error') or health.get('error')
        events = []
        for item in _rows(state_db, 'audit', limit):
            if not isinstance(item, dict):
                continue
            paths = item.get('paths') if isinstance(item.get('paths'), list) else []
            evidence_paths = [p.get('path') for p in paths if isinstance(p, dict) and p.get('path')]
            event = {
                'timestamp': item.get('timestamp'),
                'type': ','.join(item.get('types') or []) or 'AUDIT_EVENT',
                'process': item.get('comm') or item.get('exe') or item.get('proctitle'),
                'exe': item.get('exe'),
                'pid': item.get('pid'),
                'uid': item.get('uid'),
                'auid': item.get('auid'),
                'success': item.get('success'),
                'paths': evidence_paths[:5],
                'category': 'Güvenlik incelemesi gerekli' if 'AVC' in (item.get('types') or []) or item.get('success')=='no' else 'Oturum hareketi' if any(t.startswith('USER_') or t.startswith('CRED_') for t in (item.get('types') or [])) else 'Sistem olayı',
                'summary': __import__('satsuma.presentation', fromlist=['audit_summary']).audit_summary(item),
                'raw': item.get('raw'), 'serial': item.get('serial'),
            }
            events.append(event)
        result['recent_events'] = events
        result['privilege_escalation_observations'] = [
            event for event in events
            if event.get('uid') is not None and event.get('auid') is not None
            and str(event.get('uid')) != str(event.get('auid'))
        ][:20]
        result['file_process_evidence'] = [
            {
                'timestamp': event.get('timestamp'),
                'process': event.get('process'),
                'path': (event.get('paths') or [None])[0],
                'success': event.get('success'),
            }
            for event in events if event.get('paths') or event.get('process')
        ][:30]
        # Correlation: host finding whose audit candidates point at these records.
        if _table_exists(state_db, 'findings'):
            for finding_id, body in state_db.execute(
                "SELECT finding_id, body FROM findings ORDER BY last_seen DESC LIMIT 200"
            ).fetchall():
                data = _decode(body) or {}
                audit_items = data.get('AUDIT') if isinstance(data.get('AUDIT'), list) else []
                if audit_items:
                    result['related_finding'] = finding_id
                    result['correlation_result'] = {
                        'finding_id': finding_id,
                        'candidate_count': len(audit_items),
                        'confidence': (data.get('CORRELATION') or {}).get('confidence'),
                    }
                    break
        if result['related_finding']:
            try:
                with _connect() as coredb:
                    ticket = coredb.execute(
                        'SELECT ticket_id,status FROM tickets WHERE finding_id=? LIMIT 1',
                        (result['related_finding'],),
                    ).fetchone()
                    if ticket:
                        result['related_ticket'] = {'ticket_id': ticket[0], 'status': ticket[1]}
            except sqlite3.Error:
                pass
        result['data_state'] = 'OK' if events else 'NO_DATA'
    except Exception as exc:
        result['data_state'] = 'UNKNOWN'
        result['error'] = str(exc)[:300]
    finally:
        if state_db is not None:
            try:
                state_db.close()
            except Exception:
                pass
    return result


def m_suricata(limit=100):
    result = {
        'eve_input': {'state': 'NO_DATA', 'status_tr': 'VERİ YOK'},
        'process_state': 'UNKNOWN',
        'last_event': None,
        'alert_count': None,
        'dns_event_count': None,
        'network_alert_summary': [],
        'related_finding': None,
        'data_state': 'UNKNOWN',
    }
    try:
        with _connect() as db:
            health = _state(db, 'health', {}) or {}
            result['eve_input'] = {
                'state': _suricata_eve_state(health),
                'status_tr': _tr_status(_suricata_eve_state(health)),
                'reader': health.get('reader') or {},
                'eve_path': health.get('eve_path'),
                'telemetry_status': str(health.get('status') or 'UNKNOWN').upper(),
            }
            result['last_event'] = health.get('last_event')
            result['alert_count'] = _count(db, 'alerts')
            result['dns_event_count'] = _count(db, 'dns')
            alerts = _rows(db, 'alerts', limit)
            summary = []
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                summary.append({
                    'timestamp': alert.get('timestamp'),
                    'signature': alert.get('signature') or alert.get('category'),
                    'severity': alert.get('severity'),
                    'src_ip': alert.get('src_ip') or (alert.get('sources') or [None])[0],
                    'dest_ip': alert.get('dest_ip') or (alert.get('destinations') or [None])[0],
                    'protocol': alert.get('proto'),
                    'classification': alert.get('classification'),
                    'related_finding': None,
                })
            result['network_alert_summary'] = summary
            result['process_state'] = _proc_running('suricata')
            result['data_state'] = 'OK'
    except Exception as exc:
        result['data_state'] = 'UNKNOWN'
        result['error'] = str(exc)[:300]
    return result


def m_response(limit=100):
    result = {
        'response_enabled': False,
        'destructive_response_enabled': False,
        'destructive_response_policy_state': 'UNAVAILABLE',
        'persistent_block_count': None,
        'reconciled_block_count': None,
        'last_firewall_mutation': None,
        'last_response_action': None,
        'blocked_ips': [],
        'response_errors': [],
        'owned_only': True,
        'data_state': 'UNKNOWN',
    }
    try:
        with _connect() as db:
            health = _state(db, 'health', {}) or {}
            policy = _state(db, 'policy_effective') or _state(db, 'policy_applied') or {}
            workers = policy.get('workers') if isinstance(policy, dict) else {}
            response_cfg = workers.get('response') if isinstance(workers.get('response'), dict) else {}
            response_enabled = bool(health.get('response_enabled') or response_cfg.get('enabled'))
            result['response_enabled'] = response_enabled
            result['lan'] = _state(db, 'satsuma_lan_state', {}) or {}
            result['subnet'] = _state(db, 'subnet_health', {}) or {}
            result['dns_filter'] = _state(db, 'dns_filter_health', {}) or {}
            result['dns_policy'] = _state(db, 'dns_policy', {}) or {}
            response_policy = policy.get('response_policy') if isinstance(policy, dict) else {}
            if not isinstance(response_policy, dict):
                response_policy = {}
            destructive_configured = bool(
                response_cfg.get('destructive_response_enabled')
                or (response_cfg.get('destructive') or {}).get('enabled')
                or response_policy.get('destructive_enabled')
                or response_policy.get('destructive', {}).get('enabled')
            )
            result['destructive_response_enabled'] = destructive_configured
            boot = _state(db, 'early_boot', {}) or {}
            runtime = _state(db, 'integrity_runtime', {}) or {}
            from .intervention_guard import evaluate
            class ReadOnlyTrustState:
                def get(self, key, default=None):
                    return _state(db, key, default)
            decision = evaluate(ReadOnlyTrustState())
            result['verification'] = decision
            result['execution_ready'] = bool(response_enabled and decision['allowed'])
            result['execution_state'] = 'READY' if result['execution_ready'] else 'INTEGRITY_OR_POLICY_NOT_VERIFIED'
            if result['destructive_response_enabled']:
                result['destructive_response_policy_state'] = 'ACTIVE'
            blocks = _state(db, 'persistent_blocks', {}) or {}
            if not isinstance(blocks, dict):
                blocks = {}
            result['persistent_block_count'] = len(blocks)
            result['blocked_ips'] = [
                {
                    'ip': ip,
                    'reason': (meta or {}).get('reason') if isinstance(meta, dict) else None,
                    'added_at': (meta or {}).get('added_at') if isinstance(meta, dict) else None,
                    'expires_at': (meta or {}).get('expires_at') if isinstance(meta, dict) else None,
                    'nft_set': (meta or {}).get('nft_set') if isinstance(meta, dict) else None,
                    'source': 'SATSUMA_OWNED',
                }
                for ip, meta in list(blocks.items())[:200]
            ]
            result['blocked_ip_list'] = [item['ip'] for item in result['blocked_ips']]
            guard_path = Path('/var/lib/satsuma-core/suricata-otx-guard/guard.sqlite')
            # Field photo 2026-10-25: an unreadable Suricata guard database made
            # the whole page say "no data" while the OTX blocks were listed.
            result['suricata_guard_state'] = 'ABSENT'
            try:
                if guard_path.is_file():
                    # 2.2.38: same read-only path as core.db (works with no writer open).
                    with _connect_at(str(guard_path)) as guard_db:
                        guard_items = [{'ip': ip, 'reason': reason, 'added_at': ts, 'source': 'SURICATA_GUARD',
                                        'nft_set': 'blocked_v6' if ':' in ip else 'blocked_v4'}
                                       for ip, ts, reason in guard_db.execute('SELECT ip,ts,reason FROM blocks ORDER BY ts DESC LIMIT 200')]
                    result['suricata_guard_block_count'] = len(guard_items)
                    result['blocked_ips'].extend(guard_items)
                    result['blocked_ip_list'] = list(dict.fromkeys(item['ip'] for item in result['blocked_ips']))
                    result['suricata_guard_state'] = 'OK'
            except (OSError, sqlite3.Error) as exc:
                result['suricata_guard_state'] = 'UNREADABLE'
                result['suricata_guard_error'] = str(exc)[:200]
            firewall = _state(db, 'nft_policy', {}) or {}
            if isinstance(firewall, dict):
                result['reconciled_block_count'] = int(
                    (firewall.get('already_present') or 0) + (firewall.get('restored') or 0)
                )
                result['last_firewall_mutation'] = firewall.get('timestamp')
                result['response_errors'] = firewall.get('errors') or []
            actions = _rows(db, 'actions', limit)
            for action in actions:
                if not isinstance(action, dict):
                    continue
                status = str(action.get('status') or '')
                if status in ('ip_blocked', 'nft_element_restored', 'process_killed', 'file_quarantined'):
                    result['last_response_action'] = action
                    break
            error_rows = _rows(db, 'errors', limit)
            for err in error_rows:
                if not isinstance(err, dict):
                    continue
                component = str(err.get('component') or '')
                if component in ('response', 'firewall', 'command'):
                    result['response_errors'].append(err)
            result['data_state'] = 'OK'
    except Exception as exc:
        result['data_state'] = 'UNKNOWN'
        result['error'] = str(exc)[:300]
    from .nft_inventory import snapshot
    result['kernel_inventory'] = snapshot()
    result['listed_record_count'] = len(result.get('blocked_ips') or [])
    result['persisted_core_count'] = result.get('persistent_block_count')
    result['counts_scope'] = 'listed records are bounded database evidence, not current kernel membership'
    return result


def m_integrity():
    result = {
        'status': 'UNKNOWN',
        'status_tr': 'BİLİNMİYOR',
        'last_verification': None,
        'manifest_entry_count': None,
        'mismatched_file_count': None,
        'last_error': None,
        'data_state': 'UNKNOWN',
    }
    try:
        with _connect() as db:
            result['early_boot'] = _state(db, 'early_boot', {}) or {}
            result['application_integrity'] = _state(db, 'integrity_runtime', {}) or {}
            health = _state(db, 'integrity_runtime', {}) or _state(db, 'self_integrity_health', {}) or {}
            raw = str(health.get('status') or '').upper()
            mapping = {
                'VALID': 'HEALTHY',
                'DEGRADED': 'WARNING',
                'INTEGRITY_VIOLATION': 'FAILED',
                'HEALTHY': 'HEALTHY',
                'WARNING': 'WARNING',
                'FAILED': 'FAILED',
            }
            result['status'] = mapping.get(raw, raw or 'UNKNOWN')
            result['status_tr'] = {
                'HEALTHY': 'SAĞLIKLI',
                'WARNING': 'UYARI',
                'FAILED': 'BAŞARISIZ',
                'UNKNOWN': 'Veri alınamadı',
            }.get(result['status'], 'BİLİNMİYOR')
            result['last_verification'] = health.get('checked_at') or health.get('updated_at')
            result['mismatched_file_count'] = health.get('violation_count')
            result['last_error'] = health.get('error') or health.get('last_error')
            if not result['last_error']:
                for err in _rows(db, 'errors', 50):
                    if isinstance(err, dict) and 'integrity' in str(err.get('component') or '').lower():
                        result['last_error'] = err.get('error')
                        break
            result['data_state'] = 'OK' if raw else 'NO_DATA'
    except Exception as exc:
        result['data_state'] = 'UNKNOWN'
        result['error'] = str(exc)[:300]
    result['summary'] = m_health_summary()
    for path in INTEGRITY_MANIFEST_PATHS:
        try:
            manifest = json.loads(Path(path).read_text(encoding='utf-8'))
            files = manifest.get('files') if isinstance(manifest, dict) else None
            if isinstance(files, list):
                result['manifest_entry_count'] = len(files)
                break
        except (OSError, ValueError):
            continue
    return result


def m_health_summary():
    from .status_view import health_summary
    from .self_health import read_report
    try:
        with _connect() as db:
            return health_summary(_state(db, 'integrity_runtime', {}) or {}, _state(db, 'early_boot', {}) or {}, read_report())
    except Exception:
        return health_summary({}, {}, read_report())


def m_system_health():
    from .dashboard_auth import admin_hash_status
    result = {
        'admin_credential': {'configured': admin_hash_status()['configured']},
        'application_policy': {},
        'integrity_monitor': __import__('satsuma.self_health',fromlist=['read_report']).read_report(Path('/var/lib/satsuma-core/integrity/status.json')),
        'app_control': __import__('satsuma.app_firewall',fromlist=['status']).status(),
        'self_health': __import__('satsuma.self_health', fromlist=['read_report']).read_report(),
        'otx': m_otx(),
        'rescue': __import__('satsuma.self_health', fromlist=['read_report']).read_report(Path('/run/satsuma-rescue/status.json')),
        'core_db_accessible': False,
        'host_db_accessible': False,
        'normalized_event_cursor': None,
        'last_normalized_event': None,
        'teams_cursor': None,
        'rule_engine_loaded': None,
        'reader_socket': {'path': SOCKET_PATH, 'exists': os.path.exists(SOCKET_PATH)},
        'queue_backlog': None,
        'error_counters': {},
        'last_exception': None,
        'config_version': None,
        'policy_schema_version': None,
        'core_db_schema_version': None,
        'host_db_schema_version': None,
        'data_state': 'UNKNOWN',
    }
    try:
        from .app_firewall import policy as load_policy
        result['application_policy'] = {'enabled': load_policy().get('enabled', False)}
    except Exception as exc:
        result['application_policy'] = {'error': str(exc)[:200]}
    core = None
    host = None
    try:
        core = _connect()
        result['core_db_accessible'] = True
        result['network_identity'] = _state(core, 'network_identity', {})
        cursor = _state(core, 'brain.smart_rules.cursor.v2')
        result['normalized_event_cursor'] = cursor
        try:
            max_id = int(core.execute(
                "SELECT COALESCE(MAX(id),0) FROM records WHERE kind='normalized'"
            ).fetchone()[0] or 0)
            result['queue_backlog'] = max(0, max_id - int(cursor or 0))
            row = core.execute(
                "SELECT body FROM records WHERE kind='normalized' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row:
                outer = _decode(row[0]) or {}
                event = (outer.get('event') or {})
                result['last_normalized_event'] = {
                    'timestamp': (event.get('event') or {}).get('timestamp'),
                    'raw_id': outer.get('raw_id'),
                }
        except (sqlite3.Error, ValueError, TypeError):
            pass
        try:
            result['error_counters']['core_errors'] = _count(core, 'errors')
        except Exception:
            result['error_counters']['core_errors'] = None
        errors = _rows(core, 'errors', 1000)
        by_component = {}
        for err in errors:
            if isinstance(err, dict):
                component = str(err.get('component') or 'unknown')
                by_component[component] = by_component.get(component, 0) + 1
        result['error_counters']['by_component'] = by_component
        if errors and isinstance(errors[0], dict):
            result['last_exception'] = {
                'timestamp': errors[0].get('timestamp') or errors[0].get('_record_created'),
                'component': errors[0].get('component'),
                'error': str(errors[0].get('error') or '')[:500],
            }
        policy = _state(core, 'policy_saved') or _state(core, 'policy_effective') or {}
        if isinstance(policy, dict):
            result['config_version'] = policy.get('revision')
            result['policy_schema_version'] = policy.get('schema_version')
        try:
            result['core_db_schema_version'] = int(core.execute('PRAGMA user_version').fetchone()[0])
        except sqlite3.Error:
            pass
        teams = {}
        try:
            for key, body in core.execute(
                "SELECT key, body FROM state WHERE key LIKE 'team.%.health'"
            ).fetchall():
                item = _decode(body) or {}
                teams[key] = item.get('updated_at')
            result['teams_cursor'] = teams
        except sqlite3.Error:
            pass
    except Exception as exc:
        result['core_error'] = str(exc)[:300]
    finally:
        if core is not None:
            try:
                core.close()
            except Exception:
                pass
    try:
        host = _connect_host()
        result['host_db_accessible'] = True
        try:
            result['host_db_schema_version'] = int(host.execute('PRAGMA user_version').fetchone()[0])
        except sqlite3.Error:
            pass
        try:
            host_errors = _count(host, 'host_errors')
            result['error_counters']['host_errors'] = host_errors
        except Exception:
            pass
    except Exception as exc:
        result['host_error'] = str(exc)[:300]
    finally:
        if host is not None:
            try:
                host.close()
            except Exception:
                pass
    try:
        rules = m_rules()
        result['rule_engine_loaded'] = rules.get('data_state') == 'OK'
        result['rule_count'] = rules.get('active_total')
    except Exception:
        result['rule_engine_loaded'] = False
    result['summary'] = m_health_summary()
    result['data_state'] = 'OK' if (result['core_db_accessible'] or result['host_db_accessible']) else 'UNKNOWN'
    return result


def m_capabilities():
    """Reader yetenekleri: control-plane yazma destegi yok."""
    return {
        'ticket_update': False,
        'ticket_statuses': [],
        'read_only': True,
        'host_findings_read_only': True,
        'admin_auth_required': False,
    }


def m_research_queue():
    with _connect() as db:
        if not _table_exists(db, 'rule_adapter_queue'):
            return {'items': [], 'data_state': 'NO_DATA'}
        rows = db.execute("SELECT rule_id,source,technique,created_at,status FROM rule_adapter_queue WHERE status IN ('pending','pending_review','approved_for_signing','signed','signing_failed','activation_failed') ORDER BY created_at DESC LIMIT 200").fetchall()
        return {'items': [dict(zip(('rule_id','source','technique','created_at','status'), row)) for row in rows], 'data_state': 'OK'}


def m_memory_health():
    """Indexed state reads only; never enumerate findings or other workers."""
    with _connect() as db:
        return {'collector': _state(db, 'worker.memory.health', {}) or {},
                'ram_v2': _state(db, 'worker.ram_v2.health', {}) or {},
                'data_state': 'OK'}


def m_memory_defense():
    health = m_memory_health()
    result = _query_findings({'_memory_family':True},2000)
    result['count'] = len(result['items'])
    result['collector'] = health['collector']
    result['ram_v2'] = health['ram_v2']
    from .process_followup import read as read_followup
    with _connect() as db:
        for row in result['items']:
            if row.get('origin')!='core':continue
            followup=read_followup(db,row['finding_id'])
            row['process_state']=followup['summary']
            row['process_decision']=followup.get('decision_summary','Karar kaydı yok')
            row['related_processes']=followup.get('related_count',0)
            row['process_followup']=followup
    return result


def m_network_defense():
    result=m_findings(limit=2000)
    result['items']=[r for r in result.get('items',[]) if any(str(r.get('rule_id','')).startswith(p) for p in ('SATSUMA-NET-','SATSUMA-C2-','SATSUMA-EXFIL-','SATSUMA-LAT-')) or str(r.get('source','')).lower() in ('suricata','dns','network')]
    result['count']=len(result['items'])
    result['telemetry']=m_suricata()
    result['collector']=m_workers().get('suricata') or {}
    result['discovery']=m_state('network_discovery', {}) or {}
    result['devices']=list((m_state('network_devices', {}) or {}).values())
    result['scope']='Bu bilgisayarda toplanan trafik kayıtları; tüm yerel ağın izlenmesi doğrulanmadı'
    return result


def m_security_scanners():
    from .security_scan import commands
    result={'items': [], 'engines': {name: {'installed': command is not None,
             'status': 'NOT_RUN' if command else 'UNAVAILABLE'} for name,command in commands()},
             'scope': 'Bu bilgisayarda yerel dosya ve sistem taraması; uzak cihaz için ajan gerekir',
             'data_state': 'UNKNOWN', 'health': {}}
    try:
        with _connect_host() as db:
            result['items']=_rows(db,'security_scan',100)
            result['health']=_state(db,'security_scan_health',{}) or {}
            # 2.2.15: program audit proposals and restorable quarantine.
            audit=_state(db,'binary_audit',{}) or {}
            result['binary_audit']={k:audit.get(k) for k in ('updated_at','counts','error','virustotal','quarantined')}
            result['proposals']=[i['quarantine_proposal'] for i in audit.get('items',[]) if i.get('quarantine_proposal')]
            ssh=_state(db,'ssh_keys',{}) or {}
            result['ssh_pending']=ssh.get('pending',[])
            result['sshd_open']=ssh.get('sshd_open')
            result['mitm_watch']=_state(db,'mitm_watch',{}) or {}
            # 2.2.48: hidden-process findings, open and closed, for the antivirus page.
            hidden={'open':[],'closed':{}}
            for (body,) in db.execute("SELECT body FROM findings WHERE finding_id LIKE 'unhide:hidden_pid:%' "
                                      "ORDER BY last_seen DESC LIMIT 500"):
                try:finding=json.loads(body)
                except (TypeError,ValueError):continue
                obj=finding.get('item') or {}
                if finding.get('status')=='REVIEW':
                    hidden['open'].append({'pid':obj.get('pid'),'executable':obj.get('executable'),
                                           'cmdline':obj.get('cmdline'),'timestamp':finding.get('timestamp')})
                else:
                    key=finding.get('resolution') or finding.get('status')
                    hidden['closed'][key]=hidden['closed'].get(key,0)+1
            result['hidden']=hidden
        from .scan_quarantine import list_quarantine
        try:result['quarantine']=list_quarantine()
        except OSError:result['quarantine']=[]
        result['data_state']='OK'
        for item in result['items']:
            engine=result['engines'].get(item.get('tool'))
            if engine is not None and 'last_result' not in engine:
                engine['last_result']=item
    except (OSError,sqlite3.Error) as exc:
        result['error']=str(exc)[:250]
    return result


_PROVENANCE = {'at': 0.0, 'data': None}
PROVENANCE_SECONDS = 600


def m_host_provenance():
    """Read-only OS/deployment/package report, collected at most every ten minutes (2.2.45).

    It runs rpm -qa, rpm-ostree status and bootc status. The panel asked for it
    every three seconds; bootc's temporary self-copy then raised
    SATSUMA-FILELESS-002 each time (field 2026-11-18).
    En fazla on dakikada bir toplanır; panel her üç saniyede istiyordu.
    """
    import copy
    import threading
    lock = _PROVENANCE.setdefault('lock', threading.Lock())
    with lock:
        if _PROVENANCE['data'] is not None and 0 <= time.time() - _PROVENANCE['at'] < PROVENANCE_SECONDS:
            return copy.deepcopy(_PROVENANCE['data'])
        data = _m_host_provenance()
        data['collected_at'] = time.time()
        _PROVENANCE.update(at=time.time(), data=copy.deepcopy(data))
        return data


def _m_host_provenance():
    from .host_provenance import collect
    data = collect()
    from .host_risk_integration import collect_risk
    cached_python = {}
    try:
        with _connect_host() as db:
            cached_python = _state(db, 'python_audit', {}) or {}
    except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
        data['errors']['python_audit_state'] = type(exc).__name__
    # Cached advisory information is local and potentially stale.
    risk = collect_risk(data['packages']['names'], state=cached_python)
    data['integrated_risk'] = risk
    from .cve_verification import collect_cve_evidence
    from .trust_verification import ostree_signature_observation
    from .boot_chain_audit import collect as collect_boot_chain
    data['boot_chain_evidence'] = collect_boot_chain()
    from .tpm_integrity_guard import collect as collect_tpm_handles
    data['tpm_integrity_evidence'] = collect_tpm_handles()
    from .tpm_public_inventory import collect_public
    data['tpm_public_evidence'] = collect_public(handle_inventory=data['tpm_integrity_evidence'])
    data['tpm_quote_evidence'] = {'status': 'EXTERNAL_QUOTE_NOT_SUBMITTED', 'quote_signature_verified': False,
         'platform_identity_verified': False, 'trusted_boot_verified': False,
         'note': 'Offline tpm_quote_verifier aracinda bagimsiz nonce, onayli AK ve PCR referansi gerekir'}
    data['tpm_ek_identity_evidence'] = {'status': 'EXTERNAL_EK_CERTIFICATE_NOT_SUBMITTED',
         'ek_certificate_verified': False, 'ek_ak_binding_verified': False,
         'platform_identity_verified': False,
         'note': 'Offline tpm_trust_bundle aracina bagimsiz CA/EK pinleri ve quote kaniti gerekir'}
    data['tpm_credential_activation_evidence'] = {
        'status': 'EXTERNAL_ACTIVATION_NOT_SUBMITTED',
        'credential_activation_verified': False, 'ek_ak_binding_verified': False,
        'platform_identity_verified': False,
        'note': 'Bagimsiz dogrulayici tpm_credential_activation issue/verify ile tek kullanimlik kanit ister'}
    data['cve_evidence'] = collect_cve_evidence()
    data['ostree_signature_evidence'] = (ostree_signature_observation() if data.get('mode') == 'rpm-ostree' else {'status': 'NOT_OSTREE'})
    data['iso_signature_evidence'] = {'status': 'NOT_SUBMITTED', 'verified': False, 'note': 'Signed CHECKSUM and independently pinned Fedora fingerprint required'}
    from .deployment_attestation import bootc_signature_policy_observation
    data['signed_deployment_reference'] = {'status': 'NOT_SUBMITTED', 'verified': False,
         'note': 'Use offline signed manifest, detached signature and independent signer fingerprint via deployment_attestation CLI'}
    data['bootc_policy_evidence'] = (bootc_signature_policy_observation() if data.get('mode') == 'bootc'
                                    else {'status': 'NOT_BOOTC', 'verified': False})
    rows = []
    boot_chain = data['boot_chain_evidence']
    rows.extend([
        {'kind': 'UEFI Secure Boot', 'name': 'Firmware boot policy',
         'signal': boot_chain['secure_boot']['status'],
         'detail': 'Yerel EFI gozlemi; imza zinciri ya da sistem butunlugu kaniti degil'},
        {'kind': 'TPM aygiti', 'name': 'TPM evidence', 'signal': boot_chain['tpm']['status'],
         'detail': 'Aygit varligi bagimsiz TPM attestasyonu degil'},
        {'kind': 'TPM PCR gunlugu', 'name': 'Measured boot log',
         'signal': boot_chain['pcr_log']['status'],
         'detail': 'Yerel gunluk denetimi; PCR quote ve guvenilir referans eslesmesi yok'},
    ])
    rows.append({'kind': 'TPM kalici nesne envanteri', 'name': 'Persistent + NV',
                 'signal': data['tpm_integrity_evidence']['status'],
                 'detail': 'Sadece yerel GetCapability; dis baseline ve nesne icerigi dogrulanmadi'})
    rows.append({'kind': 'TPM acik nesne kimligi', 'name': 'Persistent Name + NV metadata',
                 'signal': data['tpm_public_evidence']['status'],
                 'detail': 'Yerel TPM public veri; harici baseline olmadan kimlik/firmware dogrulamasi degil'})
    rows.append({'kind': 'TPM quote dogrulamasi', 'name': 'Bagimsiz dogrulayici',
                 'signal': data['tpm_quote_evidence']['status'],
                 'detail': 'AK/PCR dis referansi ve nonce olmadan basarili attestasyon iddia edilmez'})
    rows.append({'kind': 'TPM EK ve AK baglantisi', 'name': 'Bagimsiz kimlik dogrulama',
                 'signal': data['tpm_ek_identity_evidence']['status'],
                 'detail': 'EK sertifikasi ve quote ayni TPM kaniti degildir; AK-EK credential activation gerekir'})
    # 2.2.38: these two were collected and shown in the summary text but had no row.
    # 2.2.38: bu ikisi toplanıyor ve özet metinde görünüyordu ama satırı yoktu.
    rows.append({'kind': 'TPM credential activation', 'name': 'AK-EK tek kullanimlik kanit',
                 'signal': data['tpm_credential_activation_evidence']['status'],
                 'detail': 'Bagimsiz dogrulayici olmadan AK-EK baglantisi VERIFIED sayilmaz'})
    rows.append({'kind': 'ISO imza kaniti', 'name': 'Fedora ISO / imzali CHECKSUM',
                 'signal': data['iso_signature_evidence']['status'],
                 'detail': 'Imzali CHECKSUM ve bagimsiz Fedora parmak izi olmadan ISO dogrulanmis sayilmaz; kurulu OS kaniti degil'})
    for entry in data['cve_evidence']['items']:
        rows.append({'kind': 'CVE surum karsilastirmasi', 'name': entry['cve'] + ' / ' + entry['package'],
                     'signal': entry['applicability'], 'detail': entry['advisory'] + ' · yerel metadata; istismar kaniti degil'})
    if data['cve_evidence']['status'] != 'LOCAL_VERSION_COMPARED':
        rows.append({'kind': 'Kontrol eksigi', 'name': 'CVE paket surumu',
                     'signal': data['cve_evidence']['status'], 'detail': 'DNF5 onbellegi veya RPM karsilastirmasi kullanilamadi'})
    rows.append({'kind': 'Bagimsiz deployment referansi', 'name': 'OSTree / bootc',
                 'signal': data['signed_deployment_reference']['status'],
                 'detail': 'Imzali dis referans olmadan calisan sistem VERIFIED sayilmaz'})
    if data.get('mode') == 'bootc':
        rows.append({'kind': 'bootc imza politikasi', 'name': 'containers policy',
                     'signal': data['bootc_policy_evidence']['status'],
                     'detail': 'Yerel politika gozlemi; imza ve boot butunlugu kaniti degil'})
    rows.append({'kind': 'OSTree imza kaniti', 'name': 'Deployment',
                 'signal': data['ostree_signature_evidence']['status'],
                 'detail': 'Yerel anahtarlar bagimsiz dogrulanmadan guvenilir ilan edilmez'})
    for advisory in risk['advisories']['items']:
        rows.append({'kind': 'Fedora guvenlik guncellemesi', 'name': advisory['package'],
                     'signal': advisory['severity'],
                     'detail': advisory['advisory'] + ' · onbellek adayi; CVE dogrulamasi degil'})
    for entry in risk['python_audit']['items']:
        rows.append({'kind': 'Python sezgisel bulgu', 'name': entry['path'],
                     'signal': str(entry['points']) + ' puan',
                     'detail': ', '.join(entry['rules'])[:360] + ' · zararlilik kaniti degil'})
    for path in risk['python_audit'].get('modified', []):
        rows.append({'kind': 'Degismis paketli Python', 'name': path,
                     'signal': 'butunluk farki', 'detail': 'Onceki Python tarama kaydi; yeniden dogrulama gerekli'})
    if risk['advisories']['status'] != 'CACHE_OBSERVED':
        rows.append({'kind': 'Kontrol eksigi', 'name': 'dnf5 security advisory',
                     'signal': risk['advisories']['status'], 'detail': 'Onbellek veya dnf5 kullanilamadi'})
    if risk['python_audit']['status'] != 'CACHED':
        rows.append({'kind': 'Kontrol eksigi', 'name': 'python_audit',
                     'signal': 'NOT_SCANNED', 'detail': 'Ayrı Python taramasi henuz kaydedilmemis'})
    for deployment in data['deployments']:
        if deployment['booted']:
            rows.append({'kind': 'OSTree deployment', 'name': deployment['checksum'][:18],
                         'signal': 'booted', 'detail': deployment['origin']})
        for field, packages in deployment['layer_changes'].items():
            for name in packages:
                rows.append({'kind': 'RPM katmani', 'name': name, 'signal': field,
                             'detail': 'Envanter kaydi; zararlilik tespiti degil'})
    for item in data['script_exposure']:
        rows.append({'kind': 'Dosya yetkisi', 'name': item['path'],
                     'signal': item['signal'], 'detail': item['severity']})
    for item in data['unit_entrypoints']:
        if item['commands'] or item['signal'] != 'unit_declaration':
            rows.append({'kind': 'Satsuma systemd birimi', 'name': item['path'],
                         'signal': item['signal'],
                         'detail': ' | '.join(item['commands'])[:360] or item['authority']})
    for source, error in data['errors'].items():
        rows.append({'kind': 'Kontrol eksigi', 'name': source, 'signal': error,
                     'detail': 'Bu kontrole ait dogrulama yapilamadi'})
    data.update(items=rows[:512], count=len(rows), data_state='DEGRADED' if (data['errors'] or risk['advisories']['status'] != 'CACHE_OBSERVED' or risk['python_audit']['status'] != 'CACHED') else 'OK')
    return data


def m_database_catalog():
    from .database_view import catalog
    result={'databases':{},'errors':{},'data_state':'OK'}
    for name,connect in (('core',_connect),('host',_connect_host)):
        try:
            with connect() as db:result['databases'][name]=catalog(db)
        except (OSError,sqlite3.Error) as exc:
            result['errors'][name]=str(exc)[:200];result['data_state']='DEGRADED'
    return result


def m_database_page(params):
    from .database_view import page
    source=params.get('database','core')
    if source not in ('core','host'):raise ValueError('Unknown database')
    with (_connect() if source=='core' else _connect_host()) as db:
        return page(db,params.get('table','records'),kind=params.get('kind'),
                    offset=params.get('offset',0),limit=params.get('limit',50))


def m_records_overview(params):
    """Every record kind in both databases, named and counted (record_catalog)."""
    from .record_catalog import overview
    return overview((('core', _connect), ('host', _connect_host)), hours=params.get('hours', 24))


def m_records_explained(params):
    """Newest records of one kind as plain sentences with masked raw bodies."""
    from .record_catalog import explained
    source = params.get('database', 'core')
    if source not in ('core', 'host'):
        raise ValueError('Unknown database')
    with (_connect() if source == 'core' else _connect_host()) as db:
        return explained(db, params.get('kind', ''), offset=params.get('offset', 0), limit=params.get('limit', 50))


def m_logbook(params):
    """All records of both databases as one readable log (2.2.47)."""
    from .record_catalog import timeline
    return timeline((('core', _connect), ('host', _connect_host)), view=params.get('view', 'important'),
                    hours=params.get('hours', 24), search=params.get('search', ''), before=params.get('before'),
                    limit=params.get('limit', 100))


def m_stopped_processes(params):
    from .database_view import stopped
    with _connect() as db:return stopped(db,offset=params.get('offset',0),limit=params.get('limit',50))


def m_process_approval_notice():
    """Only a bounded count, never PID, request ID or evidence, via Reader IPC.

    The write/decision channel stays authenticated separately.  Missing DB
    or schema is an error state, never an invented zero pending count.
    """
    try:
        with _connect() as db:
            if not _table_exists(db, 'process_approvals'):
                return {'status': 'UNAVAILABLE', 'enabled': None, 'pending_count': None}
            enabled = _state(db, 'interactive_process_test_mode', False) is True
            if not enabled:
                return {'status': 'DISABLED', 'enabled': False, 'pending_count': 0}
            now = time.time()
            count = db.execute(
                "SELECT COUNT(*) FROM process_approvals WHERE state='pending' "
                "AND created<=? AND expires>=?", (now, now)
            ).fetchone()[0]
            return {'status': 'OK', 'enabled': True,
                    'pending_count': min(int(count), 64)}
    except (sqlite3.Error, OSError, ValueError, TypeError):
        return {'status': 'UNAVAILABLE', 'enabled': None, 'pending_count': None}


def _recent_records(db, kinds, hours, limit):
    """(created, body) of the newest records of ``kinds`` in the window; bounded."""
    from .record_catalog import _window_start
    cutoff = time.time() - max(1, min(24 * 30, float(hours))) * 3600
    start = _window_start(db, cutoff)
    marks = ','.join('?' for _ in kinds)
    result = {kind: [] for kind in kinds}
    for kind, created, body in db.execute(
            f'SELECT kind, created, body FROM records WHERE id>=? AND created>=? AND kind IN ({marks}) ORDER BY id DESC LIMIT ?',
            (start, cutoff, *kinds, max(1, min(20000, int(limit))))):
        value = _decode(body)
        if isinstance(value, dict):
            finding = value.get('finding') if isinstance(value.get('finding'), dict) else value
            if kind == 'events':
                meta = value.get('metadata') if isinstance(value.get('metadata'), dict) else {}
                finding = meta.get('finding') if isinstance(meta.get('finding'), dict) else None
                if finding is None:
                    continue
                kind = 'findings'
            result.setdefault(kind, []).append((created, finding if kind == 'findings' else value))
    return result


def _home_info():
    """Evidence for satsuma.home_view, read-only; a missing part stays missing."""
    from .self_health import read_report
    info = {'reachable': True}
    try:
        info['app'] = __import__('satsuma.app_firewall', fromlist=['status']).status()
    except Exception as exc:
        info['app'] = {'status': 'UNAVAILABLE', 'error': str(exc)[:200]}
    info['health'] = read_report()
    info['summary'] = m_health_summary()
    info['approvals'] = m_process_approval_notice()
    try:
        info['otx'] = m_otx()
    except Exception:
        info['otx'] = {}
    try:
        from .dashboard_auth import admin_hash_status
        info['admin_configured'] = bool(admin_hash_status().get('configured'))
    except Exception:
        info['admin_configured'] = None
    try:
        with _connect() as db:
            for key, field, default in (('enforcement_policy', 'enforcement', None), ('interactive_process_test_mode', 'test_mode', False),
                                        ('dns_policy', 'dns_policy', {}), ('dns_filter_health', 'dns_health', {}),
                                        ('network_identity', 'network_identity', {}), ('critical_integrity', 'critical_integrity', {})):
                info[field] = _state(db, key, default)
    except Exception as exc:
        info['reachable'] = False
        info['error'] = str(exc)[:200]
    if not isinstance(info.get('enforcement'), dict) or type((info.get('enforcement') or {}).get('enabled')) is not bool:
        info['enforcement'] = {'enabled': True, 'source': 'default'}
    return info


def m_home(params=None):
    """2.2.45 home page: verdict, what waits for the user, layers, recent activity."""
    from .home_view import home
    info = _home_info()
    records = {'findings': [], 'actions': []}
    try:
        with _connect() as db:
            records = _recent_records(db, ('findings', 'events', 'actions'), 24, 6000)
    except Exception as exc:
        info['activity_error'] = str(exc)[:200]
    result = home(info, records.get('findings', []), records.get('actions', []))
    result['data_state'] = 'OK' if info.get('reachable') else 'UNKNOWN'
    result['version'] = __import__('satsuma').__version__
    return result


def m_activity(params=None):
    """Everything that happened in the window, repeats folded (satsuma.home_view.group_activity)."""
    from .home_view import group_activity, activity_counts
    params = params or {}
    hours = max(1, min(24 * 30, float(params.get('hours', 24) or 24)))
    try:
        with _connect() as db:
            records = _recent_records(db, ('findings', 'events', 'actions'), hours, 20000)
    except Exception as exc:
        return {'items': [], 'data_state': 'UNKNOWN', 'error': str(exc)[:300], 'hours': hours}
    rows = group_activity(records.get('findings', []), records.get('actions', []), limit=int(params.get('limit', 300) or 300))
    wanted = params.get('outcome')
    if wanted:
        rows = [row for row in rows if row['outcome'] == wanted]
    text = str(params.get('search') or '').strip().lower()
    if text:
        rows = [row for row in rows if text in ' '.join(str(row.get(k) or '') for k in ('title', 'subject', 'rule_id', 'ip', 'domain')).lower()]
    return {'items': rows, 'counts': activity_counts(rows, hours=hours), 'hours': hours, 'data_state': 'OK'}


def m_maintenance_report(params=None):
    """Last maintenance kit report (satsuma.maintenance), read-only."""
    from .self_health import read_report
    report = read_report(Path('/var/lib/satsuma-core/maintenance/last.json'))
    if report.get('status') == 'STALE':
        report['status'] = 'OLD'   # the kit runs every six hours; older than 15 minutes is normal
    return report


def m_protection(params=None):
    """Every protection switch and list as it is now, read-only (2.2.45 Koruma page).

    Values the store does not hold stay None, so the panel shows "Bilinmiyor"
    instead of guessing. Pending process approvals and app rules need the
    operator lock; only counts are here.
    """
    result = {'data_state': 'OK'}
    try:
        with _connect() as db:
            get = lambda key, default=None: _state(db, key, default)
            enforcement = get('enforcement_policy', None)
            result['enforcement'] = enforcement.get('enabled') if isinstance(enforcement, dict) and type(enforcement.get('enabled')) is bool else True
            result['test_mode'] = get('interactive_process_test_mode', False) is True
            result['auto_network'] = (get('auto_action_policy', {}) or {}).get('network_enabled')
            lan = (get('satsuma_lan_state', {}) or {}).get('enabled')
            result['lan_access'] = (not lan) if type(lan) is bool else True
            result['subnet_protection'] = (get('subnet_protection_policy', {}) or {}).get('enabled')
            otx = get('operator_otx_policy', {}) or {}
            result['otx_enabled'] = otx.get('enabled')
            result['otx_blocker'] = otx.get('blocker_enabled')
            dns = get('dns_policy', {}) or {}
            result['dns_filter'] = bool(dns.get('enabled')) if 'enabled' in dns else None
            result['dns_upstream'] = dns.get('upstream')
            result['dns_health'] = get('dns_filter_health', {}) or {}
            result['allowed_domains'] = sorted(get('dns_allowed_domains', []) or [])[:500]
            result['allow_ips'] = list(get('operator_allow_ips', []) or [])[:500]
            result['network_blocks'] = [row for row in (get('manual_network_blocks', []) or []) if isinstance(row, dict)][:256]
            from .custom_dns_lists import status as list_status

            class _View:
                def get(self, key, default=None):
                    return _state(db, key, default)
            result['custom_lists'] = list_status(_View())
    except Exception as exc:
        result.update(data_state='UNKNOWN', error=str(exc)[:300])
    result['approvals'] = m_process_approval_notice()
    try:
        app = __import__('satsuma.app_firewall', fromlist=['status']).status()
        result['app'] = {'status': app.get('status'), 'enabled': app.get('enabled'), 'pending': app.get('pending') or [],
                         'rule_count': len(app.get('rules') or {}) + len(app.get('application_rules') or {})}
    except Exception as exc:
        result['app'] = {'status': 'UNAVAILABLE', 'error': str(exc)[:200]}
    try:
        from .egress_profiles import describe, load
        result['egress'] = describe(load())
    except Exception as exc:
        result['egress'] = {'error': str(exc)[:200]}
    try:
        response = m_response(limit=200)
        result['blocked_ips'] = response.get('blocked_ips') or []
    except Exception:
        result['blocked_ips'] = []
    return result


METHODS = {
    'home': lambda p: m_home(p),
    'activity': lambda p: m_activity(p),
    'maintenance_report': lambda p: m_maintenance_report(p),
    'protection': lambda p: m_protection(p),
    'process_approval_notice': lambda p: m_process_approval_notice(),
    'database_catalog': lambda p: m_database_catalog(),
    'database_page': lambda p: m_database_page(p),
    'stopped_processes': lambda p: m_stopped_processes(p),
    'exec_guard_events': lambda p: __import__('satsuma.exec_guard_view',fromlist=['events']).events(kind=p.get('kind'), limit=p.get('limit',50)),
    'records_overview': lambda p: m_records_overview(p),
    'records_explained': lambda p: m_records_explained(p),
    'logbook': lambda p: m_logbook(p),
    'vpn_proxy': lambda p: m_state('vpn_proxy',{'status':'NOT_RUN','items':[]}),
    'security_scanners': lambda p: m_security_scanners(),
    'host_provenance': lambda p: m_host_provenance(),
    'health_summary': lambda p: m_health_summary(),
    'app_control': lambda p: __import__('satsuma.app_firewall',fromlist=['status']).status(),
    'memory_defense': lambda p: m_memory_defense(),
    'memory_health': lambda p: m_memory_health(),
    'network_defense': lambda p: m_network_defense(),
    'research_queue': lambda p: m_research_queue(),
    'state': lambda p: m_state(p.get('key'), p.get('default')),
    'rows': lambda p: m_rows(p.get('kind'), p.get('limit', 8)),
    'tickets': lambda p: m_tickets(p.get('limit', 50), p.get('status'), p.get('level')),
    'ticket_detail': lambda p: m_ticket_detail(p.get('ticket_id')),
    'tickets_stats': lambda p: m_tickets_stats(),
    'capabilities': lambda p: m_capabilities(),
    'workers': lambda p: m_workers(),
    'teams': lambda p: m_teams(),
    'health': lambda p: m_health(),
    'overview': lambda p: m_overview(),
    'findings': lambda p: m_findings(
        p.get('classification'), p.get('severity'), p.get('source'),
        p.get('rule_id') or p.get('rule'), p.get('date_from'), p.get('date_to'),
        p.get('text') or p.get('search') or p.get('q'), p.get('limit', 200),
        rule=p.get('rule'), search=p.get('search'), q=p.get('q'),
        start=p.get('start', p.get('from')), end=p.get('end', p.get('to')),
        offset=p.get('offset', 0), status=p.get('status'),
    ),
    'finding': lambda p: m_finding(p.get('finding_id'), p.get('record_key')),
    'dns': lambda p: m_dns(p.get('limit', 500)),
    'dns_summary': lambda p: m_dns_summary(p.get('limit', 5000)),
    'dns_records': lambda p: m_dns_records(p.get('limit', 500)),
    'otx': lambda p: m_otx(),
    'services': lambda p: m_services(),
    'rules': lambda p: m_rules(),
    'audit': lambda p: m_audit(p.get('limit', 50)),
    'suricata': lambda p: m_suricata(p.get('limit', 100)),
    'response': lambda p: m_response(p.get('limit', 100)),
    'network': lambda p: m_response(p.get('limit', 100)),
    'integrity': lambda p: m_integrity(),
    'modem_setup_preview': lambda p: __import__('satsuma.modem_identity', fromlist=['preview']).preview(),
    'self_health': lambda p: __import__('satsuma.self_health', fromlist=['read_report']).read_report(),
    'system_health': lambda p: m_system_health(),
    'ping': lambda p: 'pong',
}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            header = self.rfile.read(4)
            if len(header) < 4:
                return
            length = struct.unpack('>I', header)[0]
            if length > 65536:
                return
            body = self.rfile.read(length)
            req = json.loads(body.decode('utf-8'))
            method = req.get('method')
            params = req.get('params') or {}

            if method not in METHODS:
                resp = {'error': f'bilinmeyen metod: {method}'}
            else:
                try:
                    resp = {'result': METHODS[method](params)}
                except Exception as e:
                    resp = {'error': f'{type(e).__name__}: {e}'}

            out = json.dumps(resp, default=str).encode('utf-8')
            self.wfile.write(struct.pack('>I', len(out)) + out)
        except Exception as e:
            print(f'[reader] hata: {e}', file=sys.stderr)


class Server(socketserver.ThreadingUnixStreamServer):
    allow_reuse_address = False
    daemon_threads = True
    request_queue_size = 16

    def __init__(self,*args,**kwargs):
        self._slots=threading.BoundedSemaphore(16)
        super().__init__(*args,**kwargs)

    def verify_request(self,request,client_address):
        request.settimeout(5)
        return self._slots.acquire(blocking=False)

    def process_request_thread(self,request,client_address):
        try:
            return super().process_request_thread(request,client_address)
        finally:
            self._slots.release()


def main():
    os.makedirs(os.path.dirname(SOCKET_PATH), mode=0o750, exist_ok=True)

    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    server = Server(SOCKET_PATH, Handler)

    try:
        import grp
        gid = grp.getgrnam(SOCKET_GROUP).gr_gid
        os.chown(SOCKET_PATH, 0, gid)
        os.chmod(SOCKET_PATH, SOCKET_MODE)
        print(f'[reader] socket: {SOCKET_PATH}', file=sys.stderr)
    except KeyError:
        os.chmod(SOCKET_PATH, 0o600)
        print(f'[reader] {SOCKET_GROUP} yok, root-only', file=sys.stderr)
    except Exception as e:
        print(f'[reader] izin hata: {e}', file=sys.stderr)

    server.serve_forever()


if __name__ == '__main__':
    main()
