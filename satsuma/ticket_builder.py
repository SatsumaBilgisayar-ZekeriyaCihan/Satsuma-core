"""Satsuma Core — Ticket Builder.

Bulgu → Ticket dönüşümü.
Fingerprint ile tekrar engelleme.
4 seviye severity (S1-S4).
"""
import hashlib
import json
import time
import uuid


class TicketBuilder:
    """Bulgu → Ticket dönüşümü."""

    def __init__(self, store, config=None):
        self.store = store
        self.config = config or {}
        self._ensure_table()

    def _ensure_table(self):
        """Ticket tablosu oluştur."""
        self.store.db.executescript('''
            CREATE TABLE IF NOT EXISTS tickets (
                ticket_id TEXT PRIMARY KEY,
                finding_id TEXT,
                team TEXT,
                type TEXT,
                ticket_level INTEGER,
                severity TEXT,
                priority TEXT,
                confidence TEXT,
                status TEXT DEFAULT 'open',
                title TEXT,
                description TEXT,
                evidence TEXT,
                fingerprint TEXT,
                occurrence_count INTEGER DEFAULT 1,
                first_seen REAL,
                last_seen REAL,
                assigned_to TEXT,
                notes TEXT DEFAULT '[]',
                review_history TEXT DEFAULT '[]',
                created_at REAL,
                updated_at REAL,
                resolved_at REAL,
                closed_at REAL,
                resolution TEXT,
                false_positive INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_tickets_status
                ON tickets(status);
            CREATE INDEX IF NOT EXISTS idx_tickets_fingerprint
                ON tickets(fingerprint);
            CREATE INDEX IF NOT EXISTS idx_tickets_severity
                ON tickets(severity);
            CREATE INDEX IF NOT EXISTS idx_tickets_level
                ON tickets(ticket_level);
        ''')
        self.store.db.commit()

    # ------------------------------------------------------------------
    # Seviye hesaplama
    # ------------------------------------------------------------------

    # Kritik tipler — takımdan bağımsız
    SEVERITY_1_TYPES = {
        # Malware
        'ransomware_detected',
        'c2_communication',
        'kernel_taint_change',
        'rootkit_detected',
        'virus_detected',
        # Kimlik
        'privilege_escalation_attempt',
        'root_login_unknown',
        # Dosya sistemi — kritik
        'user_created', 'user_deleted',
        'passwd_modified', 'shadow_modified',
        'sudoers_modified', 'ld_so_preload_modified',
        'ld_preload_env',
        # Uzaktan yönetim
        'remote_access_tool', 'reverse_shell',
    }

    # Yüksek tipler
    SEVERITY_2_TYPES = {
        'suspicious_process_chain',
        'sensitive_file_access',
        'port_scan',
        'brute_force',
        'ssh_brute_force',
        'ssh_tunnel',
        'start_transient_unit',
        'suspicious_unit',
        'unit_masked',
        'login_failed_many',
    }

    # Orta tipler
    SEVERITY_3_TYPES = {
        'new_unit',
        'unit_enabled',
        'new_process',
        'new_module',
        'new_usb',
        'login_anomaly',
        'new_external_connection',
        'unusual_port',
        'new_domain',
    }

    def compute_level(self, finding):
        """Bulgu -> ticket level (1-4).

        Severity potansiyel etkiyi, classification ise kanit gucunu anlatir.
        Tek bir indicator kritik isim/severity tasisa bile S1 olamaz.
        """
        ftype = finding.get('type', '')
        severity = str(finding.get('severity', 'medium')).lower()
        classification = str(finding.get('classification', 'suspicious')).lower()

        if ftype in self.SEVERITY_1_TYPES or severity == 'critical':
            base = 1
        elif ftype in self.SEVERITY_2_TYPES or severity == 'high':
            base = 2
        elif ftype in self.SEVERITY_3_TYPES or severity == 'medium':
            base = 3
        else:
            base = 4

        if classification == 'indicator':
            return 4
        if classification == 'suspicious':
            return max(base, 2)  # Supheli tek sinyal S1 olamaz.
        if classification in ('likely', 'confirmed'):
            return base
        return max(base, 3)

    def _level_to_severity(self, level):
        return {
            1: 'critical',
            2: 'high',
            3: 'medium',
            4: 'low',
        }.get(level, 'low')

    def _priority(self, level, confidence):
        """Level + confidence → priority."""
        table = {
            (1, 'high'): 'critical',
            (1, 'medium'): 'high',
            (1, 'low'): 'high',
            (2, 'high'): 'high',
            (2, 'medium'): 'medium',
            (2, 'low'): 'medium',
            (3, 'high'): 'medium',
            (3, 'medium'): 'low',
            (3, 'low'): 'low',
            (4, 'high'): 'low',
            (4, 'medium'): 'low',
            (4, 'low'): 'low',
        }
        return table.get((level, confidence), 'medium')

    def _fingerprint(self, finding):
        """Aynı bulgu tekrar mı? Deterministik hash."""
        parts = [
            finding.get('team', ''),
            finding.get('type', ''),
            finding.get('summary', '')[:100],
        ]
        return hashlib.sha256('|'.join(parts).encode()).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Ticket oluşturma
    # ------------------------------------------------------------------

    def build_from_finding(self, finding):
        """Bir bulgudan ticket oluştur (veya mevcut olana ekle)."""
        fingerprint = self._fingerprint(finding)
        now = time.time()

        # Aynı fingerprint'li açık ticket var mı?
        row = self.store.db.execute(
            "SELECT ticket_id, occurrence_count FROM tickets "
            "WHERE fingerprint = ? "
            "AND status IN ('open', 'in_progress') "
            "ORDER BY updated_at DESC LIMIT 1",
            (fingerprint,),
        ).fetchone()

        if row:
            ticket_id, count = row
            self.store.db.execute(
                "UPDATE tickets SET "
                "occurrence_count = occurrence_count + 1, "
                "last_seen = ?, "
                "updated_at = ? "
                "WHERE ticket_id = ?",
                (now, now, ticket_id),
            )
            self.store.db.commit()
            return {
                'ok': True,
                'ticket_id': ticket_id,
                'action': 'updated',
                'occurrence_count': count + 1,
            }

        # Yeni ticket
        ticket_id = f'TKT-{uuid.uuid4().hex[:12]}'
        level = self.compute_level(finding)
        severity = self._level_to_severity(level)
        confidence = finding.get('confidence', 'medium')
        priority = self._priority(level, confidence)

        self.store.db.execute(
            "INSERT INTO tickets ("
            "ticket_id, finding_id, team, type, ticket_level, "
            "severity, priority, confidence, status, "
            "title, description, evidence, fingerprint, "
            "occurrence_count, first_seen, last_seen, "
            "created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ticket_id,
                finding.get('finding_id'),
                finding.get('team'),
                finding.get('type'),
                level,
                severity,
                priority,
                confidence,
                'open',
                str(finding.get('type', 'Unknown'))[:100],
                str(finding.get('summary', ''))[:500],
                json.dumps(finding, default=str),
                fingerprint,
                1,
                now,
                now,
                now,
                now,
            ),
        )
        self.store.db.commit()

        return {
            'ok': True,
            'ticket_id': ticket_id,
            'action': 'created',
            'level': level,
            'severity': severity,
        }

    def build_all_from_findings(self, limit=200):
        """Son bulgulardan ticket üret."""
        rows = self.store.db.execute(
            "SELECT body FROM records "
            "WHERE kind='events' "
            "AND json_extract(body, '$.event.category') = 'finding' "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()

        results = []
        for row in rows:
            try:
                body = json.loads(row[0])
                finding = body.get('metadata', {}).get('finding', {})
                if finding:
                    results.append(self.build_from_finding(finding))
            except (json.JSONDecodeError, KeyError):
                continue

        return results

    # ------------------------------------------------------------------
    # Listeleme ve güncelleme
    # ------------------------------------------------------------------

    def list_tickets(self, status=None, level=None, limit=50):
        """Ticket'ları listele."""
        sql = "SELECT * FROM tickets WHERE 1=1"
        params = []

        if status:
            sql += " AND status = ?"
            params.append(status)
        if level:
            sql += " AND ticket_level = ?"
            params.append(level)

        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)

        cursor = self.store.db.execute(sql, params)
        cols = [c[0] for c in cursor.description]
        rows = cursor.fetchall()
        return [dict(zip(cols, r)) for r in rows]

    def update_status(self, ticket_id, status, note=None):
        """Ticket durumunu güncelle."""
        valid = ('open', 'in_progress', 'resolved', 'closed', 'false_positive')
        if status not in valid:
            return {'ok': False, 'error': f'invalid status: {status}'}

        now = time.time()
        updates = {'status': status, 'updated_at': now}

        if status == 'resolved':
            updates['resolved_at'] = now
        elif status == 'closed':
            updates['closed_at'] = now
        elif status == 'false_positive':
            updates['false_positive'] = 1

        set_clause = ', '.join(f'{k} = ?' for k in updates)
        values = list(updates.values()) + [ticket_id]

        self.store.db.execute(
            f"UPDATE tickets SET {set_clause} WHERE ticket_id = ?",
            values,
        )

        if note:
            self._add_note(ticket_id, note, status)

        self.store.db.commit()
        return {'ok': True, 'ticket_id': ticket_id, 'status': status}

    def _add_note(self, ticket_id, note, status=None):
        """Ticket'a not ekle."""
        row = self.store.db.execute(
            "SELECT notes, review_history FROM tickets WHERE ticket_id = ?",
            (ticket_id,),
        ).fetchone()
        if not row:
            return

        notes = json.loads(row[0] or '[]')
        history = json.loads(row[1] or '[]')

        entry = {
            'timestamp': time.time(),
            'note': note[:1000],
            'status': status,
        }
        notes.append(entry)
        history.append(entry)

        self.store.db.execute(
            "UPDATE tickets SET notes = ?, review_history = ? "
            "WHERE ticket_id = ?",
            (json.dumps(notes), json.dumps(history), ticket_id),
        )

    def stats(self):
        """Ticket istatistikleri."""
        total = self.store.db.execute(
            "SELECT COUNT(*) FROM tickets"
        ).fetchone()[0]

        by_status = dict(self.store.db.execute(
            "SELECT status, COUNT(*) FROM tickets GROUP BY status"
        ).fetchall())

        by_level = dict(self.store.db.execute(
            "SELECT ticket_level, COUNT(*) FROM tickets "
            "GROUP BY ticket_level"
        ).fetchall())

        return {
            'total': total,
            'by_status': by_status,
            'by_level': by_level,
        }
