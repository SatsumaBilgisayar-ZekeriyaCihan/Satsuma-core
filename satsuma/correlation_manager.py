"""Satsuma Core — head team lead: runs every team and links their findings.

A PID reported by two or more teams becomes a critical cross-team finding.
Since 2.2.11 that finding names the program (executable, command line, user)
and lists what each team saw, so it can be judged without guessing.

Satsuma Core — Baş Ekip Başı: tüm takımları yönetir, cross-team bağlantı
kurar. İki ya da daha fazla takımın bildirdiği PID kritik bir cross-team
bulgusu olur. 2.2.11'den beri bu bulgu programı (çalıştırılabilir dosya,
komut satırı, kullanıcı) adıyla gösterir ve her takımın ne gördüğünü
listeler; tahmin etmeden değerlendirilebilir.
"""
import os
import time
import hashlib
from .finding_store import record_finding
from satsuma import shutdown


def process_identity(pid, events, proc_root='/proc'):
    """Program behind a PID: from the events, else from /proc while it lives."""
    found = {}
    for event in events:
        for key in ('exe', 'cmd', 'uid', 'ppid', 'parent_cmd'):
            if event.get(key) is not None and key not in found:
                found[key] = event[key]
    if 'exe' not in found or 'cmd' not in found:
        try:
            found.setdefault('exe', os.readlink(f'{proc_root}/{pid}/exe'))
        except OSError:
            pass
        try:
            raw = open(f'{proc_root}/{pid}/cmdline', 'rb').read(4096)
            if raw:
                found.setdefault('cmd', raw.replace(b'\0', b' ').decode('utf-8', 'replace').strip())
        except OSError:
            pass
    return found

class CorrelationManager:
    def __init__(self, store, config=None, pipeline=None):
        self.store = store
        self.config = config or {}
        self.pipeline = pipeline
        self.teams = []

    def register_team(self, team):
        """Takım ekle."""
        self.teams.append(team)

    def _cross_team_link(self, all_findings):
        """Takımlar arası bağlantı."""
        by_pid = {}
        for f in all_findings:
            for e in f.get('events', []):
                pid = e.get('pid')
                if pid:
                    by_pid.setdefault(str(pid), []).append(f)

        cross = []
        for pid, fs in by_pid.items():
            teams = set(f.get('team') for f in fs)
            if len(teams) >= 2:
                process = process_identity(pid, [e for f in fs for e in f.get('events', [])
                                                 if str(e.get('pid')) == pid])
                name = process.get('cmd') or process.get('exe') or 'program adı okunamadı'
                cross.append({
                    'type': 'cross_team_chain',
                    'severity': 'critical',
                    'confidence': 'high',
                    'timestamp': int(time.time()),
                    'teams': sorted(teams),
                    'pid': pid,
                    'process': process,
                    'findings': [
                        {
                            'team': f.get('team'),
                            'type': f.get('type'),
                            'severity': f.get('severity'),
                            'summary': f.get('summary'),
                        }
                        for f in fs
                    ],
                    'summary': f'Cross-team: PID {pid} ({str(name)[:120]}) → {", ".join(sorted(teams))}',
                })
        return cross

    def tick(self):
        """Tüm takımları çalıştır."""
        started = time.time()
        all_findings = []
        team_results = {}

        for team in self.teams:
            if shutdown.requested():
                team_results[team.name] = {'ok': True, 'stopped': True}
                continue
            try:
                result = team.tick()
                team_results[team.name] = {
                    'ok': result.get('ok'),
                    'findings': result.get('findings', 0),
                    'elapsed_ms': result.get('elapsed_ms', 0),
                }
                all_findings.extend(result.get('findings_list', []))
            except Exception as e:
                team_results[team.name] = {'ok': False, 'error': str(e)[:200]}

        # Cross-team bağlantı
        cross = self._cross_team_link(all_findings)

        # Cross-team bulguları dedup ile yaz.
        fresh_cross = []
        for c in cross:
            # PID tek başına kalıcı kimlik değildir; PID reuse eski bulguyla yanlış
            # dedup oluşturabilir. Alt bulguların kimliklerini fingerprint'e kat.
            child_ids = sorted(
                str(f.get('finding_id') or f.get('type') or '')
                for f in all_findings
                if any(str(e.get('pid')) == str(c.get('pid')) for e in f.get('events', []))
            )
            basis = "|".join([str(c.get('pid', 'unknown')), *c.get('teams', []), *child_ids])
            digest = hashlib.sha256(basis.encode('utf-8', errors='replace')).hexdigest()[:24]
            c.setdefault('finding_id', f"cross_team_{digest}")
            c.setdefault('classification', 'likely')
            result = record_finding(self.store, c, 'correlation_manager')
            c['_dedup'] = result
            if result.get('written'):
                fresh_cross.append(c)

        elapsed = time.time() - started

        self.store.set('correlation_manager.health', {
            'updated_at': int(time.time()),
            'status': 'RUNNING' if all(v.get('ok') for v in team_results.values()) else 'DEGRADED',
            'elapsed_ms': int(elapsed * 1000),
            'teams': len(self.teams),
            'team_results': team_results,
            'degraded_reason': '; '.join(name+': '+str(item.get('error') or 'Takım alt bileşenlerini inceleyin') for name,item in team_results.items() if not item.get('ok')) or None,
            'findings_total': len(all_findings),
            'cross_team': len(cross),
            'new_cross_team': len(fresh_cross),
        })

        return {
            'ok': all(v.get('ok') for v in team_results.values()),
            'teams': len(self.teams),
            'findings': len(all_findings),
            'cross_team': len(cross),
            'new_cross_team': len(fresh_cross),
            'elapsed_ms': int(elapsed * 1000),
            'team_results': team_results,
            'findings_list': all_findings + fresh_cross,
        }
