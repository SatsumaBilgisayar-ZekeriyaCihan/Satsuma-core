#!/usr/bin/env python3
"""Correlate findings and dispatch through existing policy/identity guards.

Periodic follow-up records process metadata and decisions without authorizing
signals or inheriting a threat verdict for related processes.

Stopping decisions run before investigation, a smart-rule backlog starts
the next round at once, and the slow team collectors (40 s a round in the
field) run at most every 30 seconds instead of holding up every rule round
(field 2026-11-04: decisions lagged up to 38 minutes). Since 2.2.32 events
arrive through the in-memory flow (satsuma.flow) every quarter second;
only suspicious findings and termination attempts are written, each with
its process's 30-minute flow history, and stored raw events are removed
once.

Bulguları korele eder; mevcut politika ve kimlik kapılarından müdahaleye yollar.
Periyodik takip süreç üstverisini ve kararları kaydeder; sinyal yetkisi vermez,
ilişkili süreçlere zararlılık kararı devretmez. Durdurma kararları
incelemeden önce çalışır; akıllı kural birikimi varsa sonraki tur beklemeden
başlar; yavaş ekip toplayıcıları (sahada tur başına 40 sn) her kural turunu
bekletmek yerine en çok 30 saniyede bir çalışır (saha 2026-11-04: kararlar
38 dakikaya kadar gecikiyordu). 2.2.32'den beri olaylar bellek içi akıştan
(satsuma.flow) çeyrek saniyede bir gelir; yalnızca şüpheli bulgular ve
sonlandırma denemeleri, sürecin 30 dakikalık akış geçmişiyle yazılır;
saklanmış ham olaylar bir kez silinir.
"""
from __future__ import annotations

import ipaddress
import os
import json
import sys
import contextlib
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from satsuma.store import Store
from satsuma.pipeline import Pipeline
from satsuma.config import load
from satsuma.correlation_engine import CorrelationEngine
from satsuma.smart_rules import SmartRuleEngine
from satsuma.short_event_evidence import ShortEvidenceWindow
from satsuma.finding_origin import annotate as annotate_origin
from satsuma import shutdown
from satsuma.auto_action import AutoActionEngine
from satsuma.finding_store import record_finding
from satsuma.response_policy import authorize_destructive, denied_action_record
from satsuma.action_contract import (
    DESTRUCTIVE_ACTIONS,
    SAFE_ACTIONS,
    SafeActionBroker,
    canonical_action,
    normalize_action_spec,
)
from satsuma.teams.host_team import HostTeamLead
from satsuma.teams.identity_team import IdentityTeamLead
from satsuma.teams.file_team import FileTeamLead
from satsuma.teams.network_team import NetworkTeamLead
from satsuma.correlation_manager import CorrelationManager

SMART_CURSOR_KEY = 'brain.smart_rules.cursor.v2'
SMART_BATCH_LIMIT = 5000


def _latest_normalized_id(store):
    row = store.db.execute(
        "SELECT COALESCE(MAX(id),0) FROM records WHERE kind='normalized'"
    ).fetchone()
    return int(row[0] or 0)


def _smart_event(rid, body_str):
    outer = json.loads(body_str)
    inner = outer.get('event') or {}
    ev = inner.get('event') or {}
    raw_block = inner.get('raw') or {}
    raw = raw_block.get('data') if isinstance(raw_block, dict) else {}
    if not isinstance(raw, dict):
        raw = {}
    metadata = inner.get('metadata') or {}
    extensions = metadata.get('extensions') if isinstance(metadata, dict) else {}
    if not isinstance(extensions, dict):
        extensions = {}
    network = inner.get('network') or {}
    if not isinstance(network, dict):
        network = {}
    source = inner.get('source') or {}
    if not isinstance(source, dict):
        source = {}

    def ext(*names, default=None):
        for name in names:
            value = extensions.get(name)
            if value is not None:
                return value
        return default

    return {
        'id': rid,
        'raw_id': outer.get('raw_id'),
        'timestamp': ev.get('timestamp'),
        'source': source.get('type') or source.get('collector_id'),
        'action': ev.get('action'),
        'kind': raw.get('kind') or ext('host.kind') or ev.get('action'),
        'category': ev.get('category'),
        'severity': ev.get('severity'),
        'metadata': metadata,
        'raw': raw,
        'cmd': raw.get('cmd') or ext('host.cmd', default=''),
        'origin': raw.get('origin') or ext('host.origin'),
        'exe': raw.get('exe') or ext('host.exe', default=''),
        'uid': raw.get('uid', ext('host.uid')),
        'pid': raw.get('pid', ext('host.pid')),
        'ppid': raw.get('ppid', ext('host.ppid')),
        'parent_cmd': raw.get('parent_cmd') or ext('host.parent_cmd', default=''),
        'file_path': raw.get('file_path') or raw.get('path') or ext('host.file_path', 'host.path', default=''),
        'path': raw.get('path') or raw.get('file_path') or ext('host.path', 'host.file_path', default=''),
        'operation': raw.get('operation') or ext('host.operation', default=''),
        'env': raw.get('env') or ext('host.env', default=''),
        'target_ip': raw.get('target_ip') or ext('host.target_ip'),
        'file_sha256': raw.get('file_sha256') or ext('host.file_sha256'),
        'starttime': raw.get('starttime') or ext('host.starttime'),
        'src_ip': network.get('src_ip') or raw.get('src_ip') or ext('host.src_ip'),
        'dest_ip': network.get('dst_ip') or network.get('dest_ip') or raw.get('dest_ip') or ext('host.dest_ip'),
        'src_port': network.get('src_port') or raw.get('src_port') or ext('host.src_port'),
        'dest_port': network.get('dst_port') or network.get('dest_port') or raw.get('dest_port') or ext('host.dest_port'),
        'proto': network.get('proto') or raw.get('proto') or ext('host.proto'),
    }


def _run_teams(store, config, pipeline):
    manager = getattr(pipeline, '_team_manager', None)
    if manager is None:
        manager = CorrelationManager(store, config, pipeline)
        for team_cls in (HostTeamLead, IdentityTeamLead, FileTeamLead, NetworkTeamLead):
            manager.register_team(team_cls(store, config, pipeline))
        pipeline._team_manager = manager
    return manager.tick()


def _run_smart_rules(store, engine, start_cursor):
    rows = store.db.execute(
        "SELECT id, body FROM records WHERE kind='normalized' AND id>? ORDER BY id ASC LIMIT ?",
        (int(start_cursor), SMART_BATCH_LIMIT),
    ).fetchall()

    fresh = []
    processed = 0
    last_id = int(start_cursor)
    errors = 0

    for rid, body_str in rows:
        try:
            event = _smart_event(rid, body_str)
            if event.get('origin') == 'satsuma':
                continue
            for finding in engine.match(event):
                if not _recordable(finding):
                    continue
                finding['team'] = 'smart_rules'
                annotate_origin(finding, event)
                result = record_finding(store, finding, 'smart_rules')
                finding['_dedup'] = result
                if result.get('written'):
                    fresh.append(finding)
            processed += 1
            last_id = int(rid)
        except Exception as exc:
            errors += 1
            store.add('errors', {
                'component': 'brain.smart_rules.event',
                'record_id': rid,
                'error': str(exc)[:300],
            })
            break

    # Commit only the last successfully persisted record; failed events retry.
    if rows:
        store.set(SMART_CURSOR_KEY, last_id)

    return fresh, {
        'processed_events': processed,
        'event_errors': errors,
        'cursor_start': int(start_cursor),
        'cursor_end': last_id,
        'batch_size': len(rows),
        'backlog_remaining': len(rows) >= SMART_BATCH_LIMIT,
    }


def _canonical_actions(finding):
    return [canonical_action(token) for token in normalize_action_spec(finding.get('actions') or [])]


def _automatic_actions(store, config, findings):
    # Compatibility function name for older diagnostics; no tickets are created.
    engine = AutoActionEngine(store, config)
    processed = duplicate = 0
    from satsuma.auto_process import corroborate
    confirmed = corroborate(findings)
    for finding in confirmed:
        store.add('findings', finding)
    for finding in [*findings, *confirmed]:
        result = engine.process(finding)
        if result.get('status') == 'duplicate':
            duplicate += 1
        else:
            processed += 1
    return processed, 0, duplicate


REMEDIATION_KEY = 'remediation_policy'


PRIVD_ALARM_EVERY = 3600.0


PRIVD_PROBE_EVERY = 3600.0


def _privd_probe(store, now=None, request=None):
    """Hourly: the real privd client and socket carry a file path (2.2.62, satsuma.self_test)."""
    now = time.time() if now is None else now
    last = store.get('privd_probe_at', None) or 0
    if now - float(last) < PRIVD_PROBE_EVERY:
        return None
    store.set('privd_probe_at', now)
    from satsuma import self_test
    result = self_test.check_privd(request) if request else self_test.check_privd()
    store.set('privd_probe_last', {**result, 'timestamp': now})
    if not result['passed']:
        _privd_unreachable(store, {'action': 'saatlik privd denetimi', 'path': result['detail']}, now)
    return result


def _privd_unreachable(store, action, now=None):
    """A critical finding when an undo could not reach privd (at most hourly; 2.2.60).

    Field 2026-11-19: quarantine requests failed silently for four releases.
    Geri alma privd'ye ulaşamazsa kritik bulgu verilir; sessiz arıza kalmaz.
    """
    from satsuma.finding_store import record_finding
    now = time.time() if now is None else now
    last = store.get('privd_unreachable_alarm', None) or 0
    if now - float(last) < PRIVD_ALARM_EVERY:
        return False
    store.set('privd_unreachable_alarm', now)
    record_finding(store, {
        'finding_id': f'SATSUMA-PRIVD-001:{int(now)}', 'rule_id': 'SATSUMA-PRIVD-001', 'severity': 'critical',
        'classification': 'indicator', 'source': 'self_health', 'timestamp': now,
        'title': 'Koruma yardımcısı (privd) yanıt vermiyor: otomatik geri alma yapılamadı',
        'summary': f"{action.get('action')} {action.get('path') or action.get('user') or ''}".strip(),
        'advice': 'sudo systemctl restart satsuma-privd; sonra sudo satsuma-admin geri-alma durum',
        'enforcement_eligible': False}, 'self_health')
    return True


POLICY_SIGNATURE_EVERY = 3600
POLICY_REJECTED = ('POLICY_UNSIGNED', 'POLICY_SIGNATURE_INVALID', 'POLICY_KEY_SWAPPED', 'POLICY_KEY_INVALID')


def _policy_signature(store, meta=None, now=None):
    """Hourly: a finding while policy.json is unsigned, changed after signing or no key exists (2.2.62).

    İmzasız ya da imzadan sonra değişmiş politika kullanılmaz; bu durum saat başı bulgu olarak görünür.
    """
    from satsuma.finding_store import record_finding
    now = time.time() if now is None else now
    if now - float(store.get('policy_signature_check', None) or 0) < POLICY_SIGNATURE_EVERY:
        return None
    store.set('policy_signature_check', now)
    if meta is None:
        from satsuma.config import load_with_policy
        try:
            meta = load_with_policy()[1]
        except Exception as exc:
            meta = {'status': 'error', 'rejected_code': getattr(exc, 'code', 'POLICY_INVALID'), 'error': str(exc)[:300]}
    code = meta.get('rejected_code')
    if meta.get('status') in ('last_valid', 'error') and code in POLICY_REJECTED:
        finding = {'rule_id': 'SATSUMA-POLICY-SIG-002', 'severity': 'critical',
                   'title': 'Politika dosyası imzasız ya da imzadan sonra değişmiş: kullanılmıyor',
                   'summary': f"{code}: {meta.get('error', '')}"[:400],
                   'advice': 'Değişikliği siz yaptıysanız: sudo satsuma-admin politika imzala. Siz yapmadıysanız '
                             'dosyayı geri alın; Satsuma son imzalı politikayla çalışmaya devam ediyor.'}
    elif meta.get('signature') == 'no_key':
        finding = {'rule_id': 'SATSUMA-POLICY-SIG-001', 'severity': 'high',
                   'title': 'Politika imza anahtarı yok: politika dosyası imzasız kabul ediliyor',
                   'summary': '/etc/satsuma-core/policy.json herkesin değil yalnızca sizin imzanızla geçerli olmalı.',
                   'advice': 'sudo satsuma-admin politika anahtar-olustur; sonra sudo satsuma-admin politika imzala'}
    else:
        return None
    record_finding(store, {**finding, 'finding_id': f"{finding['rule_id']}:{int(now)}", 'classification': 'indicator',
                           'source': 'self_health', 'timestamp': now, 'enforcement_eligible': False}, 'self_health')
    return finding['rule_id']


def _previous_boot_was_off(store, runner=None, boot_id_path='/proc/sys/kernel/random/boot_id'):
    """Once per boot: a finding when the previous boot ran with the satsuma.off switch (2.2.64).

    That boot had no Satsuma at all; whoever had the boot menu could do anything in it.
    Önceki açılış satsuma.off ile yapıldıysa bulgu açılır.
    """
    import subprocess
    from satsuma.finding_store import record_finding
    try:
        boot = Path(boot_id_path).read_text().strip()
    except OSError:
        return None
    if store.get('satsuma_off_checked_boot', None) == boot:
        return None
    store.set('satsuma_off_checked_boot', boot)
    runner = runner or subprocess.run
    try:
        out = runner(['/usr/bin/journalctl', '-b', '-1', '-k', '-o', 'cat', '--no-pager', '--grep', 'Command line'],
                     capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    if not any(word == 'satsuma.off' for line in out.splitlines() for word in line.split()):
        return None
    now = time.time()
    record_finding(store, {
        'finding_id': f'SATSUMA-OFF-001:{int(now)}', 'rule_id': 'SATSUMA-OFF-001', 'severity': 'high',
        'classification': 'indicator', 'source': 'self_health', 'timestamp': now, 'enforcement_eligible': False,
        'title': 'Önceki açılış Satsuma kapalıyken yapıldı (satsuma.off)',
        'summary': 'Açılış menüsünde satsuma.off yazılmış; o açılışta hiçbir Satsuma servisi çalışmadı.',
        'advice': 'Bunu siz yaptıysanız sorun yok. Siz yapmadıysanız açılış menüsüne erişen biri var: '
                  'journalctl -b -1 ile o açılışta ne yapıldığına bakın.'}, 'self_health')
    return 'SATSUMA-OFF-001'


BANNED_PACKAGES = ('firefox', 'systemd-resolved', 'avahi', 'gssproxy', 'brltty', 'ipp-usb', 'python3-cups',
                   'ibus-panel', 'python3-ibus', 'ibus-anthy-python', 'python3-langtable', 's-nail')
BANNED_EVERY = 3600


def _banned_packages(store, now=None, runner=None):
    """Hourly: a critical finding when a package the owner removed is installed again (2.2.64).

    Sahibin imajdan çıkardığı paket geri gelirse kritik bulgu.
    """
    import subprocess
    from satsuma.finding_store import record_finding
    now = time.time() if now is None else now
    if now - float(store.get('banned_packages_check', None) or 0) < BANNED_EVERY:
        return []
    store.set('banned_packages_check', now)
    runner = runner or subprocess.run
    try:
        out = runner(['/usr/bin/rpm', '-q', '--qf', '%{NAME}\\n', *BANNED_PACKAGES],
                     capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    back = sorted({line.strip() for line in out.splitlines()} & set(BANNED_PACKAGES))
    if back:
        record_finding(store, {
            'finding_id': f'SATSUMA-BANNED-PKG-001:{int(now)}', 'rule_id': 'SATSUMA-BANNED-PKG-001',
            'severity': 'critical', 'classification': 'indicator', 'source': 'self_health', 'timestamp': now,
            'enforcement_eligible': False,
            'title': 'Yasaklı paket imaja geri geldi: ' + ', '.join(back),
            'summary': 'Bu paketleri imajdan siz çıkarmıştınız; servisleri maskeli, programları çalışırsa durdurulur.',
            'advice': 'sudo rpm-ostree override remove ' + ' '.join(back)}, 'self_health')
    return back


RESTART_STORM_EVERY = 3600


def _restart_storms(store, now=None, storms=None):
    """A critical finding for each Satsuma unit that keeps falling (more than 3 restarts in 30 min).

    2.2.62: restarts never stop; this shows that something keeps stopping the unit.
    Tekrar tekrar düşen Satsuma birimi kritik bulgu olur.
    """
    from satsuma import repair_budget
    from satsuma.finding_store import record_finding
    now = time.time() if now is None else now
    storms = repair_budget.storms(now) if storms is None else storms
    alarmed = store.get('restart_storm_alarms', None) or {}
    raised = []
    for unit, info in sorted(storms.items()):
        if unit in alarmed and now - float(alarmed[unit]) < RESTART_STORM_EVERY:
            continue
        alarmed[unit] = now
        record_finding(store, {
            'finding_id': f'SATSUMA-HEALTH-RESTART-001:{unit}:{int(now)}', 'rule_id': 'SATSUMA-HEALTH-RESTART-001',
            'severity': 'critical', 'classification': 'indicator', 'source': 'self_health', 'timestamp': now,
            'title': f'Satsuma birimi tekrar tekrar duruyor: {unit}',
            'summary': f"Son 30 dakikada {info.get('count')} kez yeniden başlatıldı (son: {info.get('actor')}). "
                       'Yeniden başlatma sürüyor; aralık en fazla 10 dakikaya çıkar.',
            'advice': f'journalctl -u {unit} -n 100; bu birimi durduran süreci Bulgular ve Olanlar sayfasında arayın.',
            'enforcement_eligible': False}, 'self_health')
        raised.append(unit)
    if raised:
        store.set('restart_storm_alarms', alarmed)
    return raised


def _remediate(store, findings, request=None):
    """Undo what one-shot attack commands left behind (satsuma.remediation, 2.2.56).

    On while the stop policy is on and the owner has not switched remediation off
    (store key remediation_policy {'enabled': False}). privd checks every action again.
    """
    from satsuma import enforcement, remediation
    if not enforcement.policy(store).get('enabled'):
        return 0
    stored = store.get(REMEDIATION_KEY, None)
    if isinstance(stored, dict) and stored.get('enabled') is False:
        return 0
    if request is None:
        from satsuma.privd import delegate
        request = lambda **params: delegate('remediate', **params)
    done = 0
    seen = set()
    for finding in findings:
        for action in remediation.plan(finding):
            key = (action['action'], action.get('path') or action.get('user'), action.get('group'))
            if key in seen:
                continue
            seen.add(key)
            params = {k: v for k, v in action.items() if v is not None}
            result = request(reason='Tek seferlik saldırının etkisi geri alınıyor: ' + str(action.get('rule_id')), **params)
            if result is None:
                store.add('actions', {**params, 'action': 'remediation.' + action['action'], 'status': 'privd_unavailable',
                                      'timestamp': time.time()})
                _privd_unreachable(store, action)
            done += 1
    return done


def _dispatch_safe_actions(pipeline, findings):
    """Production non-destructive action dispatch.

    Only explicit allow-listed actions reach :class:`SafeActionBroker`.
    Destructive action names are left on the existing response_policy gate.
    Unknown actions fail closed and are recorded as denied; the broker itself
    also refuses them.  A per-finding/per-action key prevents duplicate
    execution when the same finding reaches the dispatcher through more than
    one source list.
    """
    broker = SafeActionBroker(pipeline.store, pipeline.config)
    seen = set()
    dispatched = 0
    denied = 0
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        finding_id = str(finding.get('finding_id') or ('obj:' + str(id(finding))))
        event = finding.get('event') if isinstance(finding.get('event'), dict) else {}
        context = {'finding': finding, 'finding_id': finding_id, 'event': event}
        for token in normalize_action_spec(finding.get('actions') or []):
            canonical = canonical_action(token)
            if canonical not in SAFE_ACTIONS and canonical not in DESTRUCTIVE_ACTIONS:
                # notify_admin is an existing non-destructive response path in
                # _confirmed_actions and is not part of the broker contract.
                if canonical == 'notify':
                    continue
                key = (finding_id, canonical)
                if key in seen:
                    continue
                seen.add(key)
                result = broker.dispatch(canonical, context)
                if result.get('status') == 'unknown_action':
                    denied += 1
                    pipeline.store.add('actions', {
                        'timestamp': time.time(),
                        'status': 'unknown_action_denied',
                        'action': token,
                        'canonical_action': canonical,
                        'finding_id': finding_id,
                        'rule_id': finding.get('rule_id'),
                        'executed': False,
                    })
                continue
            if canonical in DESTRUCTIVE_ACTIONS:
                # Destructive actions must flow through response_policy below.
                continue
            key = (finding_id, canonical)
            if key in seen:
                continue
            seen.add(key)
            result = broker.dispatch(canonical, context)
            if result.get('status') not in {
                'unknown_action', 'blocked_destructive', 'failed',
            }:
                dispatched += 1
    return {'safe_actions_dispatched': dispatched, 'unknown_actions_denied': denied}


def _sudo_autoblock(pipeline, findings, config):
    # Sudo is gated BEFORE exec by PAM; no kill/allowlist race.
    return 0


def _confirmed_actions(pipeline, findings):
    """Yalnizca explicit CONFIRMED finding icin destructive action uygula.

    Kurala ait action listesi yoksa Brain kendiliginden aksiyon icat etmez.
    """
    count = 0
    notified = 0
    for finding in findings:
        classification = str(finding.get('classification', 'suspicious')).lower()
        actions = set(finding.get('actions') or [])

        # likely/confirmed bildirim yapabilir, sistem durumunu degistirmez.
        if 'notify_admin' in actions and classification in {'likely', 'confirmed'}:
            pipeline.response.notify_admin(
                'Satsuma Guvenlik Bulgusu',
                f"{finding.get('rule_id') or finding.get('type')}: {finding.get('summary') or finding.get('rule_name', '')}",
                'critical' if finding.get('severity') == 'critical' else 'normal',
            )
            notified += 1

        if 'block_ip' in actions and classification in ('likely','confirmed'):
            from satsuma.auto_network import respond
            event = finding.get('event') or {}
            target = event.get('dest_ip') or event.get('src_ip') or finding.get('dst_ip') or finding.get('src_ip')
            result = respond(pipeline.response, finding, target, str(finding.get('rule_id') or finding.get('type')))
            if result.get('status') == 'set_membership_confirmed': count += 1
            actions.discard('block_ip')
        if classification != 'confirmed':
            continue

        event = finding.get('event') if isinstance(finding.get('event'), dict) else {}
        reason = f"confirmed: {finding.get('rule_id') or finding.get('type', 'finding')}"

        if 'block_ip' in actions:
            candidate = event.get('dest_ip') or event.get('src_ip') or finding.get('dst_ip') or finding.get('src_ip')
            if candidate:
                try:
                    addr = ipaddress.ip_address(candidate)
                except (ValueError, TypeError):
                    addr = None
                if addr is not None and addr.is_global:
                    # A rule/event finding is never sufficient by itself.  The
                    # gate requires response_enabled + confirmed classification
                    # + multi-source correlation + explicit policy + fail-safe.
                    auth = authorize_destructive(
                        'network_isolate', finding, pipeline.config,
                        context={'target_ip': str(addr), 'manual': False}, evidence_store=pipeline.store,
                    )
                    if auth.allowed:
                        result = pipeline.response.block_ip(str(addr), reason, manual=False)
                        if result.get('status') == 'blocked':
                            count += 1
                    else:
                        try:
                            record = denied_action_record(auth, finding)
                            record['target_ip'] = str(addr)
                            pipeline.store.add('actions', record)
                        except Exception:
                            pass

        if 'quarantine_file' in actions:
            path = event.get('file_path') or event.get('path') or finding.get('path')
            if path:
                auth = authorize_destructive(
                    'file_quarantine', finding, pipeline.config,
                    context={'path': path, 'manual': False}, evidence_store=pipeline.store,
                )
                if auth.allowed:
                    result = pipeline.response.quarantine_file(path, reason)
                    if result.get('status') == 'quarantined':
                        count += 1
                else:
                    try:
                        record = denied_action_record(auth, finding)
                        record['path'] = path
                        pipeline.store.add('actions', record)
                    except Exception:
                        pass

        # kill_process remains approval/manual-policy-only.  The BPF/process
        # kill methods are never invoked here merely because a rule matched.

    return count, notified


@contextlib.contextmanager
def _timed(phases, name):
    """Add the wall time of one phase of a turn, in milliseconds, to ``phases``.

    Bir turun bir aşamasının duvar saati süresini (ms) ``phases`` içine ekler.
    """
    start = time.monotonic()
    try:
        yield
    finally:
        phases[name] = phases.get(name, 0) + int((time.monotonic() - start) * 1000)


def _recordable(finding):
    """Only a suspicious process is written down (user decision 2026-11-04).

    Suspicious, likely and confirmed findings, and any finding the stop policy
    may act on, are recorded; log-only and indicator findings stay in the flow.
    """
    from satsuma import enforcement
    if finding.get('account_change'):
        # 2.2.38: an account file write is always shown with what it changed,
        # at the severity that change deserves (satsuma.account_change).
        return True
    classification = str(finding.get('classification', '')).lower()
    if finding.get('log_only'):
        if enforcement.eligible(finding) and classification != 'indicator':
            return True
    elif classification in ('suspicious', 'likely', 'confirmed') or enforcement.eligible(finding):
        return True
    # 2.2.54 (owner, 2026-11-19: "daha sıkı"): a high or critical rule that only reports
    # was never written down at all (106 rules silent, e.g. SSH private key read, kernel
    # module load, passwordless sudo). It is now recorded as a trace: shown and kept as
    # evidence, never a stop (enforcement.eligible refuses trace_only).
    # Yalnızca rapor eden yüksek/kritik kural artık iz olarak kaydedilir; durdurmaz.
    if str(finding.get('severity', '')).lower() in ('high', 'critical'):
        finding['trace_only'] = True
        return True
    return False


def _flow_tick(store, config, pipeline, engine, flow, receiver, limit=5000, short_window=None, deep_lane=None):
    """Evaluate the events that arrived in the flow and act at once.

    Akışa gelen olayları değerlendirir ve hemen harekete geçer.
    """
    from satsuma import self_copy
    bodies = receiver.drain(limit)
    fresh = []
    for body in bodies:
        if not isinstance(body, dict) or not isinstance(body.get('event'), dict):
            continue
        flow.add(body)
        if body.get('own'):
            # Satsuma's own command: kept in the process chain, never evaluated.
            continue
        try:
            event = _smart_event(body.get('raw_id'), json.dumps({'raw_id': body.get('raw_id'), 'event': body['event']}, default=str))
            # No evidence window is required for legacy callers. Live mode
            # provides a bounded instance, owned by Smart Rules only.
            short_evidence = short_window.observe(event) if short_window is not None else None
            if deep_lane is not None:
                deep_lane.submit({**event, 'lab_test_mode': store.get('interactive_process_test_mode', False) is True})  # only privileged local setting; never authorizes actions
            for finding in engine.match(event):
                identity = finding.get('event') or {}
                if _recordable(finding) and str(finding.get('rule_id') or '') in self_copy.RULES:
                    # 2.2.45: a packaged tool's own temporary copy (bootc) is recognised from
                    # the process chain before it is recorded (satsuma.self_copy).
                    finding['flow'] = flow.snapshot(identity.get('pid'), identity.get('starttime'))
                    self_copy.apply(finding)
                if not _recordable(finding):
                    continue
                finding['team'] = 'smart_rules'
                annotate_origin(finding, event)
                if short_evidence is not None:
                    finding['short_evidence'] = short_evidence
                if 'flow' not in finding:
                    finding['flow'] = flow.snapshot(identity.get('pid'), identity.get('starttime'))
                result = record_finding(store, finding, 'smart_rules')
                finding['_dedup'] = result
                if result.get('written'):
                    fresh.append(finding)
        except Exception as exc:
            store.add('errors', {'component': 'brain.flow.event', 'error': str(exc)[:300]})
    if fresh:
        _dispatch_safe_actions(pipeline, fresh)
        _automatic_actions(store, config, fresh)
        try:
            _remediate(store, fresh)
        except Exception as exc:
            store.add('errors', {'component': 'remediation', 'error': str(exc)[:300]})
        _sudo_autoblock(pipeline, fresh, config)
        _confirmed_actions(pipeline, fresh)
        if config.get('investigation_enabled', True):
            try:
                from satsuma.investigation import investigate_and_record
                for finding in fresh:
                    investigate_and_record(store, finding, config)
            except Exception as exc:
                store.add('errors', {'component': 'brain.flow.investigation', 'error': str(exc)[:300]})
    return {'events': len(bodies), 'findings': len(fresh)}


def _purge_raw_records(db_path=None, chunk=5000, pause=0.2):
    """One-time removal of stored raw events (user decision 2026-11-04).

    Normalized rows and raw host/Suricata events go; findings, investigations,
    actions and evidence stay. Runs in small chunks in its own connection.
    """
    import sqlite3
    db = sqlite3.connect(str(db_path or '/var/lib/satsuma-core/core.db'), timeout=30)
    try:
        if db.execute("SELECT body FROM state WHERE key='flow.raw_purge_done'").fetchone():
            return 0
        removed = 0
        raw_events = ("kind='events' AND COALESCE(json_extract(body,'$.event.category'),'')!='finding' "
                      "AND json_extract(body,'$.metadata.finding') IS NULL")
        for condition in ("kind='normalized'", raw_events):
            while not shutdown.requested():
                cursor = db.execute(f"DELETE FROM records WHERE id IN (SELECT id FROM records WHERE {condition} LIMIT ?)", (chunk,))
                db.commit()
                removed += cursor.rowcount
                if cursor.rowcount < chunk:
                    break
                time.sleep(pause)
        if not shutdown.requested():
            db.execute("INSERT OR REPLACE INTO state(key,body) VALUES('flow.raw_purge_done',?)",
                       (json.dumps({'removed': removed, 'at': time.time()}),))
            db.commit()
        return removed
    finally:
        db.close()


def _run_once(store, config, pipeline, smart_engine, rule_stats, run_teams=True):
    """Tek bir Brain turu: teams + correlation + smart rules + dispatch.

    Donen deger: health sozlugu.
    """
    from satsuma.process_followup import tick as followup_tick
    phases = {}
    if not shutdown.requested():
        try:
            with _timed(phases, 'followup'):
                followup_tick(store)
        except Exception as exc:
            store.add('errors',{'component':'process_followup','error':type(exc).__name__})
            store.set('process_followup.health',{'updated_at':time.time(),'status':'ERROR','error':type(exc).__name__})
    smart_engine.refresh_managed_rules()
    try:
        # 2.2.59: the owner's DeepSeek rule settings, and rules suspended for burning CPU.
        from satsuma import ai_guard
        smart_engine.ai_overrides = ai_guard.overrides(store)
        from satsuma import strict_mode
        smart_engine.strict_mode = strict_mode.enabled(store)
        _privd_probe(store)
        _policy_signature(store)
        _restart_storms(store)
        _previous_boot_was_off(store)
        _banned_packages(store)
        for rule_id in smart_engine.ai_runtime.take_alarms():
            store.add('findings', ai_guard.suspended_finding(rule_id))
    except Exception as exc:
        store.add('errors', {'component': 'ai_guard', 'error': str(exc)[:300]})
    rule_stats = smart_engine.stats()
    store.set('deepseek_runtime', {'updated_at': time.time(), 'loaded': rule_stats.get('managed_packages', {}),
                                 'load_errors': rule_stats.get('load_errors', [])})
    started = time.time()
    # Ilk 0.5 calismasinda eski normalized gecmisi tekrar alarm yapmasin.
    cursor = store.get(SMART_CURSOR_KEY, None)
    if cursor is None:
        cursor = 0
        store.set(SMART_CURSOR_KEY, cursor)

    try:
        with _timed(phases, 'teams'):
            # Field 2026-11-04: the team collectors took 40 s per round and held
            # the rule engine back; between team rounds only the rules run.
            team_result = _run_teams(store, config, pipeline) if run_teams else {'ok': True, 'teams': 0, 'findings': 0, 'cross_team': 0, 'findings_list': [], 'skipped': True}
        team_findings = team_result.get('findings_list', []) or []
    except Exception as exc:
        team_result = {'teams': 0, 'findings': 0, 'cross_team': 0, 'findings_list': []}
        team_findings = []
        store.add('errors', {'component': 'brain.teams', 'error': str(exc)[:300]})

    correlation_failed = False
    investigation_failed = False
    stopping = shutdown.requested()
    try:
        with _timed(phases, 'correlation'):
            engine_findings = [] if stopping or not run_teams else CorrelationEngine(store, config).correlate()
    except Exception as exc:
        engine_findings = []
        correlation_failed = True
        store.add('errors', {'component': 'brain.correlation_engine', 'error': str(exc)[:300]})

    try:
        if stopping:
            # The cursor stays put; these events are read after the restart.
            smart_findings, smart_health = [], {'processed_events': 0, 'event_errors': 0, 'cursor_start': cursor, 'cursor_end': cursor, 'stopped': True}
        else:
            with _timed(phases, 'smart_rules'):
                smart_findings, smart_health = _run_smart_rules(store, smart_engine, cursor)
    except Exception as exc:
        smart_findings = []
        smart_health = {'processed_events': 0, 'event_errors': 1, 'cursor_start': cursor, 'cursor_end': cursor}
        store.add('errors', {'component': 'brain.smart_rules', 'error': str(exc)[:300]})

    all_findings = team_findings + engine_findings + smart_findings
    try:
        # 2.2.56: what satsuma-kernel-guard put back (/proc/sys, SELinux, boot line) is a finding.
        from satsuma import kernel_guard_findings
        kernel_guard_findings.collect(store)
    except Exception as exc:
        store.add('errors', {'component': 'kernel_guard_findings', 'error': str(exc)[:300]})

    # Field 2026-11-04: stopping decisions came after every finding had been
    # investigated; actions now run first, investigation afterwards.
    with _timed(phases, 'safe_dispatch'):
        safe_dispatch = _dispatch_safe_actions(pipeline, all_findings)
    with _timed(phases, 'automatic_actions'):
        auto_processed, auto_updated, auto_duplicates = _automatic_actions(store, config, all_findings)
    try:
        _remediate(store, smart_findings)
    except Exception as exc:
        store.add('errors', {'component': 'remediation', 'error': str(exc)[:300]})
    sudo_killed = _sudo_autoblock(pipeline, all_findings, config)
    with _timed(phases, 'confirmed_actions'):
        actions, notifications = _confirmed_actions(pipeline, all_findings)

    # Investigation engine — her bulguyu yerel olarak araştır (süreç rolü takibi).
    # Web araştırması yalnızca config açıksa çalışır (varsayılan kapalı).
    investigation_count = 0
    if config.get("investigation_enabled", True):
        try:
            from satsuma.investigation import investigate_and_record
            with _timed(phases, 'investigation'):
                for finding in all_findings:
                    investigate_and_record(store, finding, config)
                    investigation_count += 1
        except Exception as exc:
            investigation_failed = True
            store.add("errors", {"component": "brain.investigation", "error": str(exc)[:300]})
    elapsed = int((time.time() - started) * 1000)
    health = {
        'updated_at': int(time.time()),
        'status': 'STOPPING' if shutdown.requested() else 'DEGRADED' if rule_stats.get('invalid_files') or smart_health.get('event_errors') or not team_result.get('ok',False) or correlation_failed or investigation_failed or store.get('correlation_engine.health', {}).get('status') == 'DEGRADED' else 'RUNNING',
        'teams': team_result.get('teams', 0),
        'team_findings_new': len(team_findings),
        'engine_findings_new': len(engine_findings),
        'smart_findings_new': len(smart_findings),
        'smart_rules_total': rule_stats.get('total_rules', 0),
        'smart_rule_classifications': rule_stats.get('classifications', {}),
        'smart_rule_load_errors': rule_stats.get('load_errors', []),
        'smart': smart_health,
        'auto_actions_processed': auto_processed,
        'auto_actions_updated': auto_updated,
        'auto_action_duplicates': auto_duplicates,
        'automatic_destructive_actions': actions,
        'sudo_autoblock_killed': sudo_killed,
        'notifications': notifications,
        'safe_action_dispatch': safe_dispatch,
        'cross_team_new': team_result.get('new_cross_team', team_result.get('cross_team', 0)),
        'elapsed_ms': elapsed,
        'phase_ms': phases,
        'response_enabled': bool(config.get('response_enabled', False)),
        'response_policy': 'automatic_network_policy; process_termination_requires_confirmed_independent_evidence_and_identity',
    }
    store.set('brain.health', health)
    return health


def main():
    """Brain dongusu: periyodik olarak _run_once cagirir.

    systemd Type=simple ile surekli calisir. Her tur arasinda BRAIN_INTERVAL
    saniye bekler. SIGTERM/SIGINT ile temiz kapanir.
    """
    import signal
    from satsuma.memory_access import protect_self
    protect_self()

    interval = float(os.environ.get('SATSUMA_BRAIN_INTERVAL', '10'))
    # Team collectors run at most this often; the rule engine runs every round.
    teams_interval = float(os.environ.get('SATSUMA_TEAMS_INTERVAL', '30'))
    last_teams = -teams_interval
    running = True

    def _stop(*_):
        nonlocal running
        running = False
        shutdown.request()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    store = Store()
    try:
        config = load()
        config['early_guard_required']=True
        pipeline = Pipeline(store, config)
        smart_engine = SmartRuleEngine()
        rule_stats = smart_engine.stats()
        # 2.2.38: account snapshot before the first event, so the first write to
        # /etc/passwd or /etc/shadow is compared with something.
        try:
            from satsuma import account_change
            account_change.TRACKER.baseline()
        except Exception as exc:
            store.add('errors', {'component': 'brain.account_snapshot', 'error': str(exc)[:300]})
        # Event flow (2.2.32): events arrive here instead of the database.
        from satsuma import flow as flow_module
        process_flow = flow_module.ProcessFlow(window=float(config.get('flow_window_seconds', 1800)))
        short_window = ShortEvidenceWindow()
        deep_lane = None
        deep_lane_error = None
        deep_lane_tried = 0.0

        def connect_deep_lane():
            # 2.2.38: one failed start no longer leaves the deep engine link off
            # for the life of the service; it is tried again every 30 seconds.
            # Tek başarısız deneme bağlantıyı servis boyunca kapalı bırakmaz.
            nonlocal deep_lane, deep_lane_error, deep_lane_tried
            deep_lane_tried = time.monotonic()
            try:
                from satsuma_engine.process_ipc import DeepProcessClient
                deep_lane = DeepProcessClient()
                deep_lane_error = None
            except Exception as exc:
                deep_lane_error = f'{type(exc).__name__}: {exc}'[:200]
                store.add('errors', {'component': 'brain.deep_engine.start', 'error': deep_lane_error})

        connect_deep_lane()
        receiver = flow_module.FlowReceiver()
        try:
            receiver.start()
        except OSError as exc:
            store.add('errors', {'component': 'brain.flow.socket', 'error': str(exc)[:300]})
        flow_module.ACTIVE = process_flow
        pipeline.flow_sink = receiver.put
        import threading
        threading.Thread(target=_purge_raw_records, name='satsuma-raw-purge', daemon=True).start()
        last_flow_health = 0.0

        def flow_step():
            nonlocal last_flow_health
            if deep_lane is None and time.monotonic() - deep_lane_tried >= 30:
                connect_deep_lane()
            try:
                _flow_tick(store, config, pipeline, smart_engine, process_flow, receiver, short_window=short_window, deep_lane=deep_lane)
            except Exception as exc:
                store.add('errors', {'component': 'brain.flow', 'error': str(exc)[:300]})
            if time.monotonic() - last_flow_health >= 5:
                last_flow_health = time.monotonic()
                store.set('flow.health', {'updated_at': time.time(), 'receiver': receiver.health(),
                                          'processes': process_flow.health(), 'smart_short_evidence': short_window.health(),
                                          'deep_engine': deep_lane.health() if deep_lane else {'running': False, 'error': deep_lane_error},
                                          'socket': str(flow_module.SOCKET)})
        while running:
            start = time.monotonic()
            health = None
            try:
                run_teams = time.monotonic() - last_teams >= teams_interval
                health = _run_once(store, config, pipeline, smart_engine, rule_stats, run_teams=run_teams)
                if deep_lane is not None:
                    for evidence in deep_lane.drain(8):
                        # Not forwarded to enforcement, only archived as bounded evidence.
                        # Do not persist lab suggestions after test mode is turned off.
                        # These are review evidence, not process approval/execution.
                        if evidence.get('test_rule') is True and store.get('interactive_process_test_mode', False) is not True:
                            continue
                        store.add('deep_engine_evidence', evidence)
                        if evidence.get('test_rule') is True and evidence.get('review_required') is True:
                            from satsuma.deep_rule_review import enqueue as queue_deep_review
                            queue_deep_review(store, evidence)
                if run_teams:
                    last_teams = time.monotonic()
                print(json.dumps(health, ensure_ascii=False), flush=True)
            except Exception as exc:
                store.add('errors', {'component': 'brain.loop', 'error': str(exc)[:300]})
                store.set('brain.health', {
                    'updated_at': int(time.time()),
                    'status': 'ERROR',
                    'error': str(exc)[:300],
                })
            # Field 2026-11-04: with a backlog, the next round starts at once
            # (decisions were up to 38 minutes behind the events).
            if isinstance(health, dict) and (health.get('smart') or {}).get('backlog_remaining'):
                flow_step()
                continue
            # Tur arasi bekleme (SIGTERM'e duyarli); the flow is served meanwhile.
            while running and time.monotonic() - start < interval:
                flow_step()
                time.sleep(0.25)
        return 0
    finally:
        if locals().get('deep_lane') is not None:
            deep_lane.close()
        try:
            receiver.close()
        except NameError:
            pass
        manager=getattr(pipeline, '_team_manager', None)
        if manager:
            for team in manager.teams:
                for worker in team.worker_instances:
                    if hasattr(worker, 'close'):worker.close()
        store.close()


if __name__ == '__main__':
    from satsuma.integrity_monitor import assess_runtime
    assessment=assess_runtime()
    if assessment['status']!='HEALTHY':
        print('SATSUMA INTEGRITY WARNING: correlation continues; mutations locked: '+assessment.get('error',''),file=sys.stderr)
        state=Store()
        try:
            state.set('integrity_runtime',assessment)
            state.add('errors',{'component':'brain.integrity',**assessment})
        finally:state.close()
    sys.exit(main())
