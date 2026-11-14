"""Ticket-free response with durable decision and observational follow-up links.

Kalıcı karar ve gözlemsel takip bağlarıyla biletsiz müdahale.
"""
import hashlib
import ipaddress
import json
import time
from .response import ResponseWorker
from .response_policy import authorize_destructive, independent_sources


def network_target(store, finding, now):
    """Resolve a unique remote endpoint using fresh local address inventory."""
    event = finding.get('event') if isinstance(finding.get('event'), dict) else {}
    explicit = finding.get('target_ip') or event.get('target_ip') or finding.get('remote_ip') or event.get('remote_ip')
    if explicit:
        return explicit
    inventory = store.get('network_discovery', {}) or {}
    stamp = inventory.get('updated_at')
    if not isinstance(stamp, (int, float)) or not 0 <= now - stamp < 90:
        return None
    local = set()
    for row in inventory.get('interfaces', []):
        for value in row.get('addresses', []):
            try:local.add(str(ipaddress.ip_interface(value).ip))
            except ValueError:continue
    targets = set()
    for row in [event, *(finding.get('events') or [])]:
        if not isinstance(row, dict):continue
        net = row.get('network') or row
        try:
            src = str(ipaddress.ip_address(net.get('src_ip')))
            dst = str(ipaddress.ip_address(net.get('dst_ip') or net.get('dest_ip')))
        except (ValueError, TypeError):continue
        if (src in local) != (dst in local):
            targets.add(dst if src in local else src)
    return next(iter(targets)) if len(targets) == 1 else None


def effective_config(store, config):
    result = dict(config)
    policy = store.get('auto_action_policy', {}) or {}
    result['early_guard_required'] = bool(result.get('early_guard_required') or policy.get('early_guard_required') is True)
    if policy.get('network_enabled') is True:
        allowed = list(result.get('destructive_allowed_actions') or [])
        if 'network_isolate' not in allowed:
            allowed.append('network_isolate')
        result.update(response_enabled=True, destructive_response_enabled=True,
                      destructive_allowed_actions=allowed, auto_action_network_enabled=True)
    elif policy.get('network_enabled') is False:
        result['auto_action_network_enabled'] = False
    return result


class AutoActionEngine:
    def __init__(self, store, config=None, response=None):
        self.store, self.config, self.response = store, config or {}, response
        store.db.execute('CREATE TABLE IF NOT EXISTS auto_action_dedup '
                         '(fingerprint TEXT PRIMARY KEY, last_seen REAL NOT NULL)')
        store.db.commit()

    def process(self, finding):
        from .process_followup import register,decision
        register(self.store,finding)
        from .ai_rule_package import is_ai_finding
        from .ai_enforcement import eligible
        if is_ai_finding(finding) and eligible(finding, self.store)[0] is None:
            result = {'action': 'proposal', 'status': 'operator_policy_review_required',
                      'rule_id': finding.get('rule_id'), 'finding_id': finding.get('finding_id'),
                      'executed': False}
            self.store.add('safe_evidence', {**result, 'timestamp': time.time()})
            decision(self.store,finding,result)
            return result
        now = time.time()
        event = finding.get('event') if isinstance(finding.get('event'), dict) else {}
        from .opnsense_advisory import is_opnsense_advisory
        remote_advisory = is_opnsense_advisory(finding)
        target = network_target(self.store, finding, now)
        seed = [finding.get('finding_id'), finding.get('rule_id'), finding.get('type'), target,
                finding.get('classification'), sorted(independent_sources(finding))]
        fp = hashlib.sha256(json.dumps(seed, sort_keys=True).encode()).hexdigest()
        cursor = self.store.db.execute('INSERT INTO auto_action_dedup VALUES (?,?) '
            'ON CONFLICT(fingerprint) DO UPDATE SET last_seen=excluded.last_seen '
            'WHERE auto_action_dedup.last_seen < ?', (fp, now, now - 300))
        self.store.db.commit()
        if cursor.rowcount == 0:
            from .process_followup import duplicate
            duplicate(self.store,finding)
            return {'action': 'duplicate', 'status': 'duplicate'}
        self.store.db.execute('DELETE FROM auto_action_dedup WHERE last_seen < ?', (now - 86400,))
        self.store.db.commit()
        self.store.add('safe_evidence', {'timestamp': now, 'finding_id': finding.get('finding_id'),
            'rule_id': finding.get('rule_id'), 'classification': finding.get('classification'), 'finding': finding})
        result = {'timestamp': now, 'action': 'evidence', 'status': 'evidence_recorded',
                  'finding_id': finding.get('finding_id'), 'target': target,
                  'reason': 'Ağ ve süreç müdahale kararları ayrı değerlendirildi',
                  'network_evaluation': {'status':'TARGET_PRESENT' if target else 'NO_NETWORK_TARGET',
                                         'required_for_process_termination':False}}
        config = effective_config(self.store, self.config)
        from .auto_process import respond as respond_process
        # Every finding is evaluated, including record/log-only rules. The
        # authorization gate, not YAML action spelling, grants termination.
        # Enabling network response must not implicitly enable process kills.
        from . import enforcement
        process_config = enforcement.apply(self.store, {**self.config, 'early_guard_required': config.get('early_guard_required', False)})
        process_response = self.response or ResponseWorker(self.store, process_config)
        try:
            result['process_response'] = respond_process(self.store, process_config, finding, process_response)
        except Exception as exc:
            failure={'timestamp':time.time(),'action':'process.terminate',
                     'finding_id':finding.get('finding_id'),'rule_id':finding.get('rule_id'),
                     'status':'response_error','signal_sent':None,'exit_verified':None,
                     'outcome_known':False,'reasons':['response_exception:'+type(exc).__name__]}
            self.store.add('actions',failure)
            decision(self.store,finding,failure)
            raise
        self.store.set('auto_action_effective', {'network_enabled': bool(config.get('auto_action_network_enabled')),
                                               'updated_at': now})
        if remote_advisory:
            result.update(action='recommendation', status='remote_advisory_only',
                          target_scope='opnsense', executed=False,
                          reason='OPNsense kararları yalnızca bulgu olarak kaydedilir')
        elif target:
            from .auto_network import respond
            response = self.response or ResponseWorker(self.store, config)
            result.update(action='network.block')
            # 2.2.11: no attempts-per-minute quota (full protection).
            auth = authorize_destructive('network_isolate', finding, config,
                                         context={'target_ip': target, 'automated': True}, evidence_store=self.store)
            if not auth.allowed:
                result.update(status='policy_denied', reasons=list(auth.reasons))
            else:
                try:
                    result.update(respond(response, finding, target, finding.get('title') or 'AutoAction'))
                except Exception as exc:
                    result.update(status='failed', reason=str(exc)[:300])
        self.store.add('actions', result)
        return {**result, 'action': 'processed'}
