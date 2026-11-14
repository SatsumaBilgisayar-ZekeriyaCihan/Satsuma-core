"""Operator-selected automatic network policy; classifications stay unchanged."""
import ipaddress,time

def eligible(finding,config):
    return bool(config.get('response_enabled') and config.get('destructive_response_enabled')
                and 'network_isolate' in config.get('destructive_allowed_actions',[])
                and finding.get('classification') in ('suspicious','likely','confirmed'))

def respond(response,finding,target,reason,raw_id=None,context=None):
    from .opnsense_advisory import is_opnsense_advisory
    if is_opnsense_advisory(finding):
        return {'status':'remote_advisory_only', 'executed':False, 'target_scope':'opnsense'}
    from .auto_action import effective_config
    from .response import ResponseWorker
    config = effective_config(response.store, response.config)
    response = ResponseWorker(response.store, config, response.replay, runner=response.runner)
    stamp=(finding.get('event') or {}).get('timestamp') or finding.get('timestamp')
    if stamp is None:return {'status':'missing_event_time'}
    if stamp is not None:
        try:
            from datetime import datetime
            observed=float(stamp) if isinstance(stamp,(int,float)) else datetime.fromisoformat(str(stamp).replace('Z','+00:00')).timestamp()
            if time.time()-observed>300 or observed-time.time()>60:return {'status':'historical_review_only'}
        except (TypeError,ValueError):return {'status':'invalid_event_time'}
    if not eligible(finding,response.config):return {'status':'policy_denied'}
    try:addr=ipaddress.ip_address(target)
    except (TypeError,ValueError):return {'status':'invalid_ip'}
    from .full_protection import protected_reason
    if protected_reason(addr):return {'status':protected_reason(addr),'ip':str(addr)}
    from .response_policy import authorize_destructive, denied_action_record
    auth = authorize_destructive(
        'network_isolate', finding, response.config,
        context={**(context or {}), 'automated': True, 'target_ip': str(addr), 'response_enabled': bool(response.config.get('response_enabled'))},
        evidence_store=response.store,
    )
    if not auth.allowed:
        record = denied_action_record(auth, finding)
        record['target_ip'] = str(addr)
        response.store.add('actions', record)
        return {'status': 'policy_denied', 'reasons': list(auth.reasons), 'ip': str(addr)}
    guard = response._guard('block_ip', str(addr))
    if guard:
        return guard
    db = response.store.db
    db.execute('CREATE TABLE IF NOT EXISTS auto_network_limits (target TEXT PRIMARY KEY, attempted REAL NOT NULL)')
    db.commit()
    now = time.time()
    db.execute('BEGIN IMMEDIATE')
    try:
        cursor = db.execute('INSERT INTO auto_network_limits VALUES (?,?) ON CONFLICT(target) '
                            'DO UPDATE SET attempted=excluded.attempted WHERE auto_network_limits.attempted < ?',
                            (str(addr), now, now - 300))
        if cursor.rowcount == 0:
            db.rollback()
            return {'status': 'cooldown', 'ip': str(addr)}
        db.execute('DELETE FROM auto_network_limits WHERE attempted < ?', (now - 86400,))
        db.commit()
    except Exception:
        db.rollback()
        raise
    response.store.add('actions',{'timestamp':time.time(),'status':'auto_block_authorized',
        'policy':auth.policy,'classification':finding.get('classification'),
        'rule_id':finding.get('rule_id'),'target':str(addr),'sources':list(auth.sources)})
    return response.block_ip(str(addr),reason,raw_id=raw_id)
