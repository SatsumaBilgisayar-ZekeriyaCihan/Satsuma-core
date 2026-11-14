"""One fail-closed trust decision for active response; not a scan scheduler.

Etkin müdahale için tek, hata halinde kapalı güven kararı; tarama zamanlayıcısı değildir.
"""


def evaluate(store, verdict_reader=None):
    from .early_guard import read_verdict
    reasons=[]
    try:
        runtime=store.get('integrity_runtime', {}) or {}
        runtime_status=runtime.get('status') if isinstance(runtime,dict) else None
    except Exception:
        runtime_status=None
    if runtime_status != 'HEALTHY':
        reasons.append('application_integrity_unverified')
    try:
        verdict=(verdict_reader or read_verdict)()
        if not isinstance(verdict,dict):
            verdict={}
    except Exception:
        verdict={}
    if verdict.get('response_unlocked') is not True or verdict.get('state') != 'FULL_CHECKED':
        reasons.append('boot_verdict_unverified_or_stale')
    return {'allowed':not reasons,'status':'LOCKED' if reasons else 'READY',
            'reasons':reasons,'runtime_status':runtime_status or 'UNKNOWN',
            'verdict_state':str(verdict.get('state','UNKNOWN'))[:80],
            'observation_policy_unchanged':True}
