import json, os, time
from pathlib import Path
from .gateway_guard import Guard, snapshot, save_profiles, load_profiles
from .store import Store
BASE=Path('/var/lib/satsuma-core'); PROFILE=BASE/'gateway-profiles.json'; EVENTS=BASE/'gateway-events.jsonl'
def run():
    from .runtime_user import require_service_user; require_service_user()
    BASE.mkdir(mode=0o700,parents=True,exist_ok=True)
    # Keep the first baseline across restarts; never adopt the current state silently.
    baseline=load_profiles(PROFILE)
    if baseline is None:
        baseline=snapshot(); save_profiles(PROFILE,baseline)
    guard=Guard(baseline)
    store=Store();reported=None
    while True:
        current=snapshot()
        events=guard.check(current)
        # A lasting difference is recorded once, not every five seconds.
        signature=json.dumps([{k:v for k,v in e.items() if k!='timestamp'} for e in events],sort_keys=True)
        if signature==reported:events=[]
        else:reported=signature
        for event in events:
            with EVENTS.open('a',encoding='utf-8') as h: h.write(json.dumps(event)+'\n')
            store.add('gateway', event)
        store.set('gateway_health', {'status':'running','interfaces':sorted(current), 'last_check':time.time(), 'events':len(events)})
        time.sleep(5)
