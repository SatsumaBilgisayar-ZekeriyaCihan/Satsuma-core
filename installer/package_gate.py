"""Private, bounded stdin protocol used by the native libdnf5 veto plugin."""
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,'/opt/satsuma-core')
from satsuma.package_trust import PackageGate,ROOT,load_policy,TrustDenied,parse_json,initialize_policy
from satsuma.protected_storage import open_directory


def main():
    if os.geteuid()!=0:raise TrustDenied('Package enforcement requires root')
    from satsuma.self_guard import verify
    verify()
    if sys.argv[1:]==['--initialize-policy']:
        initialize_policy()
        return
    request=sys.stdin.buffer.read(8*1024*1024+1)
    if len(request)>8*1024*1024:raise TrustDenied('Oversized package request')
    data=parse_json(request)
    directory=open_directory(ROOT);os.close(directory)
    gate=PackageGate(load_policy())
    if data.get('stage')=='repositories':
        for repo in data['repositories']:gate.seed_metadata_keys(repo)
    elif data.get('stage')=='planned':gate.plan(data['packages'])
    elif data.get('stage')=='downloaded':gate.verify_downloaded(data['packages'])
    else:raise TrustDenied('Unknown verification stage')
    from satsuma.protected_storage import RootDataStore
    import time
    RootDataStore('package-trust/audit.jsonl').append({'timestamp':time.time(),'stage':data['stage'],'status':'verification_passed','packages':len(data.get('packages',[]))})
    print('OK',flush=True)


if __name__=='__main__':
    try:main()
    except Exception as exc:
        try:
            import time
            from satsuma.protected_storage import RootDataStore
            RootDataStore('package-trust/audit.jsonl').append({'timestamp':time.time(),'status':'verification_denied','error':str(exc)[:300]})
        except Exception:
            pass
        print('SATSUMA PACKAGE DENIED: '+str(exc),file=sys.stderr)
        raise SystemExit(1)
