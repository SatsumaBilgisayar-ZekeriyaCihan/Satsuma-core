"""Disposable audit client: real RAM rule/response path, no production broker.

Geçici denetim istemcisi: gerçek RAM kural/müdahale yolu; üretim broker'ına bağlanmaz.
"""
import ctypes
import json
from pathlib import Path
import sys
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))


def main():
    # Match the relevant service boundary: ptrace is retained, DAC override is not.
    class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
    class Caps(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
    libc=ctypes.CDLL(None,use_errno=True);header=Header(0x20080522,0);caps=(Caps*2)()
    caps[0].effective=caps[0].permitted=1<<19  # CAP_SYS_PTRACE only
    if libc.capset(ctypes.byref(header),ctypes.byref(caps))!=0:
        raise OSError(ctypes.get_errno(),'capset audit client')
    from satsuma.store import Store
    from satsuma.config import validate
    from satsuma.pipeline import Pipeline
    from satsuma.smart_rules import SmartRuleEngine
    from satsuma.auto_action import AutoActionEngine
    from satsuma.response import ResponseWorker
    from run_satsuma_teams import _smart_event
    raw=json.loads(Path(sys.argv[1]).read_text())
    store=Store(sys.argv[2],test=True)
    try:
        config={**validate({}),'response_enabled':True,'destructive_response_enabled':True,
                'destructive_allowed_actions':['process_kill'],'auto_action_process_enabled':True}
        pipeline=Pipeline(store,config)
        pipeline.ingest_host(raw)
        row=store.db.execute("SELECT id,body FROM records WHERE kind='normalized' ORDER BY id DESC LIMIT 1").fetchone()
        event=_smart_event(*row)
        matches=SmartRuleEngine(include_managed=False).match(event)
        finding=next(f for f in matches if f['rule_id']=='SATSUMA-RAM-106')
        store.set('integrity_runtime',{'status':'HEALTHY'})
        response=ResponseWorker(store,config,runner=object())
        # This one external prerequisite is a controlled test fixture. Rule matching,
        # signature revalidation, policy, identity, pidfd and signals remain real.
        with patch('satsuma.early_guard.read_verdict',return_value={'state':'FULL_CHECKED','response_unlocked':True}):
            result=AutoActionEngine(store,config,response).process(finding)['process_response']
        print(json.dumps({'result':result,'rule':finding['rule_id'],'fixture_trust_only':True}))
    finally:store.close()


if __name__=='__main__':main()
