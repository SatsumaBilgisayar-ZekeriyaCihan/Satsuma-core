import json
import pytest
from network_fixture import table_json
from satsuma.response import ResponseWorker
from satsuma.store import Store

@pytest.mark.parametrize('fails',[False,True])
def test_unblock_requires_kernel_absence_before_removing_persistent_block(tmp_path,fails):
    store=Store(tmp_path/'data',test=True)
    store.set('persistent_blocks',{'192.168.1.20':{'ip':'192.168.1.20'}})
    peers={'192.168.1.20'}
    def runner(args):
        if args[1:3]==['delete','element'] and not fails:peers.clear()
        data=json.loads(table_json())
        next(x['set'] for x in data['nftables'] if x.get('set',{}).get('name')=='blocked_ips')['elem']=sorted(peers)
        return {'returncode':int(fails) if args[1:3]==['delete','element'] else 0,'stdout':json.dumps(data)}
    worker=ResponseWorker(store,{'response_enabled':True},runner=runner)
    try:
        result=worker.unblock_ip('192.168.1.20','operator',manual=True)
        assert result['ok'] is not fails
        assert ('192.168.1.20' in store.get('persistent_blocks')) is fails
    finally:store.close()
