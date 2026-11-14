import hashlib
import json
from types import SimpleNamespace

from satsuma.tpm_public_inventory import (collect_public, parse_object_public,
    parse_nv_public, compare_public_with_pin)

N1='000b'+'ab'*32
Q1='000b'+'cd'*32
N2='000b'+'ee'*32
NV=b'''0x1000001:
  hash algorithm:
    friendly: sha256
    value: 0xB
  attributes:
    friendly: ownerwrite|ownerread
    value: 0x2000200
  size: 32
  authorization policy:
'''


def runner(cmd, **kw):
    assert kw['timeout']==8 and kw['capture_output'] and kw['check'] is False
    assert kw['env']['LC_ALL']=='C'
    if cmd[0]=='/usr/bin/tpm2_getcap':
        result=b'- 0x81000001\n' if cmd[1]=='handles-persistent' else b'- 0x01000001\n'
    elif cmd==['/usr/bin/tpm2_readpublic','-c','0x81000001']:
        result=('name: '+N1+'\nqualified name: '+Q1+'\ntype: rsa\n').encode()
    elif cmd==['/usr/bin/tpm2_nvreadpublic']:
        result=NV
    else:
        raise AssertionError(cmd)
    return SimpleNamespace(returncode=0,stdout=result)


def test_public_collection_only_read_commands():
    cmds=[]
    def capture(cmd, **kw):
        cmds.append(cmd)
        return runner(cmd,**kw)
    result=collect_public(runner=capture)
    assert result['status']=='LOCAL_PUBLIC_INVENTORY_OBSERVED'
    assert result['verified'] is False and result['tpm_modified'] is False
    assert result['persistent']['0x81000001']['name']==N1
    assert len(result['nv_indices']['0x01000001']['public_metadata_sha256'])==64
    assert cmds==[['/usr/bin/tpm2_getcap','handles-persistent'],
                  ['/usr/bin/tpm2_getcap','handles-nv-index'],
                  ['/usr/bin/tpm2_readpublic','-c','0x81000001'],
                  ['/usr/bin/tpm2_nvreadpublic'],
                  ['/usr/bin/tpm2_getcap','handles-persistent'],
                  ['/usr/bin/tpm2_getcap','handles-nv-index']]


def test_public_name_rejects_spoofing_and_missing():
    import pytest
    for bad in [b'name: abc\nqualified name: abc\n',
                ('name: '+N1+'\n').encode(),
                ('name: '+N1+'\nname: '+N2+'\nqualified name: '+Q1+'\n').encode(),
                b'name: 000b' + b'0'*64 + b'\x1b[31m\nqualified name: '+Q1.encode()]:
        with pytest.raises(ValueError): parse_object_public(bad)


def test_nv_rejects_missing_and_injected_metadata():
    import pytest
    assert parse_nv_public(NV, ['0x01000001'])['0x01000001']['metadata_source'].startswith('local_')
    for bad in (NV.replace(b'  size: 32\n',b''),
                NV.replace(b'0x1000001',b'0x1000002'),
                NV+b'0x1000001:\n',
                NV.replace(b'sha256',b'\x1b[1msha256')):
        with pytest.raises(ValueError): parse_nv_public(bad,['0x01000001'])


def test_same_handle_changed_identity_detected(tmp_path):
    observed=collect_public(runner=runner)
    ref={'schema':2, 'persistent':observed['persistent'], 'nv_indices':observed['nv_indices']}
    f=tmp_path/'ref.json'
    raw=json.dumps(ref).encode()
    f.write_bytes(raw)
    pin=hashlib.sha256(raw).hexdigest()
    assert compare_public_with_pin(observed,f,pin)['status']=='PUBLIC_IDENTITIES_MATCH_PINNED_BASELINE'
    observed['persistent']['0x81000001']={'name':N2,'qualified_name':Q1}
    diff=compare_public_with_pin(observed,f,pin)
    assert diff['status']=='PUBLIC_IDENTITY_CHANGE_OBSERVED'
    assert diff['changes']['persistent']['identity_changed']==['0x81000001']
    assert diff['baseline_authenticated'] is False
    assert diff['trusted_boot_verified'] is False


def test_tampered_pin_and_symlink_rejected(tmp_path):
    observed=collect_public(runner=runner)
    f=tmp_path/'ref.json'
    raw=json.dumps({'schema':2,'persistent':observed['persistent'],'nv_indices':observed['nv_indices']}).encode()
    f.write_bytes(raw)
    assert compare_public_with_pin(observed,f,'0'*64)['status']=='BASELINE_PIN_MISMATCH'
    link=tmp_path/'link'
    link.symlink_to(f)
    assert compare_public_with_pin(observed,link,hashlib.sha256(raw).hexdigest())['status']=='INVALID_BASELINE'


def test_fail_closed_when_partial_or_changed():
    def partial(cmd, **kw):
        if cmd[0]=='/usr/bin/tpm2_readpublic':
            return SimpleNamespace(returncode=1,stdout=b'')
        return runner(cmd,**kw)
    assert collect_public(runner=partial)['status']=='PUBLIC_READ_FAILED'
    counter=[0]
    def changed(cmd,**kw):
        if cmd==['/usr/bin/tpm2_getcap','handles-persistent']:
            counter[0]+=1
            if counter[0]>1:
                return SimpleNamespace(returncode=0,stdout=b'- 0x81000002\n')
        return runner(cmd,**kw)
    assert collect_public(runner=changed)['status']=='HANDLE_SET_CHANGED_DURING_READ'


def test_cap_avoids_unbounded_tpm_requests():
    many=[f'0x8100{i:04x}' for i in range(129)]
    fake={'status':'LOCAL_INVENTORY_OBSERVED','capabilities':{
        'handles-persistent':{'handles':many},'handles-nv-index':{'handles':[]}}}
    assert collect_public(handle_inventory=fake)['status']=='PUBLIC_INVENTORY_LIMIT'
