import hashlib
from types import SimpleNamespace
from satsuma.tpm_quote_verifier import verify_quote


def setup(tmp_path):
    paths = {}
    for name in ('ak_public','message','signature','pcr'):
        p=tmp_path/name
        p.write_bytes(('test-'+name).encode())
        paths[name]=p
    args=dict(**paths,
              expected_ak_sha256=hashlib.sha256(paths['ak_public'].read_bytes()).hexdigest(),
              expected_pcr_sha256=hashlib.sha256(paths['pcr'].read_bytes()).hexdigest(),
              nonce_hex='ab'*32)
    return args


def test_good_quote_still_not_full_device_trust(tmp_path):
    args=setup(tmp_path)
    seen=[]
    def runner(cmd, **kw):
        seen.append((cmd,kw))
        return SimpleNamespace(returncode=0)
    result=verify_quote(**args,runner=runner)
    assert result['status']=='QUOTE_AND_PINNED_PCR_VERIFIED'
    assert result['quote_signature_verified'] is True
    assert result['platform_identity_verified'] is False
    assert result['trusted_boot_verified'] is False
    assert seen[0][0][0]=='/usr/bin/tpm2_checkquote'
    assert seen[0][0][-2:]==['-q','ab'*32]
    assert seen[0][1]['timeout']==15


def test_rejected_signature(tmp_path):
    args=setup(tmp_path)
    result=verify_quote(**args,runner=lambda *a,**kw: SimpleNamespace(returncode=1))
    assert result['status']=='QUOTE_REJECTED'
    assert result['quote_signature_verified'] is False


def test_wrong_ak_does_not_execute(tmp_path):
    args=setup(tmp_path)
    args['expected_ak_sha256']='00'*32
    result=verify_quote(**args,runner=lambda *a,**kw: 1/0)
    assert result['status']=='AK_REFERENCE_MISMATCH'


def test_wrong_pcr_does_not_execute(tmp_path):
    args=setup(tmp_path)
    args['expected_pcr_sha256']='00'*32
    assert verify_quote(**args,runner=lambda *a,**kw: 1/0)['status']=='PCR_REFERENCE_MISMATCH'


def test_no_nonce_or_weak_nonce_rejected(tmp_path):
    args=setup(tmp_path)
    args['nonce_hex']='abcd'
    assert verify_quote(**args,runner=lambda *a,**kw: 1/0)['status']=='INVALID_EXTERNAL_REFERENCE'


def test_symlink_evidence_rejected(tmp_path):
    args=setup(tmp_path)
    alias=tmp_path/'alias'
    alias.symlink_to(args['pcr'])
    args['pcr']=alias
    assert verify_quote(**args,runner=lambda *a,**kw: 1/0)['status']=='CHECK_UNAVAILABLE_OR_INVALID_INPUT'


def test_swap_after_check_rejected(tmp_path):
    args=setup(tmp_path)
    def runner(*a,**kw):
        args['message'].write_bytes(b'changed')
        return SimpleNamespace(returncode=0)
    assert verify_quote(**args,runner=runner)['status']=='EVIDENCE_CHANGED'


def test_no_tool_does_not_pass(tmp_path):
    args=setup(tmp_path)
    def runner(*a,**kw):
        raise FileNotFoundError()
    assert verify_quote(**args,runner=runner)['status']=='CHECK_UNAVAILABLE_OR_INVALID_INPUT'
