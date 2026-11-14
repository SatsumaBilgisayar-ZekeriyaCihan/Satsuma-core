import json
from types import SimpleNamespace

from satsuma.deployment_attestation import (parse_booted_identity, parse_signed_reference,
                                           compare_reference, verify_signed_deployment_reference,
                                           BOOTC_CMD, RPM_OSTREE_CMD)

D = 'a'*64
FPR = 'B'*40


def test_bootc_only_booted_digest():
    doc = {'apiVersion': 'org.containers.bootc/v1', 'status': {'booted': {'image': {'imageDigest': 'sha256:'+D}}, 'staged': {'image': {'imageDigest': 'sha256:'+('c'*64)}}}}
    assert parse_booted_identity('bootc', json.dumps(doc))['digest'] == 'sha256:'+D
    doc['status']['booted'] = None
    assert parse_booted_identity('bootc', json.dumps(doc))['status'] == 'NO_BOOTED_DEPLOYMENT'
    doc['status']['booted'] = {'image': {'imageDigest': 'sha256:BAD'}}
    assert parse_booted_identity('bootc', json.dumps(doc))['status'] == 'MISSING_BOOTED_DIGEST'


def test_ostree_exact_single_booted():
    doc = {'deployments': [{'booted': True, 'checksum': D}, {'booted': False, 'checksum': 'c'*64}]}
    assert parse_booted_identity('ostree', json.dumps(doc))['digest'] == D
    doc['deployments'][1]['booted'] = True
    assert parse_booted_identity('ostree', json.dumps(doc))['status'] == 'AMBIGUOUS_BOOTED_DEPLOYMENT'


def test_reference_schema_fail_closed():
    good = {'schema': 1, 'mode': 'ostree', 'allowed_digests': [D]}
    assert parse_signed_reference(json.dumps(good).encode())['mode'] == 'ostree'
    for bad in ({**good, 'allowed_digests': []}, {**good, 'extra': True},
                {**good, 'allowed_digests': [D,D]}, {**good, 'mode': 'bootc'}):
        assert parse_signed_reference(json.dumps(bad).encode()) is None


def test_matching_reference_not_full_verification():
    ref = {'mode':'ostree', 'allowed_digests':{D}}
    r = compare_reference(ref, {'status':'IDENTITY_OBSERVED', 'mode':'ostree','digest':D})
    assert r['status'] == 'SIGNED_REFERENCE_MATCH' and not r['verified']
    assert compare_reference(ref, {'status':'IDENTITY_OBSERVED','mode':'ostree','digest':'c'*64})['status']=='SIGNED_REFERENCE_MISMATCH'


def test_signature_and_independent_fingerprint_required(tmp_path):
    manifest = tmp_path/'manifest.json'; signature=tmp_path/'manifest.sig'; key=tmp_path/'keys.gpg'
    manifest.write_text(json.dumps({'schema':1,'mode':'ostree','allowed_digests':[D]}))
    signature.write_bytes(b'sig'); key.write_bytes(b'key')
    def runner(argv, **kw):
        if argv[0]=='/usr/bin/gpgv':
            return SimpleNamespace(returncode=0, stderr=('[GNUPG:] VALIDSIG '+FPR+' 1 0 0 0 0 0 0\n').encode())
        assert argv == RPM_OSTREE_CMD
        return SimpleNamespace(returncode=0, stdout=json.dumps({'deployments':[{'booted':True,'checksum':D}]}))
    r = verify_signed_deployment_reference(manifest,signature,key,FPR,runner=runner)
    assert r['status']=='SIGNED_REFERENCE_MATCH' and not r['verified']
    assert verify_signed_deployment_reference(manifest,signature,key,'C'*40,runner=runner)['status']=='UNTRUSTED_REFERENCE_SIGNER'
    def badsig(argv, **kw):
        return SimpleNamespace(returncode=1,stderr=b'BAD')
    assert verify_signed_deployment_reference(manifest,signature,key,FPR,runner=badsig)['status']=='BAD_REFERENCE_SIGNATURE'


def test_bootc_signed_reference(tmp_path):
    paths=[tmp_path/name for name in ('manifest.json','manifest.sig','keyring.gpg')]
    paths[0].write_text(json.dumps({'schema':1,'mode':'bootc','allowed_digests':['sha256:'+D]}))
    paths[1].write_bytes(b'x'); paths[2].write_bytes(b'y')
    def runner(argv, **kw):
        if argv[0]=='/usr/bin/gpgv':
            return SimpleNamespace(returncode=0, stderr=('[GNUPG:] VALIDSIG '+FPR+' 1 0 0 0 0 0 0\n').encode())
        assert argv==BOOTC_CMD
        return SimpleNamespace(returncode=0, stdout=json.dumps({'apiVersion':'org.containers.bootc/v1','status':{'booted':{'image':{'imageDigest':'sha256:'+D}}}}))
    assert verify_signed_deployment_reference(*paths,FPR,runner=runner)['status']=='SIGNED_REFERENCE_MATCH'


def test_bootc_signature_policy_observations(tmp_path):
    from satsuma.deployment_attestation import bootc_signature_policy_observation
    p = tmp_path/'policy.json'
    p.write_text(json.dumps({'default':[{'type':'insecureAcceptAnything'}]}))
    assert bootc_signature_policy_observation(p)['status']=='DEFAULT_ACCEPTS_UNSIGNED_IMAGES'
    p.write_text(json.dumps({'default':[{'type':'reject'}], 'transports': {'docker': {'example.com': [{'type':'signedBy','keyPath':'/key'}]}}}))
    x=bootc_signature_policy_observation(p)
    assert x['status']=='DEFAULT_REJECTS_IMAGES' and x['transport_overrides_present']
    p.write_text('not json')
    assert bootc_signature_policy_observation(p)['verified'] is False
    p.unlink(); p.symlink_to('/etc/passwd')
    assert bootc_signature_policy_observation(p)['status']=='POLICY_UNAVAILABLE'
