"""No TOFU or local-RPM-db shortcut for package trust decisions."""
import copy
import hashlib
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import pytest
from satsuma import package_trust as trust, protected_storage

FP='A'*40
POLICY={'schema':1,'repositories':{'approved':{'sources':['https://packages.example.invalid/repo'],'keys':[FP]}}}

def plan():return {'repo':'approved','nevra':'example-0:1-1.noarch','algorithm':'sha256','checksum':'1'*64,'size':10,'path':'/var/cache/example.rpm','action':'inbound'}

@pytest.mark.parametrize('source',['http://repo.invalid','file:///tmp/repo','https://u:p@repo.invalid','https://repo.invalid/#key'])
def test_repository_sources_must_be_explicit_https(source):
    policy=copy.deepcopy(POLICY);policy['repositories']['approved']['sources']=[source]
    with pytest.raises(trust.TrustDenied):trust.validate_policy(policy)

@pytest.mark.parametrize('key',['12345678','a'*40,'A'*16,'not-a-fingerprint'])
def test_full_fingerprints_are_required(key):
    policy=copy.deepcopy(POLICY);policy['repositories']['approved']['keys']=[key]
    with pytest.raises(trust.TrustDenied):trust.validate_policy(policy)

@pytest.mark.parametrize('field,value',[('repo','other'),('algorithm','sha1'),('checksum','invalid'),('size',True),('size',0),('action','downgrade')])
def test_plan_rejects_unapproved_repos_weak_digests_and_downgrades(field,value):
    package=plan();package[field]=value
    with pytest.raises(trust.TrustDenied):trust.PackageGate(POLICY).plan([package])

def test_valid_strong_plan_is_accepted_without_claiming_signature_verification():
    assert trust.PackageGate(POLICY).plan([plan()])==[plan()]

@pytest.mark.parametrize('validity,expires',[('r',''),('e',''),('d',''),('u','1')])
def test_revoked_expired_or_disabled_keys_are_rejected(validity,expires):
    row=['pub',validity,'2048','1','ABC','0',expires,'','', '']
    with pytest.raises(trust.TrustDenied):trust.fingerprints(':'.join(row)+'\nfpr:::::::::'+FP+':\n')

def test_short_ids_and_signing_subkeys_are_not_primary_fingerprint_anchors():
    text='pub:u:2048:1:short:0:0::::\nfpr:::::::::'+FP+':\nsub:u:2048:1:short:0:0::::\nfpr:::::::::'+'B'*40+':\n'
    assert trust.fingerprints(text)==[FP]
    with pytest.raises(trust.TrustDenied):trust.fingerprints('sec:u:2048:1:short:0:0::::\n')

@pytest.fixture
def protected_files(tmp_path,monkeypatch):
    real_fstat=os.fstat
    def owned(fd):
        parts=list(real_fstat(fd));parts[4]=0;return os.stat_result(parts)
    monkeypatch.setattr(os,'fstat',owned)
    monkeypatch.setattr(protected_storage,'open_directory',lambda path:os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
    return tmp_path

@pytest.mark.parametrize('kind',['symlink','hardlink','writable'])
def test_trust_input_rejects_unsafe_paths(protected_files,kind):
    root=protected_files;path=root/'policy';path.write_bytes(b'{}');path.chmod(0o600)
    if kind=='symlink':link=root/'link';link.symlink_to(path);path=link
    elif kind=='hardlink':os.link(path,root/'second')
    else:path.chmod(0o666)
    with pytest.raises((trust.TrustDenied,OSError)):trust.secure_read(path)


def test_digest_only_output_does_not_count_as_package_signature(protected_files,monkeypatch):
    root=protected_files;package=root/'package.rpm';package.write_bytes(b'unsigned');package.chmod(0o600)
    p=plan();p.update(path=str(package),size=8,checksum=hashlib.sha256(b'unsigned').hexdigest())
    gate=trust.PackageGate(POLICY,work=root,runner=lambda *a,**kw:SimpleNamespace(returncode=0,stdout='digests OK\n',stderr=''))
    monkeypatch.setattr(gate,'key_material',lambda _:[(FP,b'fixture')])
    with pytest.raises(trust.TrustDenied,match='actual approved RPM signature'):gate.verify_downloaded([p])


def test_replaced_download_fails_before_the_signature_tool(protected_files,monkeypatch):
    root=protected_files;package=root/'package.rpm';package.write_bytes(b'tampered');package.chmod(0o600)
    p=plan();p.update(path=str(package),size=8)
    calls=[]
    gate=trust.PackageGate(POLICY,work=root,runner=lambda args,**kw:calls.append(args) or SimpleNamespace(returncode=0,stdout='',stderr=''))
    monkeypatch.setattr(gate,'key_material',lambda _:[(FP,b'fixture')])
    with pytest.raises(trust.TrustDenied,match='checksum mismatch'):gate.verify_downloaded([p])
    assert not any('--checksig' in command for command in calls)


def test_duplicate_trust_json_keys_are_not_allowed():
    with pytest.raises(trust.TrustDenied):trust.parse_json('{"schema":1,"schema":1}')


def test_policy_must_have_a_valid_hmac_and_cannot_be_changed_silently(protected_files,monkeypatch):
    from installer import integrity
    root=protected_files;path=root/'policy.json';path.write_text(__import__('json').dumps(POLICY))
    key=root/'manifest.key';key.write_bytes(b'k'*32);key.chmod(0o600)
    monkeypatch.setattr(integrity,'KEY',key)
    integrity.sign(path,b'k'*32)
    assert trust.load_policy(path)==POLICY
    path.write_text('{"schema":1,"repositories":{}}')
    with pytest.raises(trust.TrustDenied,match='signature mismatch'):trust.load_policy(path)


def test_unsigned_existing_nonempty_policy_is_not_automatically_adopted(protected_files):
    path=protected_files/'policy.json';path.write_text(__import__('json').dumps(POLICY))
    with pytest.raises(trust.TrustDenied,match='must not be adopted'):trust.initialize_policy(path)
