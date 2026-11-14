import hashlib
from types import SimpleNamespace
from satsuma.cve_verification import (parse_installed, parse_cve_advisories,
                                       collect_cve_evidence, CVE_COMMAND, RPM_COMMAND)
from satsuma.trust_verification import verify_fedora_iso, ostree_signature_observation, OSTREE_COMMAND


def test_cve_fix_is_newer_than_installed_evr():
    pkgs = parse_installed('python3-pip\t0\t24.0\t1.fc42\tnoarch\n')
    doc = '[{"advisory_name":"FEDORA-2026-abcd","advisory_type":"security","nevra":"python3-pip-0:25.0-1.fc42.noarch","advisory_severity":"Important","references":[{"reference_type":"cve","reference_id":"CVE-2026-12345"}]}]'
    assert parse_cve_advisories(doc, pkgs, lambda a,b: -1)[0]['applicability'] == 'FIX_PENDING_INSTALLED_OLDER'
    assert parse_cve_advisories(doc, pkgs, lambda a,b: 1)[0]['applicability'] == 'NOT_OLDER_THAN_FIX'
    assert parse_cve_advisories(doc, pkgs, lambda a,b: None)[0]['applicability'] == 'MIXED_OR_UNKNOWN'


def test_invalid_cve_schema_cannot_create_findings():
    pkgs = parse_installed('foo\t0\t1\t2\tx86_64\n')
    doc = '[{"advisory_name":"FEDORA-2026-abcd","advisory_type":"security","nevra":"foo-0:2-1.x86_64","references":[{"reference_type":"cve","reference_id":"CVE-2026-bad"}]}]'
    assert parse_cve_advisories(doc, pkgs, lambda a,b: -1) == []


def test_collect_is_readonly_cacheonly():
    def runner(argv, **kw):
        assert argv in (CVE_COMMAND, RPM_COMMAND)
        assert kw['timeout']==8 and kw['check'] is False
        return SimpleNamespace(returncode=0, stdout='[]' if argv==CVE_COMMAND else '')
    assert collect_cve_evidence(runner=runner, compare=lambda a,b: -1)['status']=='LOCAL_VERSION_COMPARED'


def test_iso_requires_independent_fingerprint(tmp_path):
    p=tmp_path/'image.iso'; p.write_bytes(b'image')
    c=tmp_path/'CHECKSUM'; c.write_text('signed')
    k=tmp_path/'keyring'; k.write_bytes(b'key')
    assert verify_fedora_iso(p,c,k,'UNKNOWN')['status']=='INVALID_TRUST_ANCHOR'


def test_iso_offline_signed_manifest_and_hash(tmp_path):
    p=tmp_path/'Fedora.iso'; p.write_bytes(b'Fedora image example')
    c=tmp_path/'Fedora-CHECKSUM'; c.write_text('placeholder')
    k=tmp_path/'fedora.gpg'; k.write_text('placeholder')
    fpr='A'*40
    contents='SHA256 (Fedora.iso) = '+hashlib.sha256(p.read_bytes()).hexdigest()+'\n'
    def runner(argv, **kw):
        assert argv[0]=='/usr/bin/gpgv' and '--keyring' in argv
        return SimpleNamespace(returncode=0,stdout=contents.encode(),stderr=('[GNUPG:] VALIDSIG '+fpr+' 2026 0 0 0 0 0 0\n').encode())
    assert verify_fedora_iso(p,c,k,fpr,runner=runner)['status']=='VERIFIED_OFFLINE_IMAGE'
    p.write_bytes(b'altered')
    assert verify_fedora_iso(p,c,k,fpr,runner=runner)['status']=='IMAGE_HASH_MISMATCH'
    assert verify_fedora_iso(p,c,k,'B'*40,runner=runner)['status']=='UNTRUSTED_SIGNER'


def test_ostree_report_cannot_be_misread_as_attestation():
    def runner(argv, **kw):
        assert argv==OSTREE_COMMAND
        return SimpleNamespace(returncode=0,stdout='* deployment\n')
    r=ostree_signature_observation(runner=runner)
    assert r['verified'] is False
