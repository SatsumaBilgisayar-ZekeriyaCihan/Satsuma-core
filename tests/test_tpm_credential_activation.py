"""Verifier-only AK/EK activation test; never opens actual TPM devices."""
import hashlib
import os
from types import SimpleNamespace
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from satsuma.tpm_credential_activation import issue_challenge, verify_activation

AK_NAME = '000b' + 'a2' * 32


def keys(tmp_path):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ek_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test CA')])
    ek_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test EK')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(10)
          .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    ek = (x509.CertificateBuilder().subject_name(ek_name).issuer_name(ca_name)
          .public_key(ek_key.public_key()).serial_number(11)
          .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    caf = tmp_path/'ca.pem'; caf.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    ekf = tmp_path/'ek.pem'; ekf.write_bytes(ek.public_bytes(serialization.Encoding.PEM))
    pub = ek_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {'ek_certificate': ekf, 'manufacturer_ca': caf,
            'expected_ca_sha256': hashlib.sha256(caf.read_bytes()).hexdigest(),
            'expected_ek_spki_sha256': hashlib.sha256(pub).hexdigest(),
            'ak_name_hex': AK_NAME,
            'expected_ak_name_sha256': hashlib.sha256(bytes.fromhex(AK_NAME)).hexdigest()}


def mock_maker(capture):
    def fake(args, **kw):
        assert '--tcti=none' in args
        assert '-n' in args and args[args.index('-n') + 1] == AK_NAME
        capture['secret'] = kw['input']
        assert len(capture['secret']) == 32
        out = args[args.index('-o') + 1]
        with open(out,'xb') as f:
            f.write(b'dummy credential encrypted blob')
        return SimpleNamespace(returncode=0)
    return fake


def prepare(tmp_path):
    e = keys(tmp_path)
    state = tmp_path/'private'
    capture = {}
    report = issue_challenge(state_dir=state, runner=mock_maker(capture), now=1000, **e)
    assert report['status']=='CHALLENGE_ISSUED', report
    assert not report['ek_ak_binding_verified']
    assert (state.stat().st_mode & 0o077)==0
    return report, state, capture


def test_successful_activation_and_no_replay(tmp_path):
    report, state, capture = prepare(tmp_path)
    response=tmp_path/'response'; response.write_bytes(capture['secret'])
    result=verify_activation(state_dir=state,challenge_id=report['challenge_id'], activated_secret=response, now=1001)
    assert result['credential_activation_verified'] and result['ek_ak_binding_verified']
    assert not result['platform_identity_verified'] and not result['trusted_boot_verified']
    assert verify_activation(state_dir=state,challenge_id=report['challenge_id'], activated_secret=response,now=1002)['status']=='CHALLENGE_ALREADY_CONSUMED'


def test_wrong_secret_consumes_challenge(tmp_path):
    report,state,capture=prepare(tmp_path)
    response=tmp_path/'response';response.write_bytes(b'Z'*32)
    kw=dict(state_dir=state,challenge_id=report['challenge_id'],activated_secret=response,now=1001)
    assert verify_activation(**kw)['status']=='ACTIVATION_SECRET_MISMATCH'
    response.write_bytes(capture['secret'])
    assert verify_activation(**kw)['status']=='CHALLENGE_ALREADY_CONSUMED'


def test_expiry(tmp_path):
    report,state,capture=prepare(tmp_path)
    response=tmp_path/'response';response.write_bytes(capture['secret'])
    assert verify_activation(state_dir=state,challenge_id=report['challenge_id'],activated_secret=response,now=1301)['status']=='CHALLENGE_EXPIRED'


def test_invalid_ak_name_reference_rejected_before_maker(tmp_path):
    e=keys(tmp_path);e['expected_ak_name_sha256']='00'*32
    r=issue_challenge(state_dir=tmp_path/'state', runner=lambda *a,**k: 1, **e)
    assert r['status']=='AK_NAME_REFERENCE_MISMATCH'


def test_invalid_ek_ca_rejected(tmp_path):
    e=keys(tmp_path);e['expected_ca_sha256']='00'*32
    r=issue_challenge(state_dir=tmp_path/'state', runner=lambda *a,**k: 1, **e)
    assert r['status']=='EK_NOT_VERIFIED'


def test_untrusted_state_dir_rejected(tmp_path):
    e=keys(tmp_path);d=tmp_path/'public';d.mkdir(mode=0o777);os.chmod(d,0o755)
    r=issue_challenge(state_dir=d, runner=mock_maker({}), **e)
    assert r['status']=='CHALLENGE_GENERATION_UNAVAILABLE'


def test_symlinked_state_dir_rejected(tmp_path):
    e=keys(tmp_path);d=tmp_path/'actual';d.mkdir();link=tmp_path/'link';link.symlink_to(d)
    r=issue_challenge(state_dir=link, runner=mock_maker({}), **e)
    assert r['status']=='CHALLENGE_GENERATION_UNAVAILABLE'


def test_invalid_challenge_identifier(tmp_path):
    r=verify_activation(state_dir=tmp_path/'state',challenge_id='../etc/passwd',activated_secret=tmp_path/'x')
    assert r['status']=='INVALID_CHALLENGE_ID'
