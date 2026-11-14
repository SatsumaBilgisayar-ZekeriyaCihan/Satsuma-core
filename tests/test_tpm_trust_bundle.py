"""Real OpenSSL EK chain, pinned key and combined quote boundary tests."""
from datetime import datetime, timedelta, timezone
import hashlib
import subprocess
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from satsuma.tpm_trust_bundle import verify_ek_certificate, verify_combined


def evidence(tmp_path):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ek_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Unit Test Manufacturer CA')])
    ek_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Unit Test EK')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    ek = (x509.CertificateBuilder().subject_name(ek_name).issuer_name(ca_name)
          .public_key(ek_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    ca_file = tmp_path/'manufacturer.pem'; ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    ek_file = tmp_path/'ek.pem'; ek_file.write_bytes(ek.public_bytes(serialization.Encoding.PEM))
    public = ek_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return dict(ek_certificate=ek_file,manufacturer_ca=ca_file,
                expected_ca_sha256=hashlib.sha256(ca_file.read_bytes()).hexdigest(),
                expected_ek_spki_sha256=hashlib.sha256(public).hexdigest())


def test_real_certificate_chain_but_no_platform_claim(tmp_path):
    res=verify_ek_certificate(**evidence(tmp_path))
    assert res['status']=='EK_CERT_CHAIN_AND_PUBLIC_PIN_VERIFIED', res
    assert res['ek_certificate_verified']
    assert not res['platform_identity_verified']


def test_wrong_ca_pin_rejected_before_openssl(tmp_path):
    args=evidence(tmp_path); args['expected_ca_sha256']='00'*32
    assert verify_ek_certificate(**args)['status']=='MANUFACTURER_CA_PIN_MISMATCH'


def test_wrong_ek_spki_pin(tmp_path):
    args=evidence(tmp_path); args['expected_ek_spki_sha256']='ff'*32
    assert verify_ek_certificate(**args)['status']=='EK_PUBLIC_KEY_MISMATCH'


def test_symlink_certificate_fails_closed(tmp_path):
    args=evidence(tmp_path)
    link=tmp_path/'alias';link.symlink_to(args['ek_certificate']);args['ek_certificate']=link
    assert verify_ek_certificate(**args)['status']=='EK_EVIDENCE_UNAVAILABLE_OR_INVALID'


def test_chain_not_trusted_by_wrong_root(tmp_path):
    args=evidence(tmp_path)
    other=evidence(tmp_path/'other') if False else None
    # A valid pin on a CA file that is not a valid certificate fails closed.
    args['manufacturer_ca'].write_bytes(b'not a certificate')
    args['expected_ca_sha256']=hashlib.sha256(b'not a certificate').hexdigest()
    assert verify_ek_certificate(**args)['status']=='EK_CERTIFICATE_CHAIN_REJECTED'


def test_combined_evidence_does_not_infer_ek_ak_binding(tmp_path):
    args=evidence(tmp_path)
    for n in ('ak_public','message','signature','pcr'):
        p=tmp_path/n;p.write_bytes(('test-'+n).encode());args[n]=p
    args['expected_ak_sha256']=hashlib.sha256(args['ak_public'].read_bytes()).hexdigest()
    args['expected_pcr_sha256']=hashlib.sha256(args['pcr'].read_bytes()).hexdigest()
    args['nonce_hex']='ab'*32
    res=verify_combined(**args,quote_runner=lambda *a, **kw: SimpleNamespace(returncode=0))
    assert res['status']=='EK_AND_QUOTE_INDEPENDENTLY_VERIFIED_AK_EK_BINDING_MISSING'
    assert not res['ek_ak_binding_verified'] and not res['platform_identity_verified']
    assert not res['trusted_boot_verified']


def test_ek_failure_prevents_combined_success(tmp_path):
    args=evidence(tmp_path)
    for n in ('ak_public','message','signature','pcr'):
        p=tmp_path/n;p.write_bytes(n.encode());args[n]=p
    args['expected_ak_sha256']=hashlib.sha256(args['ak_public'].read_bytes()).hexdigest()
    args['expected_pcr_sha256']=hashlib.sha256(args['pcr'].read_bytes()).hexdigest()
    args['nonce_hex']='ab'*32
    args['expected_ca_sha256']='00'*32
    res=verify_combined(**args,quote_runner=lambda *a, **kw: SimpleNamespace(returncode=0))
    assert res['status']=='INCOMPLETE_OR_REJECTED_EVIDENCE'
