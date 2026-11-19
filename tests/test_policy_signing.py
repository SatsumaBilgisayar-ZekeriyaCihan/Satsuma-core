"""Faz 2: the policy is used only with the owner's signature."""
import base64
import importlib.util
import json
from pathlib import Path

import pytest

from satsuma import ed25519, policy_signing as ps

ROOT = Path(__file__).resolve().parents[1]


class Store:
    def __init__(self):
        self.value = None

    def replace(self, record):
        self.value = record

    def read(self):
        return self.value


def test_rfc8032_vector():
    sk = bytes.fromhex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb')
    sig = ed25519.sign(sk, b'\x72')
    assert ed25519.public_key(sk).hex() == '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'
    assert sig.hex().startswith('92a009a9f0d4cab8720e820b5f642540')
    assert ed25519.verify(ed25519.public_key(sk), b'\x72', sig) and not ed25519.verify(ed25519.public_key(sk), b'\x73', sig)


def test_private_key_needs_the_password():
    record = ps.encrypt_secret(b'k' * 32, 'dogru-parola')
    assert ps.decrypt_secret(record, 'dogru-parola') == b'k' * 32
    with pytest.raises(ps.SignatureError):
        ps.decrypt_secret(record, 'yanlis')
    assert 'k' * 32 not in json.dumps(record)


def test_signed_policy_is_taken_and_any_change_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(ps, 'SCRYPT', {'n': 2 ** 10, 'r': 8, 'p': 1, 'maxmem': 64 * 1024 * 1024})
    pub, policy, store = tmp_path / 'policy-signing.pub', tmp_path / 'policy.json', Store()
    policy.write_bytes(b'{"revision": 1}')
    assert ps.check(policy.read_bytes(), policy, pub, pin=None) == 'no_key'
    record = ps.create_key('parola', pub, store)
    ps.sign_file(policy, 'parola', record)
    assert ps.check(policy.read_bytes(), policy, pub, pin=record) == 'signed'
    policy.write_bytes(b'{"revision": 2}')
    with pytest.raises(ps.SignatureError) as changed:
        ps.check(policy.read_bytes(), policy, pub, pin=record)
    assert changed.value.code == 'POLICY_SIGNATURE_INVALID'
    Path(str(policy) + '.sig').unlink()
    with pytest.raises(ps.SignatureError) as unsigned:
        ps.check(policy.read_bytes(), policy, pub, pin=record)
    assert unsigned.value.code == 'POLICY_UNSIGNED'
    with pytest.raises(ps.SignatureError):
        ps.sign_file(policy, 'yanlis', record)


def test_swapping_the_public_key_in_etc_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(ps, 'SCRYPT', {'n': 2 ** 10, 'r': 8, 'p': 1, 'maxmem': 64 * 1024 * 1024})
    pub, policy = tmp_path / 'policy-signing.pub', tmp_path / 'policy.json'
    policy.write_bytes(b'{"revision": 3}')
    owner = ps.create_key('parola', pub, Store())
    attacker_secret = b'a' * 32
    pub.write_text(base64.b64encode(ed25519.public_key(attacker_secret)).decode())
    Path(str(policy) + '.sig').write_text(base64.b64encode(ed25519.sign(attacker_secret, policy.read_bytes())).decode())
    with pytest.raises(ps.SignatureError) as swapped:
        ps.check(policy.read_bytes(), policy, pub, pin=owner)
    assert swapped.value.code == 'POLICY_KEY_SWAPPED'


def _teams():
    spec = importlib.util.spec_from_file_location('teams_for_sig', ROOT / 'run_satsuma_teams.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_unsigned_policy_raises_a_finding(monkeypatch):
    teams = _teams()
    recorded = []
    monkeypatch.setattr('satsuma.finding_store.record_finding', lambda store, f, src: recorded.append(f))

    class Mem:
        def __init__(self): self.d = {}
        def get(self, k, default=None): return self.d.get(k, default)
        def set(self, k, v): self.d[k] = v
    store = Mem()
    rejected = {'status': 'last_valid', 'rejected_code': 'POLICY_SIGNATURE_INVALID', 'error': 'x'}
    assert teams._policy_signature(store, rejected, now=10_000) == 'SATSUMA-POLICY-SIG-002'
    assert recorded[-1]['severity'] == 'critical'
    assert teams._policy_signature(store, rejected, now=10_100) is None          # hourly
    assert teams._policy_signature(store, {'status': 'validated', 'signature': 'no_key'}, now=20_000) == 'SATSUMA-POLICY-SIG-001'
    assert teams._policy_signature(store, {'status': 'validated', 'signature': 'signed'}, now=30_000) is None


def test_a_public_key_nobody_pinned_is_refused(tmp_path):
    pub, policy = tmp_path / 'policy-signing.pub', tmp_path / 'policy.json'
    policy.write_bytes(b'{}')
    secret = b'b' * 32
    pub.write_text(base64.b64encode(ed25519.public_key(secret)).decode())
    Path(str(policy) + '.sig').write_text(base64.b64encode(ed25519.sign(secret, b'{}')).decode())
    with pytest.raises(ps.SignatureError) as planted:
        ps.check(b'{}', policy, pub, pin=None)
    assert planted.value.code == 'POLICY_KEY_SWAPPED'
