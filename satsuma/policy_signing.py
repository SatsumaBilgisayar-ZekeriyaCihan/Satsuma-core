"""Signed policy (faz 2, owner 2026-11-19: "Satsuma'nın düzenlenebilir bir JSON'dan görev alması
kabul edilemez").

/etc/satsuma-core/policy.json is taken only with a valid Ed25519 signature in policy.json.sig made
by the owner's key. The private key never exists unencrypted on disk: it is encrypted with a key
derived from the Satsuma admin password (scrypt), so signing needs the password
(``satsuma-admin politika imzala``). The public key is kept twice: /etc/satsuma-core/policy-signing.pub
(readable by every Satsuma process) and pinned in root-only storage; for root processes the two must
agree, so swapping the public key in /etc alone is refused too.

A policy without a valid signature is not used: Satsuma keeps the last signed policy and raises a
critical finding. Before a key exists (first install) the policy is taken with a high finding until
the owner creates the key.

What it does not stop: an attacker who is already root and also rewrites Satsuma's root-only
storage. It stops edits by anyone else, edits by a root process that only touches /etc, and
accidental edits.

İmzasız ya da imzası geçersiz politika kullanılmaz; son imzalı politika sürer ve kritik bulgu açılır.
"""
import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

from . import ed25519

SIGNATURE_SUFFIX = '.sig'
PUBLIC_PATH = Path('/etc/satsuma-core/policy-signing.pub')
KEY_RECORD = 'configuration/policy-signing-key.json'
SCRYPT = {'n': 2 ** 15, 'r': 8, 'p': 1, 'maxmem': 64 * 1024 * 1024}
CONTEXT = b'satsuma-policy-signing-v1'


class SignatureError(ValueError):
    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _kdf(password, salt):
    key = hashlib.scrypt(password.encode('utf-8'), salt=salt, dklen=64, **SCRYPT)
    return key[:32], key[32:]


def _stream(key, nonce):
    return hashlib.shake_256(CONTEXT + key + nonce).digest(32)


def encrypt_secret(secret, password):
    salt, nonce = os.urandom(16), os.urandom(16)
    k_enc, k_mac = _kdf(password, salt)
    sealed = bytes(a ^ b for a, b in zip(secret, _stream(k_enc, nonce)))
    tag = hmac.new(k_mac, CONTEXT + salt + nonce + sealed, hashlib.sha256).digest()
    return {'kdf': 'scrypt', 'scrypt': {k: v for k, v in SCRYPT.items() if k != 'maxmem'},
            'salt': salt.hex(), 'nonce': nonce.hex(), 'sealed': sealed.hex(), 'tag': tag.hex()}


def decrypt_secret(record, password):
    salt, nonce = bytes.fromhex(record['salt']), bytes.fromhex(record['nonce'])
    sealed, tag = bytes.fromhex(record['sealed']), bytes.fromhex(record['tag'])
    k_enc, k_mac = _kdf(password, salt)
    expected = hmac.new(k_mac, CONTEXT + salt + nonce + sealed, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise SignatureError('POLICY_KEY_LOCKED', 'parola anahtarı açmadı')
    return bytes(a ^ b for a, b in zip(sealed, _stream(k_enc, nonce)))


def fingerprint(public):
    return hashlib.sha256(public).hexdigest()


def _store():
    from .protected_storage import RootDataStore
    return RootDataStore(KEY_RECORD)


def pinned():
    """The pinned key record; None when no key exists yet or this process is not root.

    A record that exists but cannot be read safely (wrong owner/mode, a link, broken JSON) is not
    treated as "no key": that would let an attacker unpin the key by damaging the file.
    """
    if os.geteuid() != 0:
        return None
    try:
        record = _store().read()
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise SignatureError('POLICY_KEY_INVALID', 'sabitlenmiş anahtar kaydı okunamadı: ' + str(exc)[:200]) from exc
    if not isinstance(record, dict) or not record.get('public'):
        raise SignatureError('POLICY_KEY_INVALID', 'sabitlenmiş anahtar kaydı bozuk')
    return record


def read_public(path=PUBLIC_PATH):
    try:
        text = Path(path).read_text(encoding='ascii').strip()
    except FileNotFoundError:
        return None
    raw = base64.b64decode(text, validate=True)
    if len(raw) != 32:
        raise SignatureError('POLICY_KEY_INVALID', 'açık anahtar 32 bayt değil')
    return raw


def enrolled(public_path=PUBLIC_PATH):
    return Path(public_path).exists() or pinned() is not None


_UNSET = object()


def check(raw, policy_path, public_path=PUBLIC_PATH, pin=_UNSET):
    """Raise SignatureError unless ``raw`` (the exact bytes read) carries a valid signature.

    Returns 'signed' or 'no_key' (no key enrolled yet).
    """
    root_view = pin is not _UNSET or os.geteuid() == 0
    pin = pinned() if pin is _UNSET else pin
    public = read_public(public_path)
    if public is None and pin is None:
        return 'no_key'
    if public is not None and pin is None and root_view:
        # A public key in /etc that root storage never pinned: put there by someone else.
        raise SignatureError('POLICY_KEY_SWAPPED', '/etc içindeki açık anahtar Satsuma tarafından sabitlenmemiş')
    if pin is not None:
        pinned_public = bytes.fromhex(pin['public'])
        if public is not None and public != pinned_public:
            raise SignatureError('POLICY_KEY_SWAPPED', '/etc içindeki açık anahtar sabitlenen anahtarla uyuşmuyor')
        public = pinned_public
    sig_path = Path(str(policy_path) + SIGNATURE_SUFFIX)
    try:
        signature = base64.b64decode(sig_path.read_text(encoding='ascii').strip(), validate=True)
    except FileNotFoundError:
        raise SignatureError('POLICY_UNSIGNED', 'politika imzasız: ' + str(sig_path) + ' yok') from None
    except (ValueError, UnicodeDecodeError):
        raise SignatureError('POLICY_SIGNATURE_INVALID', 'imza dosyası okunamadı') from None
    if not ed25519.verify(public, raw, signature):
        raise SignatureError('POLICY_SIGNATURE_INVALID', 'politika imzası geçersiz (dosya imzadan sonra değişmiş)')
    return 'signed'


def _write_public(public, path):
    path = Path(path)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(base64.b64encode(public).decode() + '\n', encoding='ascii')
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def create_key(password, public_path=PUBLIC_PATH, store=None):
    secret = os.urandom(32)
    public = ed25519.public_key(secret)
    record = {'created_at': time.time(), 'public': public.hex(), 'fingerprint': fingerprint(public),
              'secret': encrypt_secret(secret, password)}
    (store or _store()).replace(record)
    _write_public(public, public_path)
    return record


def sign_file(policy_path, password, record=None):
    record = record or pinned()
    if record is None:
        raise SignatureError('POLICY_NO_KEY', 'imza anahtarı yok: önce "satsuma-admin politika anahtar-olustur"')
    secret = decrypt_secret(record['secret'], password)
    if ed25519.public_key(secret) != bytes.fromhex(record['public']):
        raise SignatureError('POLICY_KEY_INVALID', 'anahtar kaydı bozuk')
    raw = Path(policy_path).read_bytes()
    signature = ed25519.sign(secret, raw)
    sig_path = Path(str(policy_path) + SIGNATURE_SUFFIX)
    tmp = sig_path.with_name(sig_path.name + '.tmp')
    tmp.write_text(base64.b64encode(signature).decode() + '\n', encoding='ascii')
    os.chmod(tmp, 0o644)
    os.replace(tmp, sig_path)
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'signature': str(sig_path)}


def load_signed_json(path, read_bytes):
    """Read the policy bytes once, check the signature on exactly those bytes, then parse them."""
    raw = read_bytes(path)
    state = check(raw, path)
    return json.loads(raw.decode('utf-8')), state
