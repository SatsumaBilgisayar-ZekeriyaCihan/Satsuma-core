"""The machine's own Satsuma key, created on this computer when Satsuma is installed (owner's decision 2026-11-11).

When the service starts for the first time (during installation) it creates
an Ed25519 key on this computer. The private key never leaves the machine and
is never shown to anyone: it is encrypted with Windows DPAPI for the SYSTEM
account, so only the service can use it, and kept in %ProgramData%\\Satsuma,
which the service locks to SYSTEM and Administrators. The public key is kept
next to it. The service signs each Satsuma setup approval (given in the panel
with the administrator password) with this key and ignores any approval whose
signature does not verify, so an approval written into the file by hand
approves nothing.

Makinenin kendi Satsuma anahtarı; Satsuma kurulurken bu bilgisayarda
oluşturulur (sahibinin kararı 2026-11-11). Hizmet ilk kez başladığında
(kurulum sırasında) bu bilgisayarda bir Ed25519 anahtarı oluşturur. Gizli
anahtar makineden çıkmaz, kimseye gösterilmez: Windows DPAPI ile SYSTEM
hesabı için şifrelenir, yalnızca hizmet kullanabilir; SYSTEM ve Yöneticilere
kilitli %ProgramData%\\Satsuma klasöründe durur. Hizmet her Satsuma kurulum
onayını (panelde yönetici parolasıyla verilir) bu anahtarla imzalar ve
imzası tutmayan onayı yok sayar; dosyaya elle yazılan onay hiçbir şeyi
onaylamaz.
"""
import base64
from pathlib import Path

PRIVATE = 'machine-key.dpapi'
PUBLIC = 'machine-key.pub'


def dpapi_protect(data):
    import win32crypt
    return win32crypt.CryptProtectData(data, 'Satsuma machine key', None, None, None, 0x1)  # no UI


def dpapi_unprotect(data):
    import win32crypt
    return win32crypt.CryptUnprotectData(data, None, None, None, 0x1)[1]


class MachineKey:
    replaced = None

    def __init__(self, private, public_bytes):
        self.private, self.public_bytes = private, public_bytes

    def sign(self, data):
        return base64.b64encode(self.private.sign(data)).decode('ascii')

    def verify(self, data, signature_text):
        return verify(self.public_bytes, data, signature_text)


def verify(public_bytes, data, signature_text):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        signature = base64.b64decode(str(signature_text), validate=True)
    except (ValueError, TypeError):
        return False
    if len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, data)
        return True
    except InvalidSignature:
        return False


def ensure(directory, protect=dpapi_protect, unprotect=dpapi_unprotect):
    """Load the machine key, creating it the first time. Returns (key, created)."""
    from cryptography.hazmat.primitives import serialization as s
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    directory = Path(directory)
    private_file, public_file = directory / PRIVATE, directory / PUBLIC
    replaced = None
    if private_file.exists():
        try:
            raw = unprotect(private_file.read_bytes())
        except Exception as exc:  # DPAPI of another account (owner's machine 2026-11-11): keep it, make a new one
            replaced = _set_aside(directory, private_file, public_file, exc)
        else:
            replaced = None
    if private_file.exists():
        private = Ed25519PrivateKey.from_private_bytes(raw)
        public = private.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
        if public_file.exists() and base64.b64decode(public_file.read_text().strip()) != public:
            raise ValueError('machine key and its public key do not match')
        return MachineKey(private, public), False
    directory.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
    public = private.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    temporary = directory / (PRIVATE + '.tmp')
    temporary.write_bytes(protect(raw))
    temporary.replace(private_file)
    public_file.write_text(base64.b64encode(public).decode('ascii') + '\n', encoding='ascii')
    key = MachineKey(private, public)
    key.replaced = replaced
    return key, True


def _set_aside(directory, private_file, public_file, error):
    """A key this account cannot open is kept beside, never deleted, and a new key is created.

    Bu hesabın açamadığı anahtar silinmez, yanına taşınır; yeni anahtar oluşturulur.
    """
    import time
    stamp = time.strftime('%Y%m%d-%H%M%S')
    kept = directory / ('unreadable-' + stamp + '-' + PRIVATE)
    private_file.replace(kept)
    if public_file.exists():
        public_file.replace(directory / ('unreadable-' + stamp + '-' + PUBLIC))
    return {'kept_as': kept.name, 'error': str(error)[:200]}
