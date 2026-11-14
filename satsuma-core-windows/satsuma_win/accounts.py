"""Only the owner's account may log on: every other local account is denied by local security policy.

Owner's decision 2026-11-11 ("kullanılan oturum dışındaki hesapların
girişini policy ile kapatsın"). The account that installs Satsuma is the
owner; it is recorded at installation and signed with the machine key, and
it is never denied. Every other local user account (Guest, defaultuser0,
the built-in Administrator and any account created later) is put into the
deny rights of the local security policy: log on locally, from the network,
through Remote Desktop and as a batch job. Guest and defaultuser0 are also
disabled. Windows' own service accounts (SYSTEM, LOCAL SERVICE, NETWORK
SERVICE) are not local user accounts and are never touched: Windows needs
them. The policy is applied with secedit and read back; the service checks
every minute and writes it back when a new account appears or an entry was
removed. Existing deny entries are kept; uninstall restores the rights as
they were before installation. Without a signed owner nothing is denied, so
a damaged record can never lock the owner out.

Owner's decision 2026-11-11 ("yerel ağında rdp gibi uzak erişimi kısıtla"):
the owner's own account is denied Remote Desktop and network logon as well,
so nobody can log on to this machine from the network even if the firewall
is opened; outgoing remote support and other machines' shares still work.

Yalnızca sahibin hesabı oturum açabilir: diğer bütün yerel hesaplar yerel
güvenlik ilkesiyle reddedilir (sahibinin kararı 2026-11-11). Satsuma'yı
kuran hesap sahiptir; kurulumda kaydedilir, makine anahtarıyla imzalanır ve
asla reddedilmez. Diğer her yerel kullanıcı hesabı (Guest, defaultuser0,
yerleşik Administrator ve sonradan oluşturulan her hesap) yerel, ağdan, Uzak
Masaüstü ile ve toplu iş olarak oturum açma ret haklarına konur; Guest ve
defaultuser0 ayrıca kapatılır. Windows'un hizmet hesaplarına (SYSTEM, LOCAL
SERVICE, NETWORK SERVICE) asla dokunulmaz. İlke secedit ile uygulanır ve geri
okunur; hizmet dakikada bir denetler, yeni hesap çıkarsa ya da bir kayıt
silinirse geri yazar. Var olan ret kayıtları korunur; kaldırma, hakları
kurulumdan önceki haline döndürür. İmzalı sahip yoksa hiçbir şey reddedilmez;
bozuk bir kayıt sahibi asla dışarıda bırakamaz. Sahibinin kararı
2026-11-11: sahibin kendi hesabı da Uzak Masaüstü ve ağ oturumundan
reddedilir; güvenlik duvarı açılsa bile kimse ağdan bu makineye oturum
açamaz; dışarıya uzak destek ve başka makinelerin paylaşımları çalışır.
"""
import json
import re
import subprocess
from pathlib import Path

from .firewall import FirewallError, run_powershell, safe_run

RIGHTS = ('SeDenyInteractiveLogonRight', 'SeDenyNetworkLogonRight', 'SeDenyRemoteInteractiveLogonRight',
          'SeDenyBatchLogonRight')
DISABLE = ('Guest', 'defaultuser0')
# The owner too: nobody logs on to this machine from the network. Sahip de: ağdan kimse oturum açamaz.
OWNER_DENIED = ('SeDenyNetworkLogonRight', 'SeDenyRemoteInteractiveLogonRight')
OWNER = 'approved-owner.json'
ORIGINAL = 'original-logon-rights.json'
USER_SID = re.compile(r'^S-1-5-21-\d+-\d+-\d+-\d+$')

ACCOUNTS_SCRIPT = ("@(Get-LocalUser | ForEach-Object { @{name=[string]$_.Name; sid=[string]$_.SID.Value; "
                   "enabled=[bool]$_.Enabled} }) | ConvertTo-Json -Compress")


def _owner_text(sid):
    return ('satsuma-approved-owner:' + sid).encode('ascii')


def approve_owner(directory, sid, key):
    if not USER_SID.match(str(sid)):
        raise ValueError('not a local user account SID: ' + str(sid))
    path = Path(directory) / OWNER
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps({'sid': sid, 'signature': key.sign(_owner_text(sid))}), encoding='utf-8')
    temporary.replace(path)
    return sid


def load_owner(directory, key):
    try:
        row = json.loads((Path(directory) / OWNER).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    sid = str(row.get('sid', ''))
    if key is None or not USER_SID.match(sid) or not key.verify(_owner_text(sid), row.get('signature', '')):
        return None
    return sid


def parse_rights(text):
    """{right: [entries]} from a secedit export ([Privilege Rights] section)."""
    rights, section = {}, None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('['):
            section = line
            continue
        if section == '[Privilege Rights]' and '=' in line:
            name, _, value = line.partition('=')
            rights[name.strip()] = [v.strip() for v in value.split(',') if v.strip()]
    return rights


def by_sid(rights, accounts):
    """secedit exports local accounts by name ("Guest"); turn every known name into "*SID".

    secedit yerel hesapları adla yazar; bilinen her ad "*SID" yapılır.
    """
    names = {str(a.get('name', '')).lower(): a.get('sid') for a in accounts}
    result = {}
    for right, entries in rights.items():
        converted = []
        for entry in entries:
            sid = names.get(entry.split('\\')[-1].lower()) if not entry.startswith('*') else None
            converted.append('*' + sid if sid else entry)
        result[right] = converted
    return result


def wanted(owner, accounts, current):
    """The deny rights to write: existing entries plus every local account but the owner. None: nothing to deny."""
    if not owner:
        return None
    others = sorted('*' + a['sid'] for a in accounts if USER_SID.match(a.get('sid', '')) and a['sid'] != owner)
    result = {}
    for right in RIGHTS:
        if right in OWNER_DENIED:
            result[right] = sorted(set(current.get(right, [])) | set(others) | {'*' + owner})
            continue
        kept = [e for e in current.get(right, []) if e.lstrip('*') != owner]
        result[right] = sorted(set(kept) | set(others))
    return result


def missing(target, current):
    return {right: sorted(set(entries) - set(current.get(right, []))) for right, entries in target.items()
            if set(entries) - set(current.get(right, []))}


def inf(rights):
    lines = ['[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]']
    lines += [f'{right} = {",".join(entries)}' if entries else f'{right} =' for right, entries in rights.items()]
    return '\r\n'.join(lines) + '\r\n'


class Accounts:
    def __init__(self, directory, key, runner=safe_run, record=None):
        self.directory, self.key, self.runner = Path(directory), key, runner
        self.record = record or (lambda kind, **f: f)

    def _secedit(self, *args):
        result = self.runner(['secedit.exe', *args], capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise FirewallError(('secedit ' + ' '.join(args[:1]) + ': ' + (result.stdout or result.stderr or ''))[:300])

    def current(self):
        out = self.directory / 'logon-rights-export.inf'
        self._secedit('/export', '/areas', 'USER_RIGHTS', '/cfg', str(out))
        try:
            return parse_rights(out.read_bytes().decode('utf-16', errors='replace'))
        finally:
            out.unlink(missing_ok=True)

    def write(self, rights):
        cfg, db = self.directory / 'logon-rights.inf', self.directory / 'logon-rights.sdb'
        cfg.write_text(inf(rights), encoding='utf-16')
        try:
            self._secedit('/configure', '/db', str(db), '/cfg', str(cfg), '/areas', 'USER_RIGHTS', '/quiet')
        finally:
            cfg.unlink(missing_ok=True)
            db.unlink(missing_ok=True)

    def accounts(self):
        rows = json.loads(run_powershell(ACCOUNTS_SCRIPT, self.runner) or '[]')
        return rows if isinstance(rows, list) else [rows]

    def disable_unused(self, accounts, owner):
        done = []
        for account in accounts:
            if account['name'] in DISABLE and account.get('enabled') and account.get('sid') != owner:
                quoted = "'" + account['name'].replace("'", "''") + "'"
                run_powershell('Disable-LocalUser -Name ' + quoted, self.runner)
                done.append(account['name'])
        return done

    def enforce(self):
        """Apply and read back; returns the state for the record."""
        owner = load_owner(self.directory, self.key)
        if owner is None:
            return {'ok': False, 'status': 'NO_SIGNED_OWNER'}
        accounts = self.accounts()
        if owner not in {a.get('sid') for a in accounts}:
            return {'ok': False, 'status': 'OWNER_NOT_FOUND', 'owner': owner}
        current = by_sid(self.current(), accounts)
        original = self.directory / ORIGINAL
        if not original.exists():
            original.write_text(json.dumps({r: current.get(r, []) for r in RIGHTS}), encoding='utf-8')
        target = wanted(owner, accounts, current)
        gaps = missing(target, current)
        disabled = self.disable_unused(accounts, owner)
        if gaps:
            self.write(target)
            after = by_sid(self.current(), accounts)
            gaps_after = missing(target, after)
            return {'ok': not gaps_after, 'status': 'WRITTEN' if not gaps_after else 'NOT_APPLIED', 'owner': owner,
                    'added': gaps, 'still_missing': gaps_after, 'disabled': disabled}
        return {'ok': True, 'status': 'LOCKED', 'owner': owner, 'disabled': disabled}

    def restore(self):
        """At uninstall: the deny rights exactly as before installation."""
        try:
            original = json.loads((self.directory / ORIGINAL).read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return {'ok': True, 'status': 'NOTHING_TO_RESTORE'}
        self.write({right: original.get(right, []) for right in RIGHTS})
        return {'ok': True, 'status': 'RESTORED'}
