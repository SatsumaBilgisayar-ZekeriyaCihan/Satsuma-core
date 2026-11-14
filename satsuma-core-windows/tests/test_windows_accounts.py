"""Only the owner's account may log on; every other local account is denied by policy (owner's decision 2026-11-11).

Yalnızca sahibin hesabı oturum açabilir; diğer bütün yerel hesaplar ilkeyle reddedilir.
"""
import json
from types import SimpleNamespace

from satsuma_win import accounts, firewall, memory, service

OWNER = 'S-1-5-21-111-222-333-1002'
GUEST = 'S-1-5-21-111-222-333-501'
DEFAULTUSER = 'S-1-5-21-111-222-333-1000'
ADMIN = 'S-1-5-21-111-222-333-500'
USERS = [{'name': 'SatsumaBilgisayar', 'sid': OWNER, 'enabled': True},
         {'name': 'Guest', 'sid': GUEST, 'enabled': False},
         {'name': 'defaultuser0', 'sid': DEFAULTUSER, 'enabled': True},
         {'name': 'Administrator', 'sid': ADMIN, 'enabled': False}]
EXPORT = ('[Unicode]\r\nUnicode=yes\r\n[Privilege Rights]\r\nSeDenyNetworkLogonRight = *S-1-5-32-546\r\n'
          'SeServiceLogonRight = *S-1-5-80-0\r\n')


class Key:
    def sign(self, data):
        return 'S' + data.hex()

    def verify(self, data, signature):
        return signature == 'S' + data.hex()


class Machine:
    def __init__(self, users=USERS, applies=True):
        self.users, self.applies, self.rights = [dict(u) for u in users], applies, accounts.parse_rights(EXPORT)
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0] == 'secedit.exe' and argv[1] == '/export':
            # Like Windows: local accounts are exported by name, others by SID.
            names = {'*' + u['sid']: u['name'] for u in self.users}
            text = '[Privilege Rights]\r\n' + ''.join(
                f'{r} = {",".join(names.get(e, e) for e in v)}\r\n' for r, v in self.rights.items())
            open(argv[-1], 'wb').write(text.encode('utf-16'))
        elif argv[0] == 'secedit.exe' and argv[1] == '/configure':
            written = accounts.by_sid(accounts.parse_rights(
                open(argv[argv.index('/cfg') + 1], 'rb').read().decode('utf-16')), self.users)
            if self.applies:
                self.rights.update(written)
        elif argv[:-1] == firewall.POWERSHELL:
            if 'Get-LocalUser' in argv[-1]:
                return SimpleNamespace(returncode=0, stdout=json.dumps(self.users), stderr='')
            if 'Disable-LocalUser' in argv[-1]:
                name = argv[-1].split("'")[1]
                for user in self.users:
                    if user['name'] == name:
                        user['enabled'] = False
        return SimpleNamespace(returncode=0, stdout='', stderr='')


def guard(tmp_path, machine, owner=OWNER):
    if owner:
        accounts.approve_owner(tmp_path, owner, Key())
    return accounts.Accounts(tmp_path, Key(), machine)


def test_every_other_account_is_denied_and_the_owner_never(tmp_path):
    machine = Machine()
    result = guard(tmp_path, machine).enforce()
    assert result['ok'] and result['status'] == 'WRITTEN'
    for right in accounts.RIGHTS:
        entries = machine.rights[right]
        assert {'*' + GUEST, '*' + DEFAULTUSER, '*' + ADMIN} <= set(entries)
        assert ('*' + OWNER in entries) is (right in accounts.OWNER_DENIED), right
    assert '*' + OWNER not in machine.rights['SeDenyInteractiveLogonRight'], 'the owner always logs on at the desk'
    assert '*S-1-5-32-546' in machine.rights['SeDenyNetworkLogonRight'], 'existing entries are kept'
    assert machine.rights['SeServiceLogonRight'] == ['*S-1-5-80-0'], 'service rights are never touched'
    assert result['disabled'] == ['defaultuser0']


def test_a_second_check_finds_it_locked_and_a_new_account_is_added(tmp_path):
    machine = Machine()
    g = guard(tmp_path, machine)
    g.enforce()
    assert g.enforce()['status'] == 'LOCKED'
    machine.users.append({'name': 'helper', 'sid': 'S-1-5-21-111-222-333-1005', 'enabled': True})
    result = g.enforce()
    assert result['status'] == 'WRITTEN' and '*S-1-5-21-111-222-333-1005' in machine.rights['SeDenyInteractiveLogonRight']


def test_without_a_signed_owner_or_with_an_unknown_owner_nothing_is_denied(tmp_path):
    machine = Machine()
    assert guard(tmp_path, machine, owner=None).enforce()['status'] == 'NO_SIGNED_OWNER'
    (tmp_path / accounts.OWNER).write_text(json.dumps({'sid': OWNER, 'signature': 'forged'}))
    assert accounts.Accounts(tmp_path, Key(), machine).enforce()['status'] == 'NO_SIGNED_OWNER'
    assert guard(tmp_path, machine, owner='S-1-5-21-9-9-9-1001').enforce()['status'] == 'OWNER_NOT_FOUND'
    assert not any(c[:2] == ['secedit.exe', '/configure'] for c in machine.calls)


def test_the_owner_is_removed_from_deny_lists_never_added(tmp_path):
    machine = Machine()
    machine.rights['SeDenyInteractiveLogonRight'] = ['*' + OWNER]
    machine.rights['SeDenyBatchLogonRight'] = ['*' + OWNER]
    guard(tmp_path, machine).enforce()
    assert '*' + OWNER not in machine.rights['SeDenyInteractiveLogonRight']
    assert '*' + OWNER not in machine.rights['SeDenyBatchLogonRight']


def test_a_policy_that_does_not_read_back_is_reported(tmp_path):
    result = guard(tmp_path, Machine(applies=False)).enforce()
    assert result['ok'] is False and result['status'] == 'NOT_APPLIED' and result['still_missing']


def test_uninstall_restores_the_rights_as_they_were(tmp_path):
    machine = Machine()
    g = guard(tmp_path, machine)
    g.enforce()
    assert g.restore()['status'] == 'RESTORED'
    assert machine.rights['SeDenyNetworkLogonRight'] == ['*S-1-5-32-546']
    assert machine.rights['SeDenyInteractiveLogonRight'] == []


def test_the_installing_account_becomes_the_signed_owner_on_the_first_start(tmp_path):
    run = lambda argv, **kw: SimpleNamespace(returncode=0, stdout=f'"PC\\\\SatsumaBilgisayar","{OWNER}"\r\n', stderr='')
    assert service.current_user_sid(run) == OWNER
    service.write_install_approvals(tmp_path, owner=OWNER)
    done = memory.apply_install_approvals(tmp_path, Key(), created=True)
    assert done['owner'] == OWNER and accounts.load_owner(tmp_path, Key()) == OWNER


def test_names_in_the_export_are_read_as_sids():
    rights = {'SeDenyNetworkLogonRight': ['Guest', 'PC\\SatsumaBilgisayar', '*S-1-5-32-546', 'UnknownName']}
    assert accounts.by_sid(rights, USERS)['SeDenyNetworkLogonRight'] == [
        '*' + GUEST, '*' + OWNER, '*S-1-5-32-546', 'UnknownName']
