from pathlib import Path
from types import SimpleNamespace

from satsuma.boot_chain_audit import collect, decode_efi_bool, PCRLOCK_COMMAND

GUID = '8be4df61-93ca-11d2-aa0d-00e098032b8c'


def _efi(root, name, val):
    (root / (name+'-'+GUID)).write_bytes(b'\x07\x00\x00\x00'+bytes([val]))


def test_efi_flag_strict():
    assert decode_efi_bool(b'1234\x01') is True
    assert decode_efi_bool(b'1234\x00') is False
    for b in (b'\x01', b'1234\x02', b'1234\x011', b''):
        assert decode_efi_bool(b) is None


def test_missing_uefi_tpm_is_not_verified(tmp_path):
    r=collect(efivar_root=tmp_path/'absent', tpm_root=tmp_path/'missing')
    assert r['secure_boot']['status']=='UEFI_NOT_OBSERVED'
    assert r['tpm']['status']=='UNAVAILABLE'
    assert r['verified'] is False


def test_secure_boot_enabled_with_setup_mode_off(tmp_path):
    e=tmp_path/'efi'; e.mkdir()
    t=tmp_path/'tpm'; t.mkdir()
    _efi(e,'SecureBoot',1); _efi(e,'SetupMode',0)
    r=collect(efivar_root=e,tpm_root=t)
    assert r['secure_boot']['status']=='SECURE_BOOT_ENABLED_OBSERVED'
    assert r['verified'] is False


def test_setup_mode_overrides_secureboot(tmp_path):
    e=tmp_path/'efi'; e.mkdir()
    t=tmp_path/'tpm'; t.mkdir()
    _efi(e,'SecureBoot',1); _efi(e,'SetupMode',1)
    assert collect(efivar_root=e,tpm_root=t)['secure_boot']['status']=='FIRMWARE_SETUP_MODE'


def test_missing_efi_variable_not_downgraded_to_disabled(tmp_path):
    e=tmp_path/'efi'; e.mkdir()
    t=tmp_path/'tpm'; t.mkdir()
    _efi(e,'SecureBoot',1)
    assert collect(efivar_root=e,tpm_root=t)['secure_boot']['status']=='EFI_VARIABLES_UNAVAILABLE'


def test_pcr_log_read_only_command_and_no_log_leak(tmp_path):
    e=tmp_path/'efi'; e.mkdir()
    t=tmp_path/'tpm'; t.mkdir(); (t/'tpm0').mkdir()
    seen=[]
    def runner(cmd,**kw):
        seen.append((cmd,kw))
        return SimpleNamespace(returncode=0,stdout='PRIVATE_SERIAL_IDENTIFIER',stderr='')
    r=collect(efivar_root=e,tpm_root=t,runner=runner)
    assert seen[0][0] == list(PCRLOCK_COMMAND)
    assert seen[0][1]['timeout'] == 12
    assert r['pcr_log']['status']=='LOCAL_LOG_CHECK_COMPLETED'
    assert 'PRIVATE_SERIAL_IDENTIFIER' not in str(r)
    assert r['verified'] is False


def test_failed_pcr_check_not_claimed_verified(tmp_path):
    t=tmp_path/'tpm'; t.mkdir(); (t/'tpm0').mkdir()
    def runner(cmd,**kw):
        return SimpleNamespace(returncode=1,stdout='bad',stderr='')
    r=collect(efivar_root=tmp_path/'none',tpm_root=t,runner=runner)
    assert r['pcr_log']['status']=='LOG_OR_PCR_CHECK_FAILED'
    assert r['verified'] is False


def test_pcr_stdout_bounded(tmp_path):
    t=tmp_path/'tpm';t.mkdir();(t/'tpm0').mkdir()
    def runner(cmd,**kw):
        return SimpleNamespace(returncode=0,stdout='x'*(2*1024*1024+1),stderr='')
    r=collect(efivar_root=tmp_path/'none',tpm_root=t,runner=runner)
    assert r['pcr_log']['status']=='INVALID_CHECK_OUTPUT'
