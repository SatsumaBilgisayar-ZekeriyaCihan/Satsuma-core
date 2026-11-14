"""Packaging contract: files are deployable, secrets are never part of payload."""
from pathlib import Path
import shutil
import pytest
import importlib.util
_spec=importlib.util.spec_from_file_location('ai_payload_check',Path(__file__).resolve().parents[1]/'packaging/check_ai_payload.py')
_helper=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_helper)
inspect,REQUIRED=_helper.inspect,_helper.REQUIRED
# Import the repository helper by path: PyPI also has a package named packaging.


def test_staged_runtime_contains_ai_memory_schemas_and_native_qt(tmp_path):
    source=Path(__file__).resolve().parents[1]
    payload=tmp_path/'usr/lib/satsuma-core/payload';payload.mkdir(parents=True)
    for name in ('satsuma','schemas','rules','satsuma_engine','core','workers'):
        shutil.copytree(source/name,payload/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    shutil.copyfile(source/'run_satsuma_teams.py',payload/'run_satsuma_teams.py')
    (payload/'cli').mkdir()
    for name in ('satsuma-deepseek-test.py','satsuma-research.py'):shutil.copyfile(source/'bin'/name,payload/'cli'/name)
    result=inspect(tmp_path)
    assert result['status']=='PASS' and result['runtime_imports']['rules']==233
    assert not result['rpm_install_tested'] and not result['systemd_startup_tested']


def test_missing_schema_is_a_packaging_failure(tmp_path):
    with pytest.raises(RuntimeError,match='payload missing'):inspect(tmp_path)


def test_rpm_preserves_private_keys_and_trust_is_public_only():
    source=Path(__file__).resolve().parents[1]
    spec=(source/'packaging/satsuma-core.spec').read_text()
    assert 'schemas' in spec and 'gnupg2' in spec and 'python3-jsonschema' in spec
    assert '%dir %attr(0755,root,root) /etc/satsuma-core/trust' in spec
    assert '/var/lib/satsuma-core/generated_rules/active' in spec
    assert 'deepseek.key' not in spec
    assert 'ptrace_scope' not in spec and 'setenforce' not in spec


def test_installed_cli_uses_operator_not_local_key_or_unsigned_activation():
    source=Path(__file__).resolve().parents[1]
    for name in ('satsuma-deepseek-test','satsuma-research'):
        launcher=(source/'packaging/root/usr/bin'/name).read_text()
        assert '/usr/bin/python3' in launcher and '-I -B' in launcher
        assert '/opt/satsuma-core/cli/' in launcher
        cli=(source/'bin'/(name+'.py')).read_text()
        assert 'load_api_key' not in cli and 'save_api_key' not in cli
        assert 'getpass.getpass' in cli and 'ReaderClient' in cli
