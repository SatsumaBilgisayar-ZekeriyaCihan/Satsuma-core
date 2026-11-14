import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('systemd_hardening_audit', Path(__file__).parents[1]/'tools/systemd_hardening_audit.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_read_only_inventory(tmp_path):
    (tmp_path/'one.service').write_text('[Service]\nExecStart=/bin/true\nProtectSystem=strict\n')
    (tmp_path/'two.service').write_text('[Service]\nUser=daemon\nNoNewPrivileges=yes\n')
    report=module.audit(tmp_path)
    assert len(report['units']) == 2
    assert report['root_units'] == 1
    assert report['runtime_verified'] is False
    assert 'ProtectHome' in report['units'][0]['static_missing_baselines']
