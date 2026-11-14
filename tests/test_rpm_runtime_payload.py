from pathlib import Path
import shutil
import pytest
from check_rpm_runtime_payload import inspect


def test_missing_rescue_in_built_payload_is_a_failure(tmp_path):
    path=tmp_path/'usr/lib/satsuma-core/payload/satsuma'
    path.mkdir(parents=True)
    (path/'self_health.py').write_text('')
    with pytest.raises(RuntimeError, match='network_health_probe|omni_sentinel_rescue'):
        inspect(tmp_path)


def test_extracted_payload_checks_launcher_target_and_imports(tmp_path):
    source = Path(__file__).resolve().parents[1]
    app = tmp_path/'usr/lib/satsuma-core/payload'
    (app/'integrations').mkdir(parents=True)
    (app/'satsuma').mkdir()
    (app/'satsuma/self_health.py').write_text('')
    for name in ('omni_sentinel_rescue.py','network_health_probe.py'):
        shutil.copyfile(source/'integrations'/name, app/'integrations'/name)
    bins = tmp_path/'usr/bin'; bins.mkdir(parents=True)
    (bins/'satsuma-missing').write_text('exec python3 /opt/satsuma-core/missing.py')
    with pytest.raises(RuntimeError, match='missing.py'):
        inspect(tmp_path)
    (app/'missing.py').write_text('pass')
    result = inspect(tmp_path)
    assert result['status']=='PASS'
    assert len(result['integration_imports'])==2
    assert result['systemd_startup_verified'] is False
