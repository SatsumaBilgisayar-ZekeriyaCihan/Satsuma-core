from pathlib import Path
from unittest.mock import patch
from satsuma.legacy_process import legacy_running


def process(proc, args, cwd):
    path=proc/'95576';path.mkdir(parents=True)
    (path/'cmdline').write_bytes(b'\0'.join(value.encode() for value in args)+b'\0')
    (path/'cwd').symlink_to(cwd, target_is_directory=True)


def test_ibus_main_is_not_core_even_with_home_working_directory(tmp_path):
    process(tmp_path, ['/usr/bin/python3','/usr/share/ibus-typing-booster/engine/main.py','--ibus'], '/home/SatsumaBilgisayar')
    assert legacy_running(tmp_path)==[]


def test_unrelated_main_with_run_is_not_core(tmp_path):
    process(tmp_path, ['/usr/bin/python3','/usr/share/other/main.py','--run'], '/home/SatsumaBilgisayar')
    assert legacy_running(tmp_path)==[]


def test_real_legacy_layout_and_relative_script_are_detected(tmp_path):
    app=tmp_path/'old';(app/'satsuma').mkdir(parents=True)
    (app/'main.py').write_text('')
    for name in ('app.py','pipeline.py','store.py'):(app/'satsuma'/name).write_text('')
    proc=tmp_path/'proc';process(proc,['/usr/bin/python3','main.py','--run'],str(app))
    original=Path.is_relative_to
    with patch.object(Path,'is_relative_to',lambda p,other: True if other=='/home' else original(p,other)):
        assert legacy_running(proc)==['95576']
    (app/'satsuma/pipeline.py').unlink()
    with patch.object(Path,'is_relative_to',return_value=True):assert legacy_running(proc)==[]
