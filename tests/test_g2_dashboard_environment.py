"""Audit G2: the GUI that receives the admin password starts with a clean environment.

Denetim G2: yönetici parolasının yazıldığı arayüz temiz bir ortamla başlar.
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]
LAUNCHER = ROOT / 'packaging/root/usr/bin/satsuma-dashboard'
PYTHON = '/usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -E -s -B -m satsuma.dashboard_qt'


def launch_environment(env):
    # Run the launcher's final block with env(1) standing in for Python.
    text = LAUNCHER.read_text()
    block = text.split('cd /opt/satsuma-core || exit 1\n', 1)[1]
    assert PYTHON in block
    result = subprocess.run(['/bin/bash', '-c', block.replace(PYTHON, '/usr/bin/env'), 'satsuma-dashboard'],
                            env=env, capture_output=True, text=True, timeout=10, check=True)
    return dict(line.split('=', 1) for line in result.stdout.splitlines())


def test_injection_variables_never_reach_the_gui():
    seen = launch_environment({
        'PATH': '/usr/bin:/bin', 'HOME': '/home/u', 'DISPLAY': ':0', 'WAYLAND_DISPLAY': 'wayland-0',
        'XDG_RUNTIME_DIR': '/run/user/1000', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1000/bus',
        'LANG': 'tr_TR.UTF-8', 'QT_SCALE_FACTOR': '1.5',
        'PYTHONPATH': '/tmp/evil', 'PYTHONSTARTUP': '/tmp/evil.py', 'LD_LIBRARY_PATH': '/tmp/evil',
        'QT_PLUGIN_PATH': '/tmp/evil', 'QT_QPA_PLATFORM_PLUGIN_PATH': '/tmp/evil', 'QML2_IMPORT_PATH': '/tmp/evil',
        'GTK_MODULES': 'evil', 'SATSUMA_RULES_DIR': '/tmp/empty',
    })
    assert seen == {'HOME': '/home/u', 'DISPLAY': ':0', 'WAYLAND_DISPLAY': 'wayland-0',
                    'XDG_RUNTIME_DIR': '/run/user/1000', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1000/bus',
                    'LANG': 'tr_TR.UTF-8', 'QT_SCALE_FACTOR': '1.5', 'PATH': '/usr/bin:/bin'}


def test_unset_display_variables_are_not_passed_as_empty_strings():
    seen = launch_environment({'PATH': '/usr/bin:/bin', 'WAYLAND_DISPLAY': 'wayland-0'})
    assert 'DISPLAY' not in seen and seen['WAYLAND_DISPLAY'] == 'wayland-0'


def test_launcher_is_bash_and_python_ignores_its_environment():
    text = LAUNCHER.read_text()
    assert text.startswith('#!/bin/bash\n')
    assert 'exec /usr/bin/env -i "${keep[@]}"' in text
    assert PYTHON in text
