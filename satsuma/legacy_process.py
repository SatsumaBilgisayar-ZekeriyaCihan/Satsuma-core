"""Detect an actual home-based Core without matching unrelated main.py programs."""
from pathlib import Path
import os


def legacy_running(proc=Path('/proc')):
    found = []
    for cmdline in proc.glob('[0-9]*/cmdline'):
        try:
            if cmdline.parent.name == str(os.getpid()):
                continue
            raw = cmdline.read_bytes()
            if len(raw) > 65536:
                continue
            args = [os.fsdecode(value) for value in raw.split(b'\0') if value]
            if not args or not Path(args[0]).name.startswith('python') or '--run' not in args:
                continue
            scripts = [value for value in args[1:] if Path(value).name == 'main.py']
            if len(scripts) != 1:
                continue
            script = Path(scripts[0])
            if not script.is_absolute():
                script = (cmdline.parent/'cwd').resolve(strict=True)/script
            script = script.resolve(strict=True)
            if not script.is_relative_to('/home'):
                continue
            root = script.parent
            if all((root/'satsuma'/name).is_file() for name in ('app.py','pipeline.py','store.py')):
                found.append(cmdline.parent.name)
        except (OSError, ValueError, RuntimeError):
            continue
    return found
