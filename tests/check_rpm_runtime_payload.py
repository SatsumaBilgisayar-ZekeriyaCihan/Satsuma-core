"""Inspect the built RPM, rather than assuming source files were packaged."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

REQUIRED = ('integrations/omni_sentinel_rescue.py', 'integrations/network_health_probe.py')


def inspect(root):
    app = root/'usr/lib/satsuma-core/payload'
    references = set('/opt/satsuma-core/'+name for name in REQUIRED)
    launchers = list((root/'usr/bin').glob('satsuma-*'))
    launchers += list((root/'usr/lib/systemd/system').glob('satsuma-*'))
    launchers += [app/'satsuma/self_health.py']
    for path in launchers:
        for target in re.findall(r'/opt/satsuma-core/[A-Za-z0-9_./-]+\.py', path.read_text()):
            references.add(target)
    for target in sorted(references):
        path = app/target.removeprefix('/opt/satsuma-core/')
        if not path.is_file() or path.is_symlink():
            raise RuntimeError('RPM runtime target missing or symlink: '+target)
    compiled = 0
    for path in app.rglob('*.py'):
        compile(path.read_bytes(), str(path), 'exec')
        compiled += 1
    for name in REQUIRED:
        spec = importlib.util.spec_from_file_location('packaged_'+Path(name).stem, app/name)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return {'status':'PASS', 'runtime_targets':sorted(references), 'python_files_compiled':compiled,
            'integration_imports':list(REQUIRED), 'systemd_startup_verified':False}


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='satsuma-rpm-payload-') as directory:
        with tempfile.TemporaryFile() as archive:
            subprocess.run(['rpm2cpio',str(Path(sys.argv[1]).resolve())],stdout=archive,check=True)
            archive.seek(0)
            subprocess.run(['cpio','-idm','--quiet','--no-absolute-filenames'],stdin=archive,cwd=directory,check=True)
        print(json.dumps(inspect(Path(directory)),sort_keys=True))
