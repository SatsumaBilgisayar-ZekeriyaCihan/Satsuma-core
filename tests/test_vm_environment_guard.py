"""No Fedora device is modified by these mocked admission tests."""
import importlib.util
from pathlib import Path
import subprocess
import sys

VM_DIR = Path(__file__).resolve().parents[1] / 'vm-tests'
spec = importlib.util.spec_from_file_location('vm_environment', VM_DIR / 'vm_environment.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def runner(vm='kvm', *, container=False, uncertain=False):
    def run(argv, **kwargs):
        if '--container' in argv:
            return subprocess.CompletedProcess(argv, 2 if uncertain else 0 if container else 1, b'', b'')
        return subprocess.CompletedProcess(argv, 1 if vm is None else 0, (vm or 'none').encode(), b'')
    return run


def test_kvm_accepted(tmp_path):
    marker = tmp_path / 'fedora-release'; marker.write_text('Fedora')
    assert mod.detect_vm(run=runner(), fedora=marker) == (True, 'kvm')


def test_physical_refused(tmp_path):
    marker = tmp_path / 'fedora-release'; marker.touch()
    assert not mod.detect_vm(run=runner(vm=None), fedora=marker)[0]


def test_container_in_vm_refused(tmp_path):
    marker = tmp_path / 'fedora-release'; marker.touch()
    assert not mod.detect_vm(run=runner(container=True), fedora=marker)[0]


def test_uncertain_detection_refused(tmp_path):
    marker = tmp_path / 'fedora-release'; marker.touch()
    assert not mod.detect_vm(run=runner(uncertain=True), fedora=marker)[0]


def test_unrecognized_vm_refused(tmp_path):
    marker = tmp_path / 'fedora-release'; marker.touch()
    assert not mod.detect_vm(run=runner(vm='mystery'), fedora=marker)[0]


def test_missing_fedora_refused(tmp_path):
    assert not mod.detect_vm(run=runner(), fedora=tmp_path / 'missing')[0]


def test_detector_exception_refused(tmp_path):
    marker = tmp_path / 'fedora-release'; marker.touch()
    def fail(*a, **kw): raise FileNotFoundError()
    assert not mod.detect_vm(run=fail, fedora=marker)[0]
