"""Regression contracts for the Fedora RPM's verified SquashFS upgrade path."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read_spec():
    return (ROOT / "packaging" / "satsuma-core.spec").read_text()


def test_opnsense_advisory_is_packaged_and_not_retired_or_masked():
    spec = read_spec()
    pre = spec.split("%pre\n", 1)[1].split("%preun\n", 1)[0]
    case = pre.split('case "$retired" in', 1)[1].split("esac", 1)[0]
    allowed = case.split(") :;;", 1)[0]
    assert "satsuma-opnsense-advisory.service" in allowed.split("|")
    assert "satsuma*.service|satsuma*.timer" in case
    assert 'unknown pre-existing unit preserved for review' in case
    assert 'systemctl mask "$retired"' not in case
    assert 'systemctl disable --now "$retired"' not in case


def test_opnsense_advisory_requires_explicit_operator_enablement():
    spec = read_spec()
    post = spec.split("%posttrans\n", 1)[1].split("%postun\n", 1)[0]
    # The adapter must never be automatically enabled as a remote firewall controller.
    for line in post.splitlines():
        if "systemctl enable " in line or "systemctl start " in line:
            assert "satsuma-opnsense-advisory.service" not in line


def test_candidate_version_consistent_in_spec_embedded_gate_and_installer():
    spec = read_spec()
    # The 2.1.6 release left this test on the candidate20 strings; the
    # invariant is one version everywhere the package names it.
    version = (ROOT / "VERSION").read_text().strip()
    assert re.search(r"^Version: (\S+)", spec, re.M).group(1) == version
    release = re.search(r"^Release: (\S+)", spec, re.M).group(1)
    assert release == "1%{?dist}"
    assert f"__version__ = '{version}'" in (ROOT / "satsuma/__init__.py").read_text()
    installer = (ROOT / "installer/release_install.py").read_text()
    assert f"RPM_NAME = 'satsuma-core-{version}-1.fc44.x86_64.rpm'" in installer
    assert f"satsuma-core-{version}.tar.gz" in installer
