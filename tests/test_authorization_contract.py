"""Source-only safety checks; these do not claim live PAM authorization."""
from pathlib import Path

from satsuma import sudo_guard
from satsuma import application_control as app


SOURCE = Path(__file__).resolve().parents[1]


def test_sudo_fallback_cannot_grant_admin_authorization():
    assert sudo_guard.is_allowed(None, "root") is False
    assert sudo_guard.request_admin_approval(None, "rule", "reason", "root")["approved"] is False


def test_optional_pam_uses_packaged_python_without_editing_host_pam():
    source = (SOURCE / "installer" / "pam_satsuma.c").read_text()
    spec = (SOURCE / "packaging" / "satsuma-core.spec").read_text()
    assert '#define PYTHON_PATH "/usr/bin/python3"' in source
    assert "pam_satsuma.so" not in spec
    assert "/etc/pam.d/sudo" not in spec


def test_app_grants_require_explicit_activation():
    assert app.render([], enabled=False).count("policy accept") == 2
    assert app.render([], enabled=True).count("policy drop") == 2
    assert app.validate_policy({"schema":1,"grants":{}})["grants"] == {}
