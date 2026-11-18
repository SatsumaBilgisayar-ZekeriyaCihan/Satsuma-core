"""Satsuma Mini (V62 live-session script): fixed rules and fixes, checked from its source.

Satsuma Mini (V62 canlı oturum betiği): sabit kurallar ve düzeltmeler kaynağından denetlenir.
"""
import os
import re
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'satsuma-sentinel-v62-demo/satsuma-omni-sentinel-v62-fedora-hardened.sh'
import pytest
# The V62 demo is a separate project folder, not part of every source export
# (the 2026-11-18 archive had none); its checks run wherever it exists.
if not SCRIPT.exists():
    pytest.skip('satsuma-sentinel-v62-demo not in this source tree', allow_module_level=True)


def text():
    return SCRIPT.read_text()


def function(name):
    """Bash source of one top-level function."""
    body = text()
    start = body.index('\n' + name + '() {') + 1
    return body[start:body.index('\n}\n', start) + 3]


def test_bash_syntax():
    subprocess.run(['bash', '-n', str(SCRIPT)], check=True)


# -- AIDE, narrowed for live sessions (user decision 2026-11-10) -------------

def test_aide_uses_its_own_narrow_profile_and_never_edits_the_system_one():
    body = text()
    assert 'AIDE_WATCH=(/etc /usr/bin /usr/sbin /usr/libexec /usr/local /usr/lib/systemd)' in body
    assert '>> "$AIDE_CONF"' not in body and 'AIDE_CONF="/etc/aide' not in body
    calls = [line for line in body.splitlines() if re.search(r'\baide --', line)]
    assert calls and all('--config "$AIDE_CONF"' in line for line in calls)


def test_aide_snapshot_is_the_last_change_before_the_module_lock():
    wizard = function('auto_setup_wizard')
    snapshot = wizard.index('satsuma_aide_live_init ||')
    for earlier in ('satsuma_browser_harden || return 1', 'satsuma_protection_units_install',
                    'satsuma_tmp_install_service', 'satsuma_network_install_service', 'satsuma_audit_setup'):
        assert wizard.index(earlier) < snapshot, earlier
    assert snapshot < wizard.index('sysctl -w kernel.modules_disabled=1')


def run_aide(tmp_path, aide_body, prepare=''):
    fake = tmp_path / 'bin'
    fake.mkdir(exist_ok=True)
    (fake / 'aide').write_text('#!/bin/bash\n' + aide_body)
    (fake / 'restorecon').write_text('#!/bin/bash\nexit 0\n')
    for tool in ('aide', 'restorecon'):
        os.chmod(fake / tool, 0o755)
    log = tmp_path / 'log'
    log.mkdir(exist_ok=True)
    script = '\n'.join([
        'set -u', f'AIDE_DIR={tmp_path}/aide', 'AIDE_CONF="$AIDE_DIR/aide-live.conf"',
        'AIDE_DB="$AIDE_DIR/aide.db.gz"', 'AIDE_DB_NEW="$AIDE_DIR/aide.db.new.gz"',
        'AIDE_WATCH=(/etc /usr/bin)', 'C_GREEN= C_YELLOW= C_RESET=',
        function('satsuma_aide_live_config'),
        function('satsuma_aide_live_init').replace('/var/log/satsuma/', str(log) + '/'),
        prepare, 'satsuma_aide_live_init'])
    return subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                          env={**os.environ, 'PATH': f'{fake}:{os.environ["PATH"]}'})


INIT = 'for a; do case $a in --init) printf db > "$(dirname "$2")/aide.db.new.gz";; esac; done; exit 0\n'


def test_first_run_writes_the_profile_and_takes_the_snapshot(tmp_path):
    result = run_aide(tmp_path, INIT)
    assert result.returncode == 0, result.stderr
    profile = (tmp_path / 'aide/aide-live.conf').read_text()
    assert '/etc SATSUMA_LIVE' in profile and '/usr/bin SATSUMA_LIVE' in profile
    assert '!/etc/nftables\\.conf$' in profile and '/usr/lib64' not in profile
    assert (tmp_path / 'aide/aide.db.gz').read_text() == 'db'


def test_an_earlier_snapshot_that_differs_stops_setup_and_is_kept(tmp_path):
    differs = 'case "$*" in *--check*) echo "changed: /etc/passwd"; exit 4;; esac; exit 0\n'
    result = run_aide(tmp_path, differs, prepare=f'mkdir -p {tmp_path}/aide; printf old > {tmp_path}/aide/aide.db.gz')
    assert result.returncode != 0 and '/etc/passwd' in result.stderr
    assert (tmp_path / 'aide/aide.db.gz').read_text() == 'old'


def test_an_earlier_snapshot_that_matches_is_kept(tmp_path):
    same = 'exit 0\n'
    result = run_aide(tmp_path, same, prepare=f'mkdir -p {tmp_path}/aide; printf old > {tmp_path}/aide/aide.db.gz')
    assert result.returncode == 0 and (tmp_path / 'aide/aide.db.gz').read_text() == 'old'


# -- plain DNS instead of systemd-resolved; 853 closed (user decision 2026-11-10) --

def test_no_rule_accepts_port_853_and_853_is_dropped():
    for line in text().splitlines():
        rule = line.split('#', 1)[0]
        if 'accept' in rule and 'dport' in rule:
            assert not re.search(r'(?<![0-9])853(?![0-9])', rule), line
    assert 'tcp dport 853 counter drop' in text() and 'udp dport 853 counter drop' in text()


def test_plain_dns_replaces_systemd_resolved_before_firewall_audit_and_aide():
    dns = function('satsuma_plain_dns')
    assert 'systemctl mask --now "$unit"' in dns and 'systemd-resolved.service' in dns
    assert 'dns=none' in dns and 'rc-manager=unmanaged' in dns
    assert 'mv -f -T -- "$staged" /etc/resolv.conf' in dns and 'getent ahostsv4' in dns
    assert 'SATSUMA_DNS_SERVERS=(208.67.222.222 208.67.220.220)' in text()
    wizard = function('auto_setup_wizard')
    step = wizard.index('satsuma_plain_dns || return 1')
    for later in ('init_nftables || return 1', 'satsuma_audit_setup || return 1', 'satsuma_aide_live_init ||'):
        assert step < wizard.index(later), later


def test_plain_dns_servers_are_the_trusted_ones():
    trusted = re.search(r'WHITELIST_IPS=\(([^)]*)\)', text()).group(1)
    for server in ('208.67.222.222', '208.67.220.220'):
        assert server in trusted


# -- memory file scan in live sessions (field run 2026-11-10) ------------------

def embedded(marker):
    body = text()
    start = body.index(body.index("<<'" + marker + "'") and "<<'" + marker + "'")
    start = body.index('\n', start) + 1
    return body[start:body.index('\n' + marker + '\n', start)]


def memory_scan_source():
    program = embedded('SATSUMA_EMBEDDED_PYTHON')
    start = program.index('\ndef memory_scan():')
    return program[start:program.index('\ndef main():', start)]


def test_embedded_python_compiles():
    compile(embedded('SATSUMA_EMBEDDED_PYTHON'), 'satsuma_file_guard', 'exec')


def test_memory_scan_streams_content_instead_of_passing_the_descriptor():
    scan = memory_scan_source()
    assert "'--stream'" in scan and "'--fdpass'" not in scan


def test_memory_scan_reports_clamds_own_error_text():
    scan = memory_scan_source()
    assert "(out+b' '+err)" in scan and "'clamdscan: '+err" not in scan


def test_memory_scan_skips_mounts_that_are_not_tmpfs():
    scan = memory_scan_source()
    assert 'others.add(point)' in scan and 'os.path.join(parent,d) not in others' in scan


def test_install_commands_use_the_name_the_repository_downloads():
    name = SCRIPT.name
    readme = (SCRIPT.parent / 'README.md').read_text()
    for source in (readme, text()):
        assert './satsuma-mini' not in source
        assert f'/bin/bash -p -n ./{name}' in source
        assert f'install -o root -g root -m 0750 ./{name} /usr/local/bin/satsuma-mini' in source


def test_suricata_rules_bootstrap_never_stops_silently():
    body = text()
    start = body.index('\nsatsuma_suricata_rules_bootstrap() (')
    head = body[start:body.index('Suricata ET/Open imzaları indiriliyor', start)]
    head = head[:head.index("<<'SATSUMA_SURICATA_BOOTSTRAP_PATHS'")] + head[head.index('\nSATSUMA_SURICATA_BOOTSTRAP_PATHS\n'):]
    bare = [line for line in head.splitlines() if line.rstrip().endswith('|| return 1')]
    assert bare == [], bare
    assert 'fuser -v "$lock"' in head


# -- browser audit (live field run 2026-11-10) ---------------------------------

def browser_audit_source():
    program = embedded('SATSUMA_EMBEDDED_PYTHON')
    start = program.index('\ndef browser_audit():')
    return program[start:program.index('\ndef memory_scan():', start)]


def test_browser_audit_recognizes_firefox_children_by_their_program_file():
    audit = browser_audit_source()
    assert "os.readlink(proc/'exe')" in audit
    assert "if exe in ('firefox','firefox-bin','chrome','chromium','chromium-browser'): name=exe" in audit


def test_only_the_fork_server_is_exempt_from_the_seccomp_check():
    audit = browser_audit_source()
    assert "child_type!='forkserver'" in audit
    assert "status.get('Seccomp')!='2'" in audit
    for kept in ("'MOZ_DISABLE_CONTENT_SANDBOX'", "'--no-sandbox'", "'browser runs as root'"):
        assert kept in audit
