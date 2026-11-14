"""Regression coverage for the removed scanner and retained integrations."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from satsuma import host_ui, policy, security_scan
from satsuma.config import DEFAULT
from satsuma.teams.file_team.team_lead import FileTeamLead
from satsuma.teams.file_team.rules import ClamavOnlyMatchRule
from satsuma import dashboard_api

ROOT = Path(__file__).resolve().parents[1]


def test_removed_dependency_and_modules_are_unavailable():
    assert importlib.util.find_spec('yara') is None
    for module in ('satsuma.yara_host', 'satsuma.worker_yara', 'satsuma.yara_requests'):
        assert importlib.util.find_spec(module) is None
    assert not (ROOT / 'workers/yara').exists()
    assert not (ROOT / 'yara-rules').exists()
    assert not (ROOT / 'systemd/satsuma-core-yara.service').exists()


def test_cli_rejects_retired_worker_entrypoints():
    for flag in ('--yara-worker', '--yara-child'):
        result = subprocess.run([sys.executable, '-c', 'from satsuma.app import main; main()', flag],
                                cwd=ROOT, capture_output=True, text=True, timeout=10)
        assert result.returncode == 2
        assert 'unrecognized arguments' in result.stderr or 'required' in result.stderr
    help_text = subprocess.check_output([sys.executable, str(ROOT / 'main.py'), '--help'], text=True)
    assert 'yara' not in help_text.lower()


def test_policy_contains_only_retained_workers_and_rejects_old_scanner():
    value = policy.validate(policy.from_legacy(DEFAULT))
    assert {'audit', 'finding', 'evidence', 'suricata_collector'} <= value['workers'].keys()
    assert 'yara' not in json.dumps(policy.effective(value)).lower()
    value['workers']['yara'] = {'enabled': True}
    with pytest.raises(ValueError, match='unknown keys'):
        policy.validate(value)


def test_scheduled_scans_never_probe_removed_executable():
    requested = []
    def which(name):
        requested.append(name)
        return '/usr/bin/' + name
    commands = security_scan.commands(which)
    assert 'yara' not in requested
    assert {tool for tool, _ in commands} == {'clamav', 'rkhunter', 'chkrootkit'}
    assert all('yara' not in json.dumps(command).lower() for _, command in commands)


def test_clamav_detection_does_not_need_removed_partner():
    event = {'action': 'virus_detected', 'metadata': {'extensions': {
        'host.target': {'path': '/tmp/example', 'sha256': 'a' * 64}}}}
    findings = ClamavOnlyMatchRule().match([event])
    assert len(findings) == 1
    assert findings[0]['classification'] == 'suspicious'
    assert [worker.name for worker in FileTeamLead.workers] == ['clamav']


def test_host_queue_rejects_scan_jobs_before_opening_database():
    with patch.object(host_ui, 'connect', side_effect=AssertionError('must not open DB')):
        for kind in ('scan', 'validate', 'unknown'):
            with pytest.raises(ValueError, match='Unsupported host operation'):
                host_ui.submit(kind, {})


def test_dashboard_does_not_register_removed_route():
    assert not hasattr(dashboard_api, 'm_yara')
    assert 'yara' not in dashboard_api.METHODS
    assert dashboard_api._source_label({'source': 'clamav'}) == 'CLAMAV'


def test_runtime_and_packaging_have_no_removed_scanner_references():
    import re
    prohibited = re.compile(r'\byara\b|yara_|_yara|Yara[A-Z]', re.I)
    for directory in ('satsuma', 'workers', 'installer', 'bin', 'rules', 'systemd',
                      'config_examples', 'packaging', 'optional_components'):
        for path in (ROOT / directory).rglob('*'):
            if not path.is_file() or any(part in {'__pycache__', 'node_modules', 'dist'} for part in path.parts):
                continue
            assert not prohibited.search(path.name), str(path)
            if path.suffix in {'.pyc', '.png', '.jpg', '.ico', '.woff', '.woff2'}:
                continue
            try:
                text = path.read_text()
            except UnicodeDecodeError:
                continue
            # Exclude the Turkish word "yaratmasın", not scanner identifiers.
            assert not prohibited.search(text), str(path)
