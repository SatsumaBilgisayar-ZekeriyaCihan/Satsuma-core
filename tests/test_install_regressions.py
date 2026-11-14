"""Regression checks for observed package and panel failures."""
import hashlib
import os
from pathlib import Path
from unittest.mock import patch
import pytest
from installer import upgrade_setup
from satsuma import dashboard_api as api
from satsuma.critical_guardian import failure_text
from satsuma.store import Store


def test_core_findings_remain_available_without_host_database(tmp_path):
    store = Store(tmp_path/'data', test=True)
    store.add('findings', {'title': 'fixture event', 'severity': 'medium', 'source': 'CORE'})
    store.close()
    with patch.object(api, 'DB_PATH', str(tmp_path/'data'/'core.db')), patch.object(api, '_connect_host', side_effect=FileNotFoundError):
        result = api.m_findings()
    assert result['data_state'] == 'PARTIAL'
    assert result['sources']['host']['data_state'] == 'UNKNOWN'
    assert any(row['title'] == 'fixture event' for row in result['items'])


def test_identity_change_is_not_reported_as_missing():
    assert 'kimliği değişti' in failure_text({'path':'/fixture', 'reason':'critical_path_replaced'})
    assert 'bulunamadı' in failure_text({'path':'/fixture', 'reason':'critical_path_missing'})
