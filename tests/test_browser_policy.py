"""Browser policies from satsuma-omni V62 are written, merged and checked.

satsuma-omni V62 tarayıcı politikaları yazılır, birleştirilir ve denetlenir.
"""
import json
import os

import pytest

from satsuma import browser_policy as bp

UID = os.getuid()


def test_fresh_system_gets_all_three_files(tmp_path):
    result = bp.apply(tmp_path, uid=UID)
    assert sorted(result['written']) == sorted('/' + p for p in bp.POLICY_FILES)
    firefox = json.loads((tmp_path / bp.FIREFOX_PATH).read_text())['policies']
    assert firefox['WebsiteFilter'] == {'Block': ['http://*/*']} and firefox['Proxy']['Locked']
    assert firefox['ExtensionSettings']['*']['installation_mode'] == 'blocked'
    assert firefox['ExtensionSettings'][bp.ALLOWED_FIREFOX_EXTENSION_ID]['installation_mode'] == 'allowed'
    chrome = json.loads((tmp_path / bp.CHROMIUM_PATHS[0]).read_text())
    assert chrome['NativeMessagingBlocklist'] == ['*'] and chrome['URLBlocklist'] == ['http://*']
    assert bp.status(tmp_path)['ok']
    assert bp.apply(tmp_path, uid=UID)['written'] == []   # nothing to do the second time


def test_existing_keys_are_kept_backed_up_and_satsuma_wins(tmp_path):
    path = tmp_path / bp.FIREFOX_PATH
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({'policies': {'DisableTelemetry': True, 'Proxy': {'Mode': 'manual'},
                                             'Preferences': {'other.pref': {'Value': 1}}}}))
    os.chmod(path, 0o644)
    result = bp.apply(tmp_path, uid=UID)
    policies = json.loads(path.read_text())['policies']
    assert policies['DisableTelemetry'] is True and policies['Proxy']['Mode'] == 'none'
    assert 'other.pref' in policies['Preferences'] and 'security.sandbox.content.level' in policies['Preferences']
    assert len(result['backups']) == 1


def test_a_weakened_file_is_reported(tmp_path):
    bp.apply(tmp_path, uid=UID)
    path = tmp_path / bp.CHROMIUM_PATHS[1]
    data = json.loads(path.read_text())
    data['ProxyMode'] = 'fixed_servers'
    path.write_text(json.dumps(data))
    state = bp.status(tmp_path)
    assert not state['ok'] and state['files']['/' + bp.CHROMIUM_PATHS[1]] is False


def test_writable_parent_or_linked_file_is_refused(tmp_path):
    (tmp_path / 'etc').mkdir(mode=0o777)
    os.chmod(tmp_path / 'etc', 0o777)
    with pytest.raises(RuntimeError):
        bp.apply(tmp_path, uid=UID)
