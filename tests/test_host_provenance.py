import json
from types import SimpleNamespace
from satsuma.host_provenance import collect, parse_bootc, parse_rpm_ostree, parse_rpm_packages


def runner_mock(argv, **kwargs):
    assert kwargs['timeout'] == 8 and kwargs['check'] is False
    assert kwargs['env']['LC_ALL'] == 'C'
    if argv[0].endswith('rpm-ostree'):
        result = {'deployments': [{'booted': True, 'checksum': 'a' * 64, 'origin': 'fedora:test',
                                   'requested-local-packages': ['custom.rpm']} ]}
    elif argv[0].endswith('bootc'):
        result = {'status': {'booted': None}}
    else:
        return SimpleNamespace(returncode=0, stdout='test-pkg\t1.0\t1\tCustom\n')
    return SimpleNamespace(returncode=0, stdout=json.dumps(result))


def test_reports_ostree_and_layers_without_changing_host(tmp_path):
    result = collect(runner=runner_mock, reader=lambda _: 'ID=fedora\nVARIANT_ID=silverblue\n',
                     pid_root=tmp_path, watch_paths=[])
    assert result['mode'] == 'rpm-ostree'
    assert result['deployments'][0]['layer_changes']['requested-local-packages'] == ['custom.rpm']
    assert result['packages']['vulnerabilities_verified'] is False
    assert result['mutations'] is False
    assert result['analysis']['iso_integrity']


def test_bootc_detection():
    assert parse_bootc(json.dumps({'status': {'booted': {'image': {'image': 'registry.example/fedora'}}}}))['booted_present']


def test_reject_bad_ostree_schema():
    try:
        parse_rpm_ostree('{"deployments":{}}')
    except ValueError:
        pass
    else:
        assert False


def test_exposure_permissions(tmp_path):
    script = tmp_path / 'run.py'
    script.write_text('print(1)')
    script.chmod(0o666)
    result = collect(runner=runner_mock, reader=lambda _: '', pid_root=tmp_path, watch_paths=[script])
    assert result['script_exposure'][0]['signal'] == 'group_or_world_writable'


def test_rpm_parser_requires_fields():
    assert parse_rpm_packages('bad\nfoo\t2\t3\tVendor\n')[0]['name'] == 'foo'


def test_systemd_entrypoints_report_executable_and_weak_permissions(tmp_path):
    from satsuma.host_provenance import service_entrypoints
    unit = tmp_path / 'satsuma-scan.service'
    unit.write_text('[Service]\nUser=satsuma\nExecStart=/usr/bin/python3 /opt/satsuma/scan.py\n')
    unit.chmod(0o666)
    result = service_entrypoints([tmp_path])
    assert result[0]['signal'] == 'writable_unit'
    assert result[0]['authority'] == 'User=satsuma'
    assert '/opt/satsuma/scan.py' in result[0]['commands'][0]


def test_systemd_symlink_not_followed(tmp_path):
    from satsuma.host_provenance import service_entrypoints
    (tmp_path / 'satsuma-x.service').symlink_to('/etc/shadow')
    result = service_entrypoints([tmp_path])
    assert result[0]['signal'] == 'unit_symlink'
    assert result[0]['commands'] == []
