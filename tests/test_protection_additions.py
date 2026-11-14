"""Suricata configuration, OpenSnitch hand-off, module lock and package signatures (2.2.30).

Suricata yapılandırması, OpenSnitch devri, modül kilidi ve paket imzaları.
"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from satsuma import app_firewall, module_lock, opensnitch, package_signatures, suricata_config

SYSTEM = """%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
default-rule-path: /etc/suricata/rules
rule-files:
  - suricata.rules
  - local.rules
outputs:
  - fast:
      enabled: yes
  - eve-log:
      enabled: no
      filename: other.json
      types:
        - alert
classification-file: /etc/suricata/classification.config
"""


def ip_runner(args, **kw):
    out = [{'ifname': 'lo', 'addr_info': [{'local': '127.0.0.1', 'prefixlen': 8}]},
           {'ifname': 'enp34s0', 'addr_info': [{'local': '192.168.1.20', 'prefixlen': 24}]}]
    return SimpleNamespace(returncode=0, stdout=json.dumps(out), stderr='')


def test_generated_suricata_config_has_satsuma_settings(tmp_path):
    system, target, rules = tmp_path / 'suricata.yaml', tmp_path / 'run' / 'suricata.yaml', tmp_path / 'rules'
    system.write_text(SYSTEM)
    rules.mkdir()
    (rules / 'local.rules').write_text('alert ip any any -> any any (sid:1;)\n')
    config = suricata_config.build(yaml.safe_load(SYSTEM), suricata_config.home_networks(ip_runner), rules)
    assert config['vars']['address-groups']['HOME_NET'] == '[192.168.1.0/24]'
    assert config['rule-files'] == ['suricata.rules', 'local.rules']
    eve = [o['eve-log'] for o in config['outputs'] if 'eve-log' in o][0]
    assert eve['enabled'] == 'yes' and eve['filename'] == 'eve.json' and {'alert', 'dns', 'tls', 'flow'} <= set(eve['types'])
    assert config['nfq'] == {'mode': 'accept', 'fail-open': 'no'}
    assert config['classification-file'] == '/etc/suricata/classification.config'
    result = suricata_config.generate(ip_runner, system, target)
    assert result['status'] == 'generated' and target.read_text().startswith('%YAML 1.1\n---\n')


def test_rejected_config_falls_back_to_the_system_file(tmp_path):
    system, target = tmp_path / 'suricata.yaml', tmp_path / 'out.yaml'
    system.write_text(SYSTEM)
    def failing(path):
        raise RuntimeError('suricata -T failed')
    result = suricata_config.generate(ip_runner, system, target, test=failing)
    assert result['status'] == 'system_copy' and target.read_text() == SYSTEM


def test_only_the_real_root_opensnitchd_counts(tmp_path, monkeypatch):
    proc = tmp_path
    for pid, exe, uid in (('10', '/usr/bin/opensnitchd', '1000'), ('11', '/tmp/opensnitchd', '0')):
        (proc / pid).mkdir()
        (proc / pid / 'exe').symlink_to(exe)
        (proc / pid / 'status').write_text(f'Name:\topensnitchd\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n')
    assert opensnitch.running(str(proc)) is False
    (proc / '12').mkdir()
    (proc / '12' / 'exe').symlink_to('/usr/bin/opensnitchd')
    (proc / '12' / 'status').write_text('Uid:\t0\t0\t0\t0\n')
    assert opensnitch.running(str(proc)) is True


def test_satsuma_rules_are_written_and_stale_ones_removed_but_user_rules_kept(tmp_path):
    (tmp_path / 'user-rule.json').write_text('{}')
    (tmp_path / 'satsuma-old.json').write_text('{}')
    written = opensnitch.sync_rules(opensnitch.wanted_rules([51820], 990), tmp_path)
    assert sorted(written) == ['satsuma-dns-filter.json', 'satsuma-wireguard-51820.json']
    assert (tmp_path / 'user-rule.json').exists() and not (tmp_path / 'satsuma-old.json').exists()
    body = json.loads((tmp_path / 'satsuma-wireguard-51820.json').read_text())
    assert body['action'] == 'allow' and {'operand': 'dest.port', 'data': '51820'}.items() <= body['operator']['list'][1].items()


def test_app_control_steps_aside_while_opensnitch_runs(monkeypatch):
    engine = app_firewall.Decisions.__new__(app_firewall.Decisions)
    monkeypatch.setattr(app_firewall, 'policy', lambda: {'enabled': True, 'rules': {}, 'application_rules': {}})
    engine.rules, engine.application_rules, engine.once = {}, {}, {}
    monkeypatch.setattr(opensnitch, 'running', lambda *a: True)
    assert engine.reload() is False and engine.handoff is True
    engine._handoff_checked = -10
    monkeypatch.setattr(opensnitch, 'running', lambda *a: False)
    assert engine.reload() is True


def test_module_lock_preloads_before_locking(tmp_path, monkeypatch):
    control = tmp_path / 'modules_disabled'
    control.write_text('0\n')
    calls = []
    loaded = module_lock.preload(lambda args, **kw: calls.append(args[-1]) or SimpleNamespace(returncode=0))
    assert 'wireguard' in loaded and calls[0] == 'wireguard'
    assert module_lock.lock(control)['status'] == 'LOCKED' and control.read_text().strip() == '1'


def test_gpgcheck_off_is_found_and_turned_on(tmp_path):
    conf, repos = tmp_path / 'dnf.conf', tmp_path / 'repos'
    repos.mkdir()
    conf.write_text('[main]\ngpgcheck=True\n')
    (repos / 'a.repo').write_text('[good]\nenabled=1\ngpgcheck=1\n\n[bad]\nenabled=1\ngpgcheck=0\n\n[off]\nenabled=0\ngpgcheck=0\n')
    assert package_signatures.weak(conf, repos) == [(str(repos / 'a.repo'), 'bad')]
    assert package_signatures.enforce(conf, repos, now=0) == [str(repos / 'a.repo')]
    assert package_signatures.weak(conf, repos) == []
    assert list(repos.glob('a.repo.satsuma-*'))


def test_unsigned_packages_are_listed_except_own():
    out = ('bash\t(none)\tRSA/SHA256, key ID x\t(none)\t(none)\n'
           'opensnitch-ui\t(none)\t(none)\tEdDSA/SHA512, key ID 6cd595fefd12dae2\t(none)\n'
           'evil\t(none)\t(none)\t(none)\t(none)\n'
           'satsuma-core\t(none)\t(none)\t(none)\t(none)\ngpg-pubkey\t(none)\t(none)\t(none)\t(none)\n')
    runner = lambda *a, **k: SimpleNamespace(returncode=0, stdout=out, stderr='')
    assert package_signatures.unsigned_packages(runner) == ['evil']


def test_opensnitch_dns_rule_matches_merged_bin_path():
    # Field 2026-11-04: Fedora reports /usr/bin/dnsmasq; a /usr/sbin rule never matched.
    import re
    from satsuma.opensnitch import wanted_rules
    conditions = wanted_rules(dns_uid=990)['dns-filter']['operator']['list']
    path = next(c for c in conditions if c['operand'] == 'process.path')
    assert path['type'] == 'regexp'
    assert re.fullmatch(path['data'].strip('^$'), '/usr/bin/dnsmasq')
    assert re.fullmatch(path['data'].strip('^$'), '/usr/sbin/dnsmasq')
    assert not re.search(path['data'], '/tmp/usr/bin/dnsmasq')
