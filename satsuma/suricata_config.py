"""Satsuma's own Suricata configuration, built from the system suricata.yaml at every start.

User request 2026-11-04: the product edits Suricata's YAML itself. The
packaged /etc/suricata/suricata.yaml is never rewritten (the suricata
package owns it and an update would undo the edit). Each start of the
Satsuma IPS reads it and writes /run/satsuma-suricata/suricata.yaml with
the settings Satsuma needs:

- HOME_NET: the machine's own IPv4 networks (falls back to the RFC 1918
  ranges when none is found);
- rules from /var/lib/suricata/rules (suricata-update's output) plus any
  rule files listed in the system file that exist;
- an EVE JSON log at /var/log/suricata/eve.json with the alert, dns, tls
  and flow records Satsuma reads;
- inline NFQUEUE settings (accept mode, no fail-open) and the unix command
  socket under /run/satsuma-suricata.

The result is tested with ``suricata -T``; if it fails, the system file is
copied unchanged so the IPS starts exactly as before and the reason is
reported. Missing rules are downloaded with suricata-update by
satsuma-admin tam-kontrol (the IPS starts before the network).

Satsuma'nın kendi Suricata yapılandırması; her başlangıçta sistemdeki
suricata.yaml'dan üretilir. Kullanıcı isteği 2026-11-04: ürün Suricata'nın
YAML dosyasını kendisi düzenlesin. Paketin /etc/suricata/suricata.yaml
dosyası hiç yeniden yazılmaz (onu suricata paketi sahiplenir; güncelleme
düzenlemeyi geri alırdı). Satsuma IPS her başladığında bu dosyayı okur ve
gereken ayarlarla /run/satsuma-suricata/suricata.yaml yazar: HOME_NET
olarak bilgisayarın kendi IPv4 ağları, /var/lib/suricata/rules kuralları,
Satsuma'nın okuduğu kayıtlarla EVE JSON günlüğü, satır içi NFQUEUE ayarları
ve komut soketi. Sonuç ``suricata -T`` ile denenir; başarısız olursa sistem
dosyası olduğu gibi kopyalanır, IPS eskisi gibi başlar ve neden bildirilir.
Eksik kurallar satsuma-admin tam-kontrol tarafından suricata-update ile
indirilir (IPS ağdan önce başlar).
"""
import copy
import ipaddress
import json
import os
from pathlib import Path
import subprocess

SYSTEM = Path('/etc/suricata/suricata.yaml')
GENERATED = Path('/run/satsuma-suricata/suricata.yaml')
RULE_DIR = Path('/var/lib/suricata/rules')
LOG_DIR = '/var/log/suricata/'
SOCKET = '/run/satsuma-suricata/command.socket'
FALLBACK_HOME = ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']
EVE_TYPES = ('alert', 'dns', 'tls', 'flow')
HEADER = '%YAML 1.1\n---\n'


def home_networks(runner=subprocess.run):
    """The machine's own IPv4 networks, from ``ip -j -4 address``."""
    try:
        result = runner(['/usr/sbin/ip', '-j', '-4', 'address', 'show'], capture_output=True, text=True, timeout=5)
        interfaces = json.loads(result.stdout or '[]') if result.returncode == 0 else []
    except (OSError, subprocess.SubprocessError, ValueError):
        interfaces = []
    found = []
    for interface in interfaces:
        if interface.get('ifname') == 'lo':
            continue
        for entry in interface.get('addr_info', []):
            try:
                network = ipaddress.ip_interface(f"{entry['local']}/{entry['prefixlen']}").network
            except (KeyError, ValueError):
                continue
            if network.is_private and str(network) not in found:
                found.append(str(network))
    return found or list(FALLBACK_HOME)


def _eve(outputs):
    """The eve-log entry, created when missing, with Satsuma's record types enabled."""
    for item in outputs:
        if isinstance(item, dict) and isinstance(item.get('eve-log'), dict):
            eve = item['eve-log']
            break
    else:
        eve = {}
        outputs.insert(0, {'eve-log': eve})
    eve.update({'enabled': 'yes', 'filetype': 'regular', 'filename': 'eve.json'})
    types = eve.get('types') if isinstance(eve.get('types'), list) else []
    present = {next(iter(t)) if isinstance(t, dict) else t for t in types}
    for kind in EVE_TYPES:
        if kind not in present:
            types.append(kind)
    eve['types'] = types
    return eve


def build(system, networks, rule_dir=RULE_DIR):
    """Satsuma's configuration as a dict; ``system`` is the parsed system file."""
    config = copy.deepcopy(system) if isinstance(system, dict) else {}
    groups = config.setdefault('vars', {}).setdefault('address-groups', {})
    groups['HOME_NET'] = '[' + ','.join(networks) + ']'
    groups.setdefault('EXTERNAL_NET', '!$HOME_NET')
    config['default-rule-path'] = str(rule_dir)
    listed = [r for r in (config.get('rule-files') or []) if isinstance(r, str)]
    rules = ['suricata.rules'] + [r for r in listed if r != 'suricata.rules' and (rule_dir / r).is_file()]
    config['rule-files'] = rules
    config['default-log-dir'] = LOG_DIR
    outputs = config.get('outputs') if isinstance(config.get('outputs'), list) else []
    config['outputs'] = outputs
    _eve(outputs)
    config['nfq'] = {**(config.get('nfq') if isinstance(config.get('nfq'), dict) else {}), 'mode': 'accept', 'fail-open': 'no'}
    config['unix-command'] = {'enabled': 'yes', 'filename': SOCKET}
    stream = config.get('stream') if isinstance(config.get('stream'), dict) else {}
    config['stream'] = {**stream, 'inline': 'yes', 'bypass': 'no'}
    return config


def _dump(config):
    import yaml
    return HEADER + yaml.safe_dump(config, default_flow_style=False, sort_keys=False, allow_unicode=False)


def _load(text):
    import yaml
    return yaml.safe_load(text)


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name('.' + path.name + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, 'w') as handle:
        handle.write(text)
    os.replace(tmp, path)


def generate(runner=subprocess.run, system=SYSTEM, target=GENERATED, test=None):
    """Write Satsuma's configuration; fall back to an unchanged copy if Suricata rejects it."""
    original = Path(system).read_text()
    try:
        text = _dump(build(_load(original), home_networks(runner)))
        _write(Path(target), text)
        if test is not None:
            test(Path(target))
        return {'status': 'generated', 'path': str(target), 'home_net': home_networks(runner)}
    except Exception as exc:
        _write(Path(target), original)
        return {'status': 'system_copy', 'path': str(target), 'error': str(exc)[:500]}


def rules_present(rule_dir=RULE_DIR):
    path = Path(rule_dir) / 'suricata.rules'
    return path.is_file() and path.stat().st_size > 0


def update_rules(runner=subprocess.run):
    """Download the rule set with suricata-update (needs the network)."""
    result = runner(['/usr/bin/suricata-update', '--no-test', '--no-reload'], capture_output=True, text=True, timeout=600)
    if result.returncode:
        raise RuntimeError('suricata-update başarısız: ' + (result.stderr or result.stdout)[-400:])
    return rules_present()
