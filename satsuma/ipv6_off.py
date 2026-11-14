"""IPv6 off: the machine keeps no IPv6 connection at all (2.2.9).

The user decided that Satsuma switches every IPv6 connection off by itself.
Three layers do it, so that one of them being undone does not bring IPv6
back:

1. Kernel: net.ipv6.conf.{all,default,lo,<every interface>}.disable_ipv6 = 1,
   written at boot by satsuma-memory-hardening.service and kept by
   systemd-sysctl through /usr/lib/sysctl.d/91-satsuma-ipv6.conf.
2. Firewall: the first rule of every satsuma_core chain drops all IPv6
   packets (satsuma.network_control), whatever the kernel setting is.
3. DNS: Satsuma's dnsmasq listens on 127.0.0.1 only.

IPv6 kapalı: makinede hiçbir IPv6 bağlantısı kalmaz (2.2.9).

Kullanıcının kararıyla Satsuma bütün IPv6 bağlantılarını kendiliğinden
kapatır. Üç katman vardır; biri geri alınsa da IPv6 geri gelmez: çekirdek
ayarı (her arayüzde disable_ipv6 = 1), güvenlik duvarında her zincirin ilk
kuralı olarak bütün IPv6 paketlerinin düşürülmesi ve dnsmasq'ın yalnızca
127.0.0.1'den dinlemesi.
"""
from pathlib import Path

NAMES = ('all', 'default', 'lo')


def apply(sys_root=Path('/proc/sys')):
    """Write disable_ipv6 = 1 for all, default, lo and every interface."""
    conf = Path(sys_root) / 'net' / 'ipv6' / 'conf'
    if not conf.is_dir():
        return {'ok': True, 'ipv6': 'absent_in_kernel', 'disabled': []}
    names = list(NAMES) + sorted(p.name for p in conf.iterdir() if p.name not in NAMES)
    done, failed = [], {}
    for name in names:
        target = conf / name / 'disable_ipv6'
        try:
            target.write_text('1\n')
            done.append(name)
        except OSError as exc:
            failed[name] = str(exc)
    return {'ok': not failed, 'ipv6': 'disabled' if not failed else 'partly_disabled',
            'disabled': done, 'failed': failed}


def status(sys_root=Path('/proc/sys')):
    """Interfaces on which IPv6 is still enabled."""
    conf = Path(sys_root) / 'net' / 'ipv6' / 'conf'
    if not conf.is_dir():
        return {'ipv6_off': True, 'enabled_on': []}
    enabled = []
    for path in sorted(conf.iterdir()):
        try:
            if path.joinpath('disable_ipv6').read_text().strip() != '1':
                enabled.append(path.name)
        except OSError:
            enabled.append(path.name)
    return {'ipv6_off': not enabled, 'enabled_on': enabled}
