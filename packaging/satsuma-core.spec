%global __os_install_post %{nil}
%global debug_package %{nil}
%global _build_id_links none
Name: satsuma-core
Version: 2.2.37
Release: 1%{?dist}
Summary: Satsuma Core security monitoring and response
License: LicenseRef-Proprietary AND GPL-3.0-only AND Unlicense
Obsoletes: satsuma-core-dnf-guard < 2.0.0-0.candidate16
Provides: group(satsuma-engine)
Provides: user(satsuma-engine)
Provides: group(satsuma-dns)
Provides: user(satsuma-dns)
Provides: group(satsuma-core)
Provides: user(satsuma-core)
Provides: group(satsuma-reader)
Source0: %{name}-%{version}.tar.gz
Requires: rpm
Requires: gnupg2
Requires: audit
Requires: usbguard
Suggests: bpftool
Suggests: chkrootkit
Requires: clamav
Requires: clamd
Requires: policycoreutils-python-utils
Requires: clamav-data
Requires: clamav-freshclam
Requires: coreutils
Requires: dnsmasq
Requires: bind-utils
Requires: suricata >= 7
Requires: iproute
Requires: nftables
Requires: libnetfilter_queue
Requires: squashfs-tools
Requires: util-linux
Requires: conntrack-tools
Requires: python3
Requires: python3-jsonschema
Requires: python3-cryptography
Requires: openssl
Recommends: tpm2-tools
Requires: python3-psutil
Requires: python3-pydantic
Requires: python3-pyqt6-base
Requires: python3-pyyaml
Requires: rkhunter
# 2.2.36: tools from the satsuma-omni V62 setup, configured by satsuma-kur.
Requires: aide
# 2.2.31: D-Bus worker (dbus-monitor) and hidden process/port scan (unhide).
Requires: dbus-tools
Requires: unhide
Requires: shadow-utils
Requires(pre): python3
Requires(pre): suricata >= 7
Requires(pre): shadow-utils
Requires(pre): /usr/bin/systemd-sysusers
# Exact executable, NFQUEUE and rules are mandatory checks in pre-install and service startup.
Requires: systemd
Requires: polkit

%description
Security monitoring, policy-gated response, Audit, Suricata and evidence services.
Candidate build requiring live Fedora integration validation.

%prep
%setup -q

%build
# Do not build the custom libdnf5 veto plugin.
:

%install
# Explicit runtime payload: source archives and documentation never go into /opt.
install -d -m 0755 %{buildroot}/usr/lib/satsuma-core/payload
for entry in main.py run_satsuma_teams.py run_deep_engine.py core satsuma workers rules schemas suppressions satsuma_engine; do
 cp -a "$entry" %{buildroot}/usr/lib/satsuma-core/payload/
done
install -d -m 0755 %{buildroot}/usr/lib/satsuma-core/payload/cli
install -m 0644 bin/satsuma-deepseek-test.py bin/satsuma-research.py %{buildroot}/usr/lib/satsuma-core/payload/cli/
install -d -m 0755 %{buildroot}/usr/lib/satsuma-core/payload/installer
install -m 0644 installer/*.py %{buildroot}/usr/lib/satsuma-core/payload/installer/
install -d -m 0755 %{buildroot}/usr/lib/satsuma-core/payload/integrations
install -m 0644 integrations/satsuma_guard.py %{buildroot}/usr/lib/satsuma-core/payload/integrations/satsuma_guard.py
install -m 0644 integrations/omni_sentinel_rescue.py integrations/network_health_probe.py %{buildroot}/usr/lib/satsuma-core/payload/integrations/
find %{buildroot}/usr/lib/satsuma-core/payload -name __pycache__ -type d -prune -exec rm -rf {} +
find %{buildroot}/usr/lib/satsuma-core/payload -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '*.md' \) -delete
rm -rf %{buildroot}/usr/lib/satsuma-core/payload/satsuma_engine/samples
find %{buildroot}/usr/lib/satsuma-core/payload -type d -exec chmod 0755 {} +
find %{buildroot}/usr/lib/satsuma-core/payload -type f -exec chmod 0644 {} +
install -d -m 0755 %{buildroot}%{_docdir}/%{name}/examples
install -m 0644 satsuma_engine/samples/events.jsonl %{buildroot}%{_docdir}/%{name}/examples/
install -m 0644 SELF-REPAIR-GUIDE.md BUILD-VALIDATION.json %{buildroot}%{_docdir}/%{name}/
install -d -m 0755 %{buildroot}/usr/share/satsuma-core/dns-feeds
install -m 0644 data/dns-feeds/* %{buildroot}/usr/share/satsuma-core/dns-feeds/
install -d -m 0755 %{buildroot}/usr/share/satsuma-core/hardening
install -m 0644 packaging/hardening/* %{buildroot}/usr/share/satsuma-core/hardening/
cp -a packaging/root/. %{buildroot}/
install -D -m 0644 packaging/root/usr/lib/sysusers.d/satsuma-core.conf %{buildroot}/usr/lib/sysusers.d/satsuma-core.conf
# Public trust directory only. Never package/copy an API key or private GPG key.
install -d -m 0755 %{buildroot}/etc/satsuma-core/trust
install -d -m 0700 %{buildroot}/var/lib/satsuma-core/generated_rules/active
# 2.2.24: MITRE ATT&CK / CISA KEV definitions (reference data, not rules).
install -d -m 0755 %{buildroot}/var/lib/satsuma-core/tanim
install -m 0644 data/tanim/*.yaml %{buildroot}/var/lib/satsuma-core/tanim/
install -d -m 0700 %{buildroot}/etc/satsuma-core/package-trust/keys
install -d %{buildroot}/usr/lib/systemd/system %{buildroot}/etc/satsuma-core
install -m 0644 systemd/* %{buildroot}/usr/lib/systemd/system/
chmod 0644 %{buildroot}/usr/share/applications/satsuma-dashboard.desktop %{buildroot}/etc/xdg/autostart/satsuma-notify.desktop
install -d -m 0750 %{buildroot}/etc/satsuma-core/dns
install -m 0640 config_examples/config.json %{buildroot}/etc/satsuma-core/config.json
install -m 0640 config_examples/policy.json %{buildroot}/etc/satsuma-core/policy.json
install -m 0600 config_examples/suricata-otx-guard.json %{buildroot}/etc/satsuma-core/suricata-otx-guard.json

install -d -m 0755 %{buildroot}/opt/satsuma-core %{buildroot}/usr/libexec
install -m 0755 installer/image_runtime.py %{buildroot}/usr/libexec/satsuma-image

%pre
# Installation never invokes or accepts a host-wide integrity baseline.
# Existing application evidence is preserved; new payload is independently checked.

/usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -I -B - <<'SATSUMA_IPS_CHECK' || exit 1
"""Refuse an IPS binary without NFQ support or a usable detection rule set."""
import re
import os
import stat
from pathlib import Path
import subprocess
import sys

BINARY='/usr/bin/suricata'
CONFIG='/etc/suricata/suricata.yaml'
FLAGS=['--set','stream.inline=yes','--set','stream.bypass=no',
       '--set','nfq.mode=accept','--set','nfq.fail-open=no']


def verify(runner=subprocess.run, binary=BINARY, config=CONFIG):
    if runner is subprocess.run:
        path=Path(binary).resolve(strict=True)
        for entry in (path, *path.parents):
            info=entry.lstat()
            if info.st_uid!=0 or info.st_mode & 0o022:
                raise RuntimeError('Unsafe Suricata executable path: '+str(entry))
        if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_nlink!=1:
            raise RuntimeError('Suricata must be a protected regular executable')
    version=runner([binary,'-V'],capture_output=True,text=True,timeout=15,check=True)
    match=re.search(r'Suricata version (\d+)\.',version.stdout+getattr(version,'stderr',''))
    if not match or int(match.group(1))<7:
        raise RuntimeError('Suricata version 7 or newer required')
    build=runner([binary,'--build-info'],capture_output=True,text=True,timeout=15,check=True)
    if not re.search(r'NFQueue support:\s+yes\b',build.stdout):
        raise RuntimeError('Suricata binary has no NFQUEUE support')
    # Rules and configuration are handled at IPS start (satsuma.suricata_config,
    # 2.2.30) and by satsuma-admin tam-kontrol (suricata-update); a fresh Suricata
    # without downloaded rules no longer blocks the installation.
    return {'status':'binary_checked','host_cleanliness_verified':False}


if __name__=='__main__':
    try:
        print(verify())
    except Exception as exc:
        print(str(exc),file=sys.stderr)
        raise SystemExit(1)

SATSUMA_IPS_CHECK

# BEGIN PRE FAILURE RECOVERY
satsuma_stopped_recorded=0
satsuma_image_was_active=0
satsuma_pre_exit() {
 code=$?
 trap - EXIT
 if [ "$code" -ne 0 ]; then
  echo "Satsuma pre-install failed (status $code); restoring previously active services" >&2
  if [ "$satsuma_image_was_active" -eq 1 ]; then
   systemctl start satsuma-image.service || echo 'SATSUMA_ROLLBACK: image restart failed' >&2
  fi
  if [ "$satsuma_stopped_recorded" -eq 1 ]; then
   while read -r restore_unit; do
    case "$restore_unit" in
     satsuma*.service|satsuma*.timer|satsuma*.path)
      systemctl start "$restore_unit" || echo "SATSUMA_ROLLBACK: restart failed: $restore_unit" >&2;;
     *) echo 'SATSUMA_ROLLBACK: invalid saved unit; preserved for review' >&2;;
    esac
   done < /var/lib/satsuma-core/rpm-active-units
  fi
 fi
 exit "$code"
}
trap satsuma_pre_exit EXIT
# END PRE FAILURE RECOVERY
# Use the distribution account manager; it applies the host's SELinux policy.
# The config is embedded because %pre runs before the RPM payload is unpacked.
if ! /usr/bin/systemd-sysusers --replace=/usr/lib/sysusers.d/satsuma-core.conf - <<'SATSUMA_SYSUSERS'
# Satsuma service identities. Existing IDs are preserved by systemd-sysusers.
g satsuma-dns -
g satsuma-core -
g satsuma-reader -
g satsuma-priv -
g satsuma-engine -
u satsuma-engine - "Satsuma isolated deep engine" / /usr/sbin/nologin
u satsuma-dns - "Satsuma DNS" / /usr/sbin/nologin
u satsuma-core - "Satsuma Core" /var/lib/satsuma-core /usr/sbin/nologin
SATSUMA_SYSUSERS
then
    echo 'SATSUMA_ACCOUNT_SETUP_FAILED: systemd-sysusers could not create the service identities; installation stopped before payload preparation.' >&2
    /usr/bin/id >&2 || :
    /usr/bin/ls -ldZ /etc /etc/group /etc/gshadow /etc/passwd /etc/shadow >&2 || :
    exit 1
fi
for identity in satsuma-dns satsuma-core satsuma-reader satsuma-engine; do
    getent group "$identity" >/dev/null || {
        echo "SATSUMA_ACCOUNT_SETUP_FAILED: group not resolvable: $identity" >&2; exit 1;
    }
done
for identity in satsuma-dns satsuma-core satsuma-engine; do
    getent passwd "$identity" >/dev/null || {
        echo "SATSUMA_ACCOUNT_SETUP_FAILED: user not resolvable: $identity" >&2; exit 1;
    }
done
# Runs before RPM extracts the payload. Never follow a pre-existing link.
/usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -I -B - <<'SATSUMA_PREPARE' || exit 1
import os, stat

def prepare(path, mode):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.strip('/').split('/'):
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise PermissionError('Unsafe installation directory: ' + path)
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)

for path, mode in (
    ('/usr/lib/satsuma-core/payload', 0o755),
    ('/var/lib/satsuma-core/images', 0o700),
    ('/var/lib/satsuma-core/app-control', 0o700),
    ('/etc/satsuma-core', 0o755),
    ('/etc/satsuma-core/trust', 0o700),
    ('/etc/satsuma-core/package-trust', 0o700),
    ('/etc/satsuma-core/package-trust/keys', 0o700),
    ('/var/lib/satsuma-core/package-trust', 0o700),
    ('/var/lib/satsuma-core/application-control', 0o700),
    ('/var/lib/satsuma-core', 0o700),
    ('/var/lib/satsuma-core/host', 0o700),
    ('/var/lib/satsuma-core/integrity', 0o700),
    ('/usr/share/satsuma-core', 0o755),
):
    prepare(path, mode)
    for directory, dirs, names, fd in os.fwalk(path, follow_symlinks=False):
        for name in dirs + names:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (info.st_uid != 0 or info.st_mode & 0o022
                    or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                    or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
                raise PermissionError('Unsafe existing installation entry: ' + directory + '/' + name)
SATSUMA_PREPARE
umask 077
[ ! -L /var/lib/satsuma-core/rpm-active-units ] || exit 1
rm -f /var/lib/satsuma-core/rpm-active-units || exit 1
(set -C; : > /var/lib/satsuma-core/rpm-active-units) || exit 1
satsuma_stopped_recorded=1
if systemctl is-active --quiet satsuma-image.service; then satsuma_image_was_active=1; fi
if [ -d /run/systemd/system ]; then
 # Retired project units must not recreate old application files during installation.
 if ! systemctl list-unit-files --no-legend --no-pager > /var/lib/satsuma-core/rpm-all-units; then
  echo 'Cannot enumerate systemd units' >&2; exit 1
 fi
 /usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -I -B -c 'from pathlib import Path; p=Path("/var/lib/satsuma-core"); (p/"rpm-known-units").write_text("".join(x+"\n" for x in (p/"rpm-all-units").read_text().splitlines() if x.startswith("satsuma")))' || exit 1
 while read -r retired state preset; do
  case "$retired" in
   satsuma-flow-guard.service|satsuma-kernel-profile.service|satsuma-aide-check.service|satsuma-aide-check.timer|satsuma-module-lock.service|satsuma-module-lock.timer|satsuma-mitm-watch.service|satsuma-mitm-watch.timer|satsuma-quarantine-confirm.service|satsuma-quarantine-confirm.timer|satsuma-quarantine-rollback.service|satsuma-privd.service|satsuma-ram-clamd.service|satsuma-clamonacc.service|satsuma-onaccess-listener.service|satsuma-image.service|satsuma-boot-lockdown.service|satsuma-kernel-guard.service|satsuma-exec-guard.service|satsuma-temporary-scan.service|satsuma-temporary-scan.timer|satsuma-configuration.path|satsuma-configuration.service|satsuma-core-audit.service|satsuma-core-dns-refresh.service|satsuma-core-dns-refresh.timer|satsuma-core-dns.service|satsuma-core-finding.service|satsuma-deep-engine.service|satsuma-core-gateway.service|satsuma-core-otx.service|satsuma-core-security-scan.service|satsuma-core-security-scan-now.service|satsuma-core-security-scan.timer|satsuma-core-sentinel.service|satsuma-core-subnet.service|satsuma-core.service|satsuma-early-guard.service|satsuma-memory-hardening.service|satsuma-guardian.service|satsuma-network-modes.service|satsuma-network.service|satsuma-operator.service|satsuma-reader.service|satsuma-teams.service|satsuma-suricata-ips.service|satsuma-suricata-otx-guard.service|satsuma-app-control.service|satsuma-network-identity.service|satsuma-containment.service|satsuma-opnsense-advisory.service|satsuma-self-health.service|satsuma-self-health.timer|satsuma-rescue.service|satsuma-udev.service|satsuma-integrity-check.service|satsuma-integrity-check.timer|satsuma-boot-inventory.service|satsuma-boot-inventory.timer) :;;
   satsuma*.service|satsuma*.timer)
    # Do not stop/mask unknown units. An operator must review retired services.
    echo "SATSUMA: unknown pre-existing unit preserved for review: $retired" >&2;;
  esac
 done < /var/lib/satsuma-core/rpm-known-units
 # Stop producers before consumers, and the image only after every consumer.
 for timer in satsuma-mitm-watch.timer satsuma-configuration.path satsuma-core-security-scan.timer satsuma-core-dns-refresh.timer satsuma-self-health.timer satsuma-integrity-check.timer satsuma-app-control.timer; do
  if systemctl cat "$timer" >/dev/null 2>&1; then
   if systemctl is-active --quiet "$timer"; then printf '%s\n' "$timer" >> /var/lib/satsuma-core/rpm-active-units; fi
   systemctl stop "$timer" || exit 1
  fi
 done
 for unit in satsuma-self-health.timer satsuma-self-health satsuma-rescue satsuma-core satsuma-flow-guard satsuma-configuration.path satsuma-configuration.service satsuma-teams satsuma-deep-engine satsuma-reader satsuma-operator satsuma-guardian satsuma-core-audit satsuma-core-otx satsuma-core-subnet satsuma-core-dns satsuma-core-dns-refresh satsuma-network-modes satsuma-core-finding satsuma-core-gateway satsuma-core-sentinel satsuma-core-security-scan-now satsuma-core-security-scan.timer satsuma-core-dns-refresh.timer satsuma-network satsuma-suricata-ips satsuma-suricata-otx-guard satsuma-early-guard satsuma-memory-hardening satsuma-exec-guard satsuma-containment satsuma-network-identity satsuma-app-control satsuma-integrity-check.timer satsuma-integrity-check satsuma-boot-inventory.timer satsuma-boot-inventory satsuma-udev satsuma-mitm-watch satsuma-privd satsuma-ram-clamd satsuma-clamonacc satsuma-onaccess-listener satsuma-temporary-scan.timer satsuma-temporary-scan satsuma-aide-check.timer satsuma-aide-check; do
  case "$unit" in *.timer) name="$unit";; *.service) name="$unit";; *) name="$unit.service";; esac
  if systemctl is-active --quiet "$name"; then
   printf '%s\n' "$name" >> /var/lib/satsuma-core/rpm-active-units
   systemctl stop "$name" || exit 1
  fi
 done
 # RPM must relabel the underlying directory, not the mounted read-only image.
 if systemctl cat satsuma-image.service >/dev/null 2>&1; then
  systemctl stop satsuma-image.service || exit 1
 fi
fi

# BEGIN RPM MOUNT EXTRACTION GATE
# Also handle a residual image whose systemd unit is already inactive.
if /usr/bin/mountpoint -q /opt/satsuma-core; then
 /usr/bin/python3 -I -B /usr/libexec/satsuma-image unmount || exit 1
fi
if /usr/bin/mountpoint -q /opt/satsuma-core; then
 echo 'SATSUMA: runtime remains mounted; refusing RPM extraction and SELinux relabel' >&2
 exit 1
fi
# END RPM MOUNT EXTRACTION GATE

exit 0

%preun
if [ "$1" -eq 0 ]; then
 # First, before anything that can abort: give USB input back. The image is
 # still mounted here; after unmount /opt/satsuma-core is gone. Field report
 # 2026-10-25: keyboard and mouse were dead after removal.
 /usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -I -B /opt/satsuma-core/main.py --usbguard-restore || echo 'USB restore incomplete; see the output above' >&2
 # Kept even if the step above failed: without it no USB device is authorised after the next boot.
 if [ -x /usr/sbin/grubby ]; then
  /usr/sbin/grubby --update-kernel=ALL --remove-args=usbcore.authorized_default=2 || exit 1
 fi
fi
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
 # Stop every timer before its service so a timer cannot recreate an image user.
 for timer in satsuma-mitm-watch.timer satsuma-configuration.path satsuma-core-security-scan.timer satsuma-core-dns-refresh.timer satsuma-self-health.timer satsuma-integrity-check.timer satsuma-app-control.timer; do
  if systemctl cat "$timer" >/dev/null 2>&1; then
   if systemctl is-active --quiet "$timer"; then printf '%s\n' "$timer" >> /var/lib/satsuma-core/rpm-active-units; fi
   systemctl stop "$timer" || exit 1
  fi
 done
 for unit in satsuma-self-health.timer satsuma-self-health satsuma-rescue satsuma-core satsuma-flow-guard satsuma-configuration.path satsuma-configuration.service satsuma-teams satsuma-deep-engine satsuma-reader satsuma-operator satsuma-guardian satsuma-core-audit satsuma-core-otx satsuma-core-subnet satsuma-core-dns satsuma-core-dns-refresh satsuma-core-security-scan satsuma-network-modes satsuma-core-finding satsuma-core-gateway satsuma-core-sentinel satsuma-network satsuma-suricata-ips satsuma-suricata-otx-guard satsuma-early-guard satsuma-memory-hardening satsuma-containment satsuma-network-identity satsuma-app-control satsuma-integrity-check.timer satsuma-integrity-check satsuma-boot-inventory.timer satsuma-boot-inventory satsuma-udev satsuma-mitm-watch satsuma-privd satsuma-ram-clamd satsuma-clamonacc satsuma-onaccess-listener satsuma-temporary-scan.timer satsuma-temporary-scan satsuma-aide-check.timer satsuma-aide-check; do
  case "$unit" in *.timer) name="$unit";; *.service) name="$unit";; *) name="$unit.service";; esac
  # Optional/retired units may not be installed. A loaded unit failing to stop
  # must abort removal, preserving the helper required for a safe retry.
  if systemctl cat "$name" >/dev/null 2>&1; then
   systemctl disable --now "$name" || exit 1
  fi
 done
 # DefaultDependencies=no units still require explicit reverse shutdown ordering.
 # Do not swallow EBUSY and remove the unmount helper from beneath a live image.
 /usr/bin/python3 -I -B /usr/libexec/satsuma-image unmount || exit 1
 /usr/bin/python3 -I -B /usr/libexec/satsuma-image cleanup-firewall || exit 1
 systemctl disable --now satsuma-image.service || exit 1
fi

%posttrans
umask 077
/usr/bin/python3 -I -B /usr/libexec/satsuma-image build || exit 1
if [ -d /run/systemd/system ]; then
 # Stop the retired timer before activating the new image. OpenSnitch is kept:
 # since 2.2.30 it is the per-program firewall and App Control steps aside.
 systemctl disable --now satsuma-app-control.timer >/dev/null 2>&1 || :
 # Refuse to conceal residual queues owned by another firewall.
 /usr/bin/python3 -I -B /usr/libexec/satsuma-image legacy-check || exit 1
 /usr/bin/python3 -I -B /usr/libexec/satsuma-image activate || exit 1
 systemctl daemon-reload || exit 1
 # 2.2.11: nftables.service loads Satsuma's firewall at boot (90-satsuma.conf).
 systemctl enable nftables.service >/dev/null 2>&1 || echo 'nftables.service could not be enabled' >&2
 /usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -I -B /opt/satsuma-core/installer/service_setup.py || exit 1
 # Satsuma's SHA-256 blacklist into ClamAV's databases, before any scan runs.
 /usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -I -B /opt/satsuma-core/main.py --hash-blacklist || echo 'Hash blacklist not installed into ClamAV' >&2
 # USBGuard from early boot; never fails the install (see /var/lib/satsuma-core/usbguard.json).
 /usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -I -B /opt/satsuma-core/main.py --usbguard-setup || echo 'USBGuard setup incomplete; see /var/lib/satsuma-core/usbguard.json' >&2
 systemctl disable --now satsuma-ram-clamd.service >/dev/null 2>&1 || :
 systemctl enable satsuma-image.service satsuma-memory-hardening.service satsuma-early-guard.service satsuma-app-control.service satsuma-integrity-check.timer satsuma-self-health.timer satsuma-boot-inventory.timer satsuma-quarantine-rollback.service satsuma-quarantine-confirm.timer satsuma-mitm-watch.timer || exit 1
 systemctl start satsuma-image.service || exit 1
 systemctl enable satsuma-boot-lockdown.service || exit 1
 systemctl enable satsuma-kernel-guard.service || exit 1
 # 2026-11-11 (owner): build tools are refused before they run unless dnf/rpm runs.
 systemctl enable satsuma-exec-guard.service || exit 1
 # Enable on-access prevention by default on Fedora, regardless of virtualization.
 # Refuse incompatible pre-existing clamd policies rather than silently weakening security.
 /usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -I -B /opt/satsuma-core/installer/onaccess_setup.py install || exit 1
 systemctl enable clamd@scan.service satsuma-clamonacc.service || exit 1
 systemctl restart clamd@scan.service || exit 1
 systemctl start satsuma-clamonacc.service || exit 1
 # Enable the bounded journal consumer for integration testing. Unknown messages
 # remain non-actionable; all candidates require a fresh descriptor-bound scan.
 systemctl enable satsuma-onaccess-listener.service || exit 1
 systemctl start satsuma-onaccess-listener.service || exit 1
 # Temporary directories use the system clamd file scanner, never the retired RAM daemon.
 systemctl enable satsuma-temporary-scan.timer || exit 1
 systemctl start satsuma-temporary-scan.timer || echo 'satsuma-temporary-scan.timer could not start' >&2
 systemctl start satsuma-kernel-guard.service || echo 'satsuma-kernel-guard could not start; see journalctl -u satsuma-kernel-guard' >&2
 systemctl start satsuma-exec-guard.service || echo 'satsuma-exec-guard could not start; see journalctl -u satsuma-exec-guard' >&2
 systemctl start satsuma-boot-lockdown.service || echo 'satsuma-boot-lockdown incomplete; see /var/lib/satsuma-core/boot-lockdown.json' >&2
 /usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -I -B /opt/satsuma-core/installer/seed_db.py || exit 1
 dns_setup_failed=0
 systemctl restart satsuma-memory-hardening.service satsuma-early-guard.service || exit 1
 systemctl enable satsuma-privd.service || exit 1
 systemctl restart satsuma-privd.service || echo 'satsuma-privd could not start; services block by themselves' >&2
 # DNS readiness sends real traffic: bind both security consumers first.
 systemctl start satsuma-network.service satsuma-suricata-ips.service satsuma-app-control.service || exit 1
 /usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -I -B /opt/satsuma-core/installer/dns_setup.py || dns_setup_failed=1
 systemctl enable satsuma-configuration.path satsuma-core-gateway.service satsuma-core-sentinel.service satsuma-rescue.service satsuma-udev.service satsuma-network.service satsuma-network-identity.service satsuma-suricata-ips.service satsuma-suricata-otx-guard.service satsuma-core.service satsuma-deep-engine.service satsuma-teams.service satsuma-reader.service satsuma-operator.service satsuma-guardian.service satsuma-network-modes.service satsuma-core-audit.service satsuma-core-otx.service satsuma-core-subnet.service satsuma-core-finding.service satsuma-core-security-scan.timer satsuma-core-dns-refresh.timer || exit 1
 systemctl start satsuma-configuration.path satsuma-core-gateway.service satsuma-core-sentinel.service satsuma-rescue.service satsuma-udev.service satsuma-network.service satsuma-suricata-ips.service satsuma-app-control.service satsuma-core.service satsuma-deep-engine.service satsuma-teams.service satsuma-reader.service satsuma-operator.service satsuma-guardian.service satsuma-network-identity.service satsuma-suricata-otx-guard.service satsuma-core-audit.service satsuma-core-otx.service satsuma-core-subnet.service satsuma-core-finding.service satsuma-integrity-check.timer satsuma-self-health.timer satsuma-boot-inventory.timer satsuma-core-dns-refresh.timer satsuma-core-security-scan.timer || exit 1
 # 2.2.36: a network-modes failure (DNS readiness) is reported, but never stops
 # the remaining installation steps; field 2026-11-04 left them undone.
 # 2.2.36: network-modes hatası bildirilir ama kurulumun kalan adımlarını durdurmaz.
 network_modes_failed=0
 systemctl start satsuma-network-modes.service || network_modes_failed=1
 # Verification is part of installation, not an operator terminal task.
 systemctl start satsuma-integrity-check.service || exit 1
 # 2.2.15: man-in-the-middle watch every minute; its first run applies 92-satsuma-network.conf.
 systemctl start satsuma-mitm-watch.timer || echo 'satsuma-mitm-watch.timer could not start' >&2
# One-way kernel module lock: takes effect from the next boot (2.2.30).
systemctl enable satsuma-module-lock.timer || echo 'satsuma-module-lock.timer could not be enabled' >&2
# Flow guard (2.2.32): watches the in-memory event flow; raw events are no longer stored.
systemctl enable --now satsuma-flow-guard.service || echo 'satsuma-flow-guard.service could not start' >&2
 /usr/bin/satsuma-enroll-desktop --auto || exit 1
 (cd /opt/satsuma-core && /usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -E -s -B -m satsuma.configuration_reload) || exit 1
 # Finish configuration first, then wait for the real health result. A pending
 # modem approval remains an explicit warning; installation never invents it.
 systemctl start satsuma-self-health.service || echo 'Satsuma functional health verification failed; see the report below.' >&2
 (cd /opt/satsuma-core && /usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -E -s -B -m satsuma.self_health --report) || echo 'Satsuma installed with outstanding health checks; protection is not fully verified.' >&2
 if [ "$network_modes_failed" -ne 0 ]; then
  echo 'Satsuma workers started, but satsuma-network-modes failed (DNS readiness). Inspect: journalctl -u satsuma-network-modes; sudo satsuma-admin tam-kontrol.' >&2
 fi
 if [ "$dns_setup_failed" -ne 0 ]; then
  # 2.2.26: a DNS readiness timeout is a health warning, not a failed package
  # transaction; the DNS health check keeps reporting it until it works.
  echo 'Satsuma workers started, but DNS setup failed. Inspect the DNS health report (sudo satsuma-admin tam-kontrol).' >&2
 fi
else
 echo 'SquashFS candidate prepared. Activate on the target Fedora system before starting Satsuma.'
fi
printf '\nSatsuma kuruldu. Kurulumu tamamlamak için şimdi şunu çalıştırın:\n\n    sudo satsuma-kur\n\nAraçları yapılandırır; masaüstü kullanıcısını, yönetici parolasını, modemi ve isteğe bağlı OTX anahtarını sırayla sorar.\n'

%postun
if [ -d /run/systemd/system ]; then systemctl daemon-reload >/dev/null 2>&1 || :; fi

%files
%defattr(-,root,root,-)
%license LICENSE
%doc docs/INTEGRATED-AUDIT-2026.md
%doc docs/NETWORK-PROTECTION-PLAN.md docs/RULE-PREVENTION-AUDIT-20.1.4.md docs/POLICY-CONFIGURATION.md
%doc docs/RELEASE-2.1.6.md docs/RELEASE-2.2.0.md docs/RELEASE-2.2.1.md docs/RELEASE-2.2.2.md docs/RELEASE-2.2.3.md docs/RELEASE-2.2.4.md docs/RELEASE-2.2.5.md docs/RELEASE-2.2.6.md docs/RELEASE-2.2.7.md docs/RELEASE-2.2.8.md docs/RELEASE-2.2.9.md docs/RELEASE-2.2.10.md docs/RELEASE-2.2.11.md docs/RELEASE-2.2.12.md docs/RELEASE-2.2.13.md docs/RELEASE-2.2.14.md docs/RELEASE-2.2.15.md docs/RELEASE-2.2.16.md docs/RELEASE-2.2.17.md docs/RELEASE-2.2.18.md docs/RELEASE-2.2.19.md docs/RELEASE-2.2.20.md docs/RELEASE-2.2.21.md docs/RELEASE-2.2.22.md docs/RELEASE-2.2.23.md docs/RELEASE-2.2.24.md docs/RELEASE-2.2.25.md docs/RELEASE-2.2.26.md docs/RELEASE-2.2.27.md docs/RELEASE-2.2.28.md docs/RELEASE-2.2.29.md docs/RELEASE-2.2.30.md docs/RELEASE-2.2.31.md docs/RELEASE-2.2.32.md docs/RELEASE-2.2.33.md docs/RELEASE-2.2.34.md docs/RELEASE-2.2.35.md docs/RELEASE-2.2.36.md docs/RELEASE-2.2.37.md
%doc docs/MEMORY-PROTECTION.md docs/AUTOMATIC-PROCESS-RESPONSE.md docs/MEMORY-INSTALL-FEDORA44.md docs/SATSUMA-SIGNING.md
%doc CANDIDATE20.1.4-UI.md CANDIDATE20.1.3-REPORT.md CANDIDATE20.1.3-INSTALL.md WORKER-AUDIT-20261019.md DEVICE-AND-SYSTEMD-RESEARCH.md CANDIDATE19-STATUS.md README.md VERSION NETWORK-AND-DASHBOARD.md RULES-AND-DEFENSE.md BOOT-INSTALLATION.md NETWORK-IPS.md PACKAGE-TRUST.md APPLICATION-CONTROL.md OPNSENSE-ADVISORY.md CANDIDATE18-AUTHORIZATION-REVIEW.md NETWORK-IDENTITY.md REMOTE-ACCESS.md
%{_docdir}/%{name}/examples
%{_docdir}/%{name}/SELF-REPAIR-GUIDE.md
%{_docdir}/%{name}/BUILD-VALIDATION.json
%dir /opt/satsuma-core
/usr/lib/satsuma-core/payload
/usr/libexec/satsuma-image
/usr/libexec/satsuma-quarantine-rollback
/usr/lib/sysusers.d/satsuma-core.conf
/usr/lib/sysctl.d/90-satsuma-memory.conf
/usr/lib/sysctl.d/91-satsuma-ipv6.conf
/usr/lib/sysctl.d/92-satsuma-network.conf
/usr/lib/sysctl.d/93-satsuma-strict.conf
/usr/bin/satsuma-*
/usr/lib/systemd/system/satsuma*
%dir /usr/lib/systemd/system/nftables.service.d
/usr/lib/systemd/system/nftables.service.d/90-satsuma.conf
/usr/share/applications/satsuma-dashboard.desktop
/etc/xdg/autostart/satsuma-notify.desktop
/usr/share/satsuma-core/dns-feeds
/usr/share/satsuma-core/hardening
%config(noreplace) /etc/pki/rpm-gpg/RPM-GPG-KEY-SatsumaBilgisayar
%dir %attr(0755,root,root) /etc/satsuma-core
%dir %attr(0750,root,satsuma-dns) /etc/satsuma-core/dns
%config(noreplace) /etc/satsuma-core/config.json
%config(noreplace) /etc/satsuma-core/policy.json
%config(noreplace) /etc/satsuma-core/nftables.nft
%config(noreplace) %attr(0644,root,root) /etc/satsuma-core/dns-pinned.json
%config(noreplace) /etc/satsuma-core/suricata-otx-guard.json

%dir %attr(0700,root,root) /etc/satsuma-core/package-trust
%dir %attr(0700,root,root) /etc/satsuma-core/package-trust/keys
%config(noreplace) /etc/satsuma-core/package-trust/policy.json

%dir %attr(0755,root,root) /etc/satsuma-core/trust
%dir %attr(0700,root,root) /var/lib/satsuma-core/generated_rules
%dir %attr(0700,root,root) /var/lib/satsuma-core/generated_rules/active
%dir %attr(0755,root,root) /var/lib/satsuma-core/tanim
%verify(not md5 size mtime) %attr(0644,root,root) /var/lib/satsuma-core/tanim/*.yaml


