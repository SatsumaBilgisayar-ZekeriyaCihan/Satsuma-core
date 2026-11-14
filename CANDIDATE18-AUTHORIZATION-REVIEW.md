# Candidate 18 — sudo and application-authorization review

## Sudo/PAM: source status, NOT live host enforcement

* `source/satsuma/sudo_guard.py` is currently a fail-closed stub.
* An optional PAM account module is in `source/installer/pam_satsuma.c`,
  now using the RPM-available `/usr/bin/python3` as its default helper runtime.
* The RPM spec does **not** compile/install `pam_satsuma.so`, change
  `/etc/pam.d/sudo*` or provide sudoers grants; therefore **do not claim
  Satsuma PAM authorization is currently enforced**.
* Never automatically alter a production host's PAM stack. A tested rollback
  path via independent root console and `visudo -c` is required before
  attempting optional enrollment in a disposable Fedora 44 VM.
* Existing sudo-hardening YAML rules are detection-only and cannot prove that
  a sudo command succeeded or that the user was authorized. The earlier audit
  reported 16 passing, 9 failing behavioral checks, and must be rerun.

## Application authorization

* Existing Satsuma app filter grants cover **systemd system service cgroups**
  with a verified executable hash and explicit DNS/HTTPS grants.
* It is disabled unless an operator explicitly enables it; the default mode
  does not impose a host-wide application block.
* It does **not** provide per-desktop-app interactive prompts. The existing
  OpenSnitch daemon may be a candidate for optional desktop app permission UI,
  but no new OpenSnitch installation, rule modification or service activation
  is performed in this branch.
* Do not enable both Satsuma blanket egress deny and OpenSnitch enforcement
  until policy precedence, DNS, loopback, and recovery have been tested.
* Only local host policy is permitted to write to `inet satsuma_core` and
  `inet satsuma_apps`. OPNsense remains **remote advisory only**.

## Release blockers

1. Test PAM cached/noninteractive sudo, root console recovery, and malformed
   credential fail-closed behavior in a disposable VM.
2. Test OpenSnitch coexistence in monitoring-only mode before enforcement.
3. Verify RPM upgrades do not silently change sudoers/PAM or elevate privilege.
4. Verify app authorization survives systemd restarts without dropping trusted
   DNS/loopback or essential update traffic.
5. Full Fedora 44 install and genuine nftables packet-path tests still needed.
