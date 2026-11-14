# Satsuma Candidate 18: OPNsense observation-only adapter

## Explicit authority boundary

| Evidence or action | Local Fedora host | OPNsense firewall |
| --- | --- | --- |
| Suricata/local events | Local policy can authorize nftables host blocks | Never writes to OPNsense |
| OPNsense forwarded filterlog | Stored as remote events; may produce findings | Operator recommendations only |
| Remote API/firewall configuration | Not called by this adapter | No automatic rule changes |
| IP targets | Only single IPv4 /32 or IPv6 /128 addresses | Only advisory candidate addresses |

OPNsense telemetry is not trusted local enforcement evidence. Inbound blocked
packets from one public host address are counted in a ten-minute window, and
three hits can produce one review recommendation per hour. A firewall's block
log is **not** independent proof of an attack.

### Data path

1. Configure OPNsense to forward *filterlog* through a separately administered
   syslog receiver. Secure and restrict that transport in your network.
2. The local receiver should write a root-protected
   `/var/log/satsuma-opnsense.log`. Satsuma does not create a receiver, change
   host routes, open an inbound port or modify OPNsense settings.
3. After review, an administrator can explicitly enable
   `satsuma-opnsense-advisory.service`. The unit is **not enabled by RPM**.
4. The worker tails the file with inode+offset cursor and writes
   `opnsense_events` and `findings` into the local protected Satsuma store.
   The service uses `PrivateNetwork=true`; it cannot contact OPNsense.
5. In the Dashboard > Bulgular view, select source **OPNSENSE**. Findings
   explicitly state the target scope and whether an action was executed.

### Important limitations

- This is a read-only filterlog adapter, **not** an authenticated IDS API
  integration. IDS/IPS evaluation imports need additional schema and trust tests.
- Plain UDP syslog is not authenticated. OPNsense source identity must be
  established by the administrator's collector; this adapter will never
  treat the contents as authority to change local or remote firewalls.
- Host blocking remains policy-gated and writes only to the local dedicated
  `inet satsuma_core` nftables table. A valid local finding may authorize a
  local block; a remote OPNsense finding cannot authorize an automatic one.
- RPM build, clean Fedora 44 installation and live OPNsense forwarding remain
  unverified. Do not describe the integration as production-ready yet.
