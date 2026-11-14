# Satsuma App Control — Candidate20 draft

OpenSnitch is no longer a runtime dependency. The Satsuma daemon binds NFQUEUE 201 before installing its own `inet satsuma_app_control` output table. Suricata retains its separate queue and tables. No global ruleset flush is used.

New installations enable App Control. Unknown or ambiguous outbound TCP/UDP owners are denied and appear in the dashboard's right-side request panel. The authenticated admin channel supports a five-minute grant for one process lifetime and flow, or a persistent decision bound to executable hash, effective UID and cgroup. Explicit deny overrides earlier temporary allow. Pending commands cannot overwrite one another; stale commands are rejected.

Satsuma's required network workers, Suricata and dnsmasq can communicate through exact non-delegated Satsuma system service cgroups. The executable must match an expected dependency path and the installed RPM digest. Running the same Python binary from a desktop or another service does not inherit this permission. An operator's explicit disable remains respected.

Permissions cover code loaded by the executable. They are not a boundary against a compromised kernel, privileged root, or code injected into an allowed process. Loopback traffic and reply-direction traffic remain subject to the existing authenticated IPC and incoming firewall protections. DHCP and IPv6 neighbor discovery remain available.

This candidate uses per-packet process attribution. Sustained throughput, socket races under load, IPv6 variants and native Fedora integration require acceptance testing. Source tests alone do not establish production readiness or 100% protection/performance.
