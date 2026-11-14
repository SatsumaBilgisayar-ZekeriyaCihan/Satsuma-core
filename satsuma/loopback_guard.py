"""Additional loopback checks, split by conntrack availability.

Stateless address spoof checks run before conntrack. Local-route and DNS DNAT
exceptions run after conntrack and destination NAT. A healthy owned table is
left untouched so counters remain cumulative.
"""
import json
import re
import shlex
import subprocess

TABLE = "satsuma_loopback"
OWNER = "Satsuma loopback validation"
CHAINS = ("pre_input", "pre_output", "input", "output", "forward")


def render(present=False, existing_chains=()):
    # The migration removes only chains owned by this table, never the table.
    lines = [f"delete chain inet {TABLE} {name}" for name in existing_chains if name in CHAINS or name == "pre_forward"] if present else [f"table inet {TABLE} {{", f' comment "{OWNER}"']
    for chain, hook, interface in (("pre_input", "prerouting", "iifname"), ("pre_output", "output", "oifname")):
        lines.append(f" chain {chain} {{ type filter hook {hook} priority -300; policy accept;")
        for protocol, subnet in (("ip", "127.0.0.0/8"), ("ip6", "::1")):
            for field in ("saddr", "daddr"):
                lines.append(f'  {interface} != "lo" {protocol} {field} {subnet} counter drop')
        lines.append(" }")
    for chain in ("input", "output", "forward"):
        lines.append(f" chain {chain} {{ type filter hook {chain} priority 0; policy accept;")
        if chain in ("input", "output"):
            interface = "iifname" if chain == "input" else "oifname"
            lines.append(f'  {interface} "lo" fib saddr type local fib daddr type local accept')
            lines.append(f'  {interface} "lo" meta l4proto tcp ct status dnat ct original proto-dst 53 accept')
            lines.append(f'  {interface} "lo" meta l4proto udp ct status dnat ct original proto-dst 53 accept')
            lines.append(f'  {interface} "lo" counter drop')
        lines.append(" }")
    return "\n".join(lines + ([] if present else ["}"]) + [""])


def tokens(value):
    value = re.sub(r"counter packets [0-9]+ bytes [0-9]+", "counter", value)
    value = re.sub(r"fib (saddr|daddr) type local", r"fib \1 type 2", value)
    value = value.replace("ct status dnat", "ct status 0x20")
    # Fedora nft -nnn -y prints transport names as protocol numbers in readback.
    # Normalize only the exact l4proto field; keep all verdicts and ports strict.
    value = re.sub(r"\bmeta l4proto (tcp|udp)\b",
                   lambda match: "meta l4proto " + {"tcp": "6", "udp": "17"}[match.group(1)],
                   value)
    parser = shlex.shlex(value, posix=True, punctuation_chars="{};")
    parser.whitespace_split = True
    parser.commenters = ""
    return [token for item in parser for token in re.findall(r"[{}]|[^{};]+", item) if token]


def _table_present(payload):
    return any(entry.get("table", {}).get("name") == TABLE
               and entry["table"].get("family") == "inet"
               for entry in payload.get("nftables", []))


def setup(runner=subprocess.run):
    def call(*args, **kwargs):
        return runner(["/usr/sbin/nft", *args], capture_output=True, text=True, timeout=15, **kwargs)

    listed = call("-j", "list", "tables")
    if listed.returncode:
        raise RuntimeError("Cannot inspect loopback firewall")
    tables = json.loads(listed.stdout)
    present = _table_present(tables)
    if present:
        old = call("-j", "list", "table", "inet", TABLE)
        if old.returncode:
            raise RuntimeError("Cannot inspect owned loopback table")
        if not any(entry.get("table", {}).get("comment") == OWNER for entry in json.loads(old.stdout).get("nftables", [])):
            raise RuntimeError("Unknown loopback table ownership")
        existing_chains = [entry["chain"]["name"] for entry in json.loads(old.stdout).get("nftables", []) if "chain" in entry]
        actual = call("-nnn", "-y", "list", "table", "inet", TABLE)
        if actual.returncode:
            raise RuntimeError("Cannot read back loopback firewall")
        if tokens(actual.stdout) == tokens(render()):
            return {"status": "already_healthy", "counters_preserved": True}

    script = render(present, existing_chains if present else ())
    for flags in (("--check", "-f", "-"), ("-f", "-")):
        done = call(*flags, input=script)
        if done.returncode:
            raise RuntimeError("Loopback validation failed: " + done.stderr[:300])
    actual = call("-nnn", "-y", "list", "table", "inet", TABLE)
    if actual.returncode or tokens(actual.stdout) != tokens(render()):
        raise RuntimeError("Loopback firewall readback differs")
    return {"status": "installed", "external_loopback_spoofing": "drop",
            "loopback_addresses": "local_fib_only_with_dns_dnat"}
