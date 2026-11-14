"""Regression tests for the loopback guard renderer and no-op reconciliation."""
import json
from types import SimpleNamespace

import pytest
from satsuma import loopback_guard as guard


@pytest.mark.parametrize(("family", "address"), [("ip", "127.0.0.0/8"), ("ip6", "::1")])
@pytest.mark.parametrize(("chain", "direction"), [
    ("pre_input", "iifname"), ("pre_output", "oifname"),
])
def test_stateless_spoof_rules_precede_conntrack(family, address, chain, direction):
    text = guard.render()
    start = text.index("chain " + chain)
    section = text[start:text.index(" }", start)]
    assert "hook prerouting" in section or "hook output" in section
    assert "priority -300" in section
    assert f"{family} saddr {address} counter drop" in section
    assert f"{family} daddr {address} counter drop" in section
    assert "ct " not in section
    if direction:
        assert f'{direction} != "lo"' in section


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_dns_dnat_exception_is_explicit_per_transport_after_conntrack(protocol):
    text = guard.render()
    assert "priority 0" in text
    assert f'meta l4proto {protocol} ct status dnat ct original proto-dst 53 accept' in text


@pytest.mark.parametrize(("family", "address"), [("ip", "127.0.0.0/8"), ("ip6", "::1")])
def test_dnat_and_local_fib_exceptions_preserve_loopback_clients(family, address):
    text = guard.render()
    assert "fib saddr type local fib daddr type local accept" in text
    assert "ct status dnat" in text
    assert address in text


def test_reader_and_operator_unix_sockets_are_not_filtered_by_nft_rules():
    # Reader/Operator use Unix-domain sockets; these IP-only chains do not match them.
    text = guard.render()
    assert "/run/satsuma-reader/reader.sock" not in text
    assert "operator.sock" not in text
    assert 'iifname "lo" fib saddr type local fib daddr type local accept' in text
    assert 'oifname "lo" fib saddr type local fib daddr type local accept' in text


def test_migration_never_deletes_table_or_flushes_ruleset():
    text = guard.render(present=True, existing_chains=("input", "output", "forward"))
    assert "delete table" not in text
    assert "flush ruleset" not in text
    assert "delete chain inet satsuma_loopback input" in text
    # The last "}" closes the final chain, not the table: a migration script
    # deliberately omits a surrounding table declaration.
    assert "table inet satsuma_loopback {" not in text
    assert text.count("\n chain ") == len(guard.CHAINS)


def test_healthy_table_is_noop_and_preserves_counters():
    calls = []
    def runner(args, **kwargs):
        calls.append(args)
        if args[1:4] == ["-j", "list", "tables"]:
            output = {"nftables": [{"table": {"family": "inet", "name": guard.TABLE}}]}
        elif args[1:4] == ["-j", "list", "table"]:
            output = {"nftables": [{"table": {"family": "inet", "name": guard.TABLE, "comment": guard.OWNER}}]}
        else:
            return SimpleNamespace(returncode=0, stdout=guard.render(), stderr="")
        return SimpleNamespace(returncode=0, stdout=json.dumps(output), stderr="")
    result = guard.setup(runner)
    assert result == {"status": "already_healthy", "counters_preserved": True}
    assert not any("-f" in args for args in calls)


def test_owned_old_table_is_migrated_in_place_without_table_flush():
    calls = []
    old = {"nftables": []}
    old["nftables"] = [{"table": {"family": "inet", "name": guard.TABLE, "comment": guard.OWNER}}] + [
        {"chain": {"name": name}} for name in ("input", "output", "forward")
    ]
    reads = 0
    def runner(args, **kwargs):
        nonlocal reads
        calls.append((args, kwargs))
        if args[1:4] == ["-j", "list", "tables"]:
            return SimpleNamespace(returncode=0, stdout=json.dumps({"nftables": [{"table": {"family": "inet", "name": guard.TABLE}}]}), stderr="")
        if args[1:4] == ["-j", "list", "table"]:
            return SimpleNamespace(returncode=0, stdout=json.dumps(old), stderr="")
        if "-f" in args:
            assert "delete table" not in kwargs.get("input", "")
            assert "flush ruleset" not in kwargs.get("input", "")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        reads += 1
        return SimpleNamespace(returncode=0, stdout="old rules" if reads == 1 else guard.render(), stderr="")
    assert guard.setup(runner)["status"] == "installed"
    scripts = [kwargs["input"] for args, kwargs in calls if "-f" in args]
    assert len(scripts) == 2
    assert "delete chain inet satsuma_loopback input" in scripts[-1]
    assert "priority -300" in scripts[-1] and "priority 0" in scripts[-1]


def test_numeric_kernel_protocols_are_equivalent_but_port_changes_are_not():
    expected = guard.render()
    kernel = (expected.replace("meta l4proto tcp", "meta l4proto 6")
              .replace("meta l4proto udp", "meta l4proto 17")
              .replace("fib saddr type local", "fib saddr type 2")
              .replace("fib daddr type local", "fib daddr type 2")
              .replace("ct status dnat", "ct status 0x20"))
    assert guard.tokens(kernel) == guard.tokens(expected)
    assert guard.tokens(kernel.replace("ct original proto-dst 53", "ct original proto-dst 853")) != guard.tokens(expected)


def test_numeric_kernel_protocols_preserve_noop_reconciliation():
    requests = []
    readback = (guard.render()
                .replace("meta l4proto tcp", "meta l4proto 6")
                .replace("meta l4proto udp", "meta l4proto 17")
                .replace("ct status dnat", "ct status 0x20"))

    def runner(args, **kwargs):
        requests.append(args)
        if args[1:4] == ["-j", "list", "tables"]:
            output = {"nftables": [{"table": {"family": "inet", "name": guard.TABLE}}]}
        elif args[1:4] == ["-j", "list", "table"]:
            output = {"nftables": [{"table": {"family": "inet", "name": guard.TABLE, "comment": guard.OWNER}}]}
        else:
            return SimpleNamespace(returncode=0, stdout=readback, stderr="")
        return SimpleNamespace(returncode=0, stdout=json.dumps(output), stderr="")

    assert guard.setup(runner) == {"status": "already_healthy", "counters_preserved": True}
    assert not any("-f" in args for args in requests)
