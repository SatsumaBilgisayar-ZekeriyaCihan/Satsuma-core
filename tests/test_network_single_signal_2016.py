"""Candidate 20.1.6: single-indicator network-response regressions (no live firewall)."""
import importlib.util
import io
import json
import pathlib
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

MODULE = pathlib.Path(__file__).resolve().parents[1] / "integrations" / "satsuma_guard.py"
spec = importlib.util.spec_from_file_location("network_single_signal_guard", MODULE)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class NetworkSingleSignalTests(unittest.TestCase):
    def service(self, tmp, **kwargs):
        cfg = dict(guard.DEFAULT, state_dir=tmp, mode="observe", otx_enabled=False, **kwargs)
        with patch.object(guard, "local_ips", return_value={"192.168.1.10"}):
            return guard.Guard(cfg, boot_provider=lambda: {"response_unlocked": True})

    def test_k3_single_otx_pulse_is_never_sufficient(self):
        # Audit K3: anyone can publish one pulse; it must not corroborate.
        with tempfile.TemporaryDirectory() as tmp:
            svc = self.service(tmp)
            try:
                svc.api_key = "fixture-only"
                payload = json.dumps({"pulse_info": {"count": 1}, "reputation": 0})
                with patch.object(guard.urllib.request, "urlopen") as urlopen:
                    urlopen.return_value.__enter__.return_value = io.StringIO(payload)
                    self.assertFalse(svc.otx_check("45.33.32.10"))
                    urlopen.assert_called_once()
                with patch.object(guard.urllib.request, "urlopen") as urlopen:
                    self.assertFalse(svc.otx_check("45.33.32.10"))
                    urlopen.assert_not_called()
                strong = json.dumps({"pulse_info": {"count": 2}, "reputation": 1})
                with patch.object(guard.urllib.request, "urlopen") as urlopen:
                    urlopen.return_value.__enter__.return_value = io.StringIO(strong)
                    self.assertTrue(svc.otx_check("45.33.32.11"))
            finally:
                svc.events.close()
                svc.db.close()

    def test_one_suricata_alert_blocks_remote_for_outbound_and_reply(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = self.service(tmp)
            # Fixed rule 3: the flow behind the alert is a live local process
            # (the gate itself is covered by test_guard_peer_rules).
            svc.alert_verifier = lambda a: {"verdict": "verified_live_process"}
            try:
                alert = {"priority": 2, "source_ip": "192.168.1.10",
                         "dest_ip": "45.33.32.10", "signature": "fixture",
                         "rule_id": "1:900001:1"}
                # Audit K2: the reply is blocked only on a verified, completed TCP connection.
                svc.flow_checker = lambda a: False
                svc.reply_checker = lambda a: True
                with patch.object(svc, "block") as block:
                    svc.on_alert(alert)
                    svc.on_alert({**alert, "source_ip": alert["dest_ip"],
                                  "dest_ip": alert["source_ip"]})
                self.assertEqual(block.call_count, 2)
                self.assertEqual([c.args[0] for c in block.call_args_list],
                                 ["45.33.32.10", "45.33.32.10"])
                self.assertEqual(block.call_args_list[0].kwargs["direction"], "outbound_original")
                self.assertEqual(block.call_args_list[1].kwargs["direction"], "remote_to_local")
            finally:
                svc.events.close()
                svc.db.close()

    def test_k2_unverified_packet_to_this_host_never_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = self.service(tmp)
            svc.flow_checker = lambda a: False
            svc.reply_checker = lambda a: False
            try:
                with patch.object(svc, "block") as block:
                    svc.on_alert({"priority": 1, "source_ip": "1.1.1.1", "dest_ip": "192.168.1.10",
                                  "protocol": "UDP", "source_port": 53, "dest_port": 40000,
                                  "signature": "forged", "rule_id": "1:2:3"})
                    block.assert_not_called()
                events = svc.db.execute("SELECT count(*) FROM events WHERE event='ACTION_UNSUPPORTED'").fetchone()[0]
                self.assertEqual(events, 1)
            finally:
                svc.events.close()
                svc.db.close()

    def test_k2_dns_servers_are_never_blocked_even_when_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = self.service(tmp)
            svc.flow_checker = lambda a: True
            try:
                with patch.object(svc, "resolvers", return_value={"195.175.39.39"}), \
                        patch.object(svc, "block") as block:
                    svc.on_alert({"priority": 1, "source_ip": "195.175.39.39", "dest_ip": "192.168.1.10",
                                  "protocol": "TCP", "source_port": 53, "dest_port": 40000,
                                  "signature": "fixture", "rule_id": "1:2:3"})
                    block.assert_not_called()
            finally:
                svc.events.close()
                svc.db.close()

    def test_trusted_address_and_forwarded_reply_remain_protected(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = self.service(tmp)
            svc.trusted = [guard.ipaddress.ip_network("45.33.32.0/24")]
            alert = {"priority": 2, "source_ip": "192.168.1.10",
                     "dest_ip": "45.33.32.10", "signature": "fixture"}
            try:
                with patch.object(svc, "block") as block:
                    svc.on_alert(alert)
                    block.assert_not_called()
                svc.trusted = []
                svc.flow_checker = lambda alert: False
                with patch.object(svc, "block") as block:
                    svc.on_alert({**alert, "source_ip": "45.33.32.10",
                                  "dest_ip": "192.168.1.99"})
                    block.assert_not_called()
            finally:
                svc.events.close()
                svc.db.close()

    def test_sequential_peer_ips_count_even_after_connection_closes(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = self.service(tmp)
            try:
                with patch.object(guard.shutil, "which", return_value="/usr/sbin/conntrack"), \
                     patch.object(svc, "block") as block:
                    for i in range(1, 11):
                        src = f"45.33.32.{i}"
                        record = (f"tcp 6 431999 ESTABLISHED src={src} "
                                  "dst=192.168.1.10 sport=123 dport=80")
                        scan = types.SimpleNamespace(returncode=0, stdout=record, stderr="")
                        with patch.object(guard, "command", return_value=scan), \
                             patch.object(guard.time, "time", return_value=100 + i):
                            svc.check_connections()
                block.assert_called_once()
                self.assertEqual(block.call_args.args[0], "45.33.32.10")
                self.assertEqual(block.call_args.kwargs["active_distinct"], 10)
                self.assertEqual(block.call_args.kwargs["window_seconds"], 300)
            finally:
                svc.events.close()
                svc.db.close()

    def test_legacy_verified_nft_table_adds_output_chain_without_flushing(self):
        nft = guard.Nft()
        with patch.object(guard, "command", return_value=types.SimpleNamespace(returncode=0)), \
             patch.object(nft, "run") as run, \
             patch.object(nft, "verify_layout", side_effect=[RuntimeError("legacy"), None, None]) as verify:
            nft.setup()
        upgrade = [call for call in run.call_args_list if call.args[0] == ["nft", "-f", "-"]]
        self.assertEqual(len(upgrade), 1)
        self.assertIn("add chain inet satsuma_otx_guard output", upgrade[0].kwargs["input_text"])
        self.assertIn("output ct direction original ip daddr @blocked_v4",
                      upgrade[0].kwargs["input_text"])
        self.assertNotIn("flush", upgrade[0].kwargs["input_text"])
        self.assertEqual(verify.call_count, 3)


if __name__ == "__main__":
    unittest.main()
