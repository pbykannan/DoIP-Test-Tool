import tempfile
import unittest
from pathlib import Path

from doip_tester.config.loader import (
    dump_app_config_yaml,
    load_app_config,
    load_app_config_from_str,
)


class TestConfig(unittest.TestCase):
    def test_from_project_template_file(self) -> None:
        root = Path(__file__).resolve().parents[1]
        ex = root / "project_configs" / "qirui.yaml"
        if not ex.is_file():
            self.skipTest("project_configs/qirui.yaml missing")
        cfg = load_app_config(ex)
        self.assertTrue(cfg.network.host)
        self.assertGreater(cfg.doip.server_logical_address, 0)

    def test_hex_coercion(self) -> None:
        y = """
network:
  host: "10.0.0.1"
  tcp_port: 13400
  udp_port: 13400
doip:
  client_logical_address: 0x0E00
  server_logical_address: 0x0001
  protocol_version: 2
  activation_type: Default
uds: {}
diagnostics:
  dids: [0xF190]
flash:
  memory_address: 0x08000000
  address_format: 32
  memorysize_format: 32
"""
        cfg = load_app_config_from_str(y)
        self.assertEqual(cfg.doip.client_logical_address, 0x0E00)
        self.assertEqual(cfg.diagnostics.dids[0], 0xF190)

    def test_dump_roundtrip(self) -> None:
        y = """
network:
  host: "10.0.0.2"
  tcp_port: 13400
doip:
  client_logical_address: 3584
  server_logical_address: 43
  protocol_version: 2
  activation_type: Default
  activation_disabled: false
uds:
  request_timeout: 5.0
diagnostics:
  dids: [61840]
  dtc_status_mask: 255
flash:
  memory_address: 134217728
  address_format: 32
  memorysize_format: 32
"""
        a = load_app_config_from_str(y)
        b = load_app_config_from_str(dump_app_config_yaml(a))
        self.assertEqual(a.network.host, b.network.host)
        self.assertEqual(a.doip.server_logical_address, b.doip.server_logical_address)
        self.assertEqual(a.diagnostics.dids, b.diagnostics.dids)


if __name__ == "__main__":
    unittest.main()
