import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import List, Tuple
from unittest import mock

from udsoncan.exceptions import TimeoutException

from doip_tester.config.loader import load_app_config
from doip_tester.flash.transfer import (
    TransferItem,
    _run_flash_download_items,
)


class _FakeClient:
    def __init__(self) -> None:
        self.config = {"p2_timeout": 1.0, "p2_star_timeout": 5.0}
        self.session_timing = None
        self.events: List[Tuple] = []
        conn = mock.Mock()
        doip = mock.Mock()
        doip._uds_target_logical_address = 0x002B
        conn._connection = doip
        conn.empty_rxqueue = mock.Mock()
        conn.send.side_effect = lambda payload: self.events.append(
            (
                "conn_send",
                hex(doip._uds_target_logical_address),
                bytes(payload).hex().upper(),
            )
        )
        conn.wait_frame.side_effect = TimeoutException("p2")
        self.conn = conn
        self.last_response = None

    def change_session(self, mode) -> None:
        name = {0x01: "default", 0x02: "programming", 0x03: "extended"}.get(
            int(mode), "0x%02X" % int(mode)
        )
        self.events.append(("session", name))

    def unlock_security_access(self, level) -> None:
        self.events.append(("unlock", int(level)))
        return None

    def request_download(self, mem, dfi=None):
        self.events.append(("request_download", mem.address, mem.memorysize))
        return SimpleNamespace(service_data=SimpleNamespace(max_length=512))

    def transfer_data(self, seq, chunk) -> None:
        self.events.append(("transfer_data", seq, len(chunk)))

    def request_transfer_exit(self, data=None) -> None:
        self.events.append(("transfer_exit", bytes(data or b"")))

    def routine_control(self, routine_id, control_type, data=None) -> None:
        self.events.append(
            ("routine", int(routine_id) & 0xFFFF, int(control_type), bytes(data or b""))
        )

    @contextmanager
    def suppress_positive_response(self, wait_nrc=True):
        yield

    def tester_present(self) -> None:
        self.events.append(("tester_present",))

    def send_request(self, req) -> None:
        payload = req.get_payload() if hasattr(req, "get_payload") else bytes(req)
        self.events.append(("send", bytes(payload).hex().upper()))


class TestV335FlashFlow(unittest.TestCase):
    """v335.yaml：B40L 刷写无 FF00/FF01，仅 0202×2 + 1101。"""

    def setUp(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.cfg = load_app_config(root / "project_configs" / "v335.yaml")

    def _make_items(self) -> List[TransferItem]:
        import tempfile

        td = tempfile.mkdtemp(prefix="v335_flow_")
        s19 = Path(td) / "flash.s19"
        tar = Path(td) / "flash.tar"
        s19.write_bytes(b"\x11" * 1000)
        tar.write_bytes(b"\x22" * 3000)
        self.addCleanup(s19.unlink, missing_ok=True)
        self.addCleanup(tar.unlink, missing_ok=True)
        return [
            TransferItem(
                name="flash.s19",
                path=s19,
                size=s19.stat().st_size,
                signature=bytes(range(256)),
            ),
            TransferItem(
                name="flash.tar",
                path=tar,
                size=tar.stat().st_size,
                signature=bytes(reversed(range(256))),
            ),
        ]

    def test_security_uses_baic_df_token(self) -> None:
        self.assertEqual(self.cfg.uds.security_algorithm, "baic-df-token")
        # V335 MCU ramKey（L1）；与 N80KS 因子不同
        self.assertEqual(
            self.cfg.uds.security_key_level1.hex().upper(),
            "0CDF898CB7260FB85B00CFD25503EC9C",
        )
        self.assertEqual(
            self.cfg.uds.security_key_level3.hex().upper(),
            "0F9E79AE136FBDC67F0B5CF6B3053E41",
        )

    def test_no_ff00_ff01_in_post_routines(self) -> None:
        rids = [int(s.routine_id) & 0xFFFF for s in self.cfg.flash.post_transfer_routines]
        self.assertEqual(rids, [0x0202, 0x0202])
        self.assertNotIn(0xFF00, rids)
        self.assertNotIn(0xFF01, rids)

    def test_post_transfer_reassert_keeps_programming(self) -> None:
        """N80/335 图8：37 后 none——不重切会话，直接 0202（避免 10 01 清 0203）。"""
        self.assertEqual(self.cfg.flash.post_transfer_session_reassert, "none")
        client = _FakeClient()
        post_client = _FakeClient()
        items = self._make_items()
        _run_flash_download_items(
            client,
            self.cfg,
            items,
            None,
            log=lambda _m: None,
            cancel=threading.Event(),
            reconnect_after_ecu_reset=lambda: post_client,
        )
        exit_idxs = [i for i, e in enumerate(client.events) if e[0] == "transfer_exit"]
        self.assertTrue(exit_idxs)
        after = client.events[exit_idxs[-1] + 1 :]
        # 到 0202 之前不应再切会话；1101 前才回 default
        i_0202 = next(i for i, e in enumerate(after) if e[0] == "routine" and e[1] == 0x0202)
        before_0202 = after[:i_0202]
        self.assertNotIn(("session", "default"), before_0202)
        self.assertNotIn(("session", "extended"), before_0202)
        self.assertNotIn(("session", "programming"), before_0202)

    def test_flow_has_0202_twice_then_reset(self) -> None:
        client = _FakeClient()
        post_client = _FakeClient()
        items = self._make_items()
        _run_flash_download_items(
            client,
            self.cfg,
            items,
            None,
            log=lambda _m: None,
            cancel=threading.Event(),
            reconnect_after_ecu_reset=lambda: post_client,
        )
        routines = [e for e in client.events if e[0] == "routine"]
        self.assertEqual(len(routines), 2)
        self.assertEqual(routines[0][1], 0x0202)
        self.assertEqual(routines[1][1], 0x0202)
        self.assertEqual(len(routines[0][3]), 256)
        self.assertEqual(len(routines[1][3]), 256)
        sends = [e[1] for e in client.events if e[0] == "send"]
        self.assertIn("1101", sends)
        self.assertNotIn("3101FF00", sends)
        self.assertNotIn("3101FF01", sends)


if __name__ == "__main__":
    unittest.main()
