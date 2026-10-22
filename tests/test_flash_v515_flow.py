import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import List, Tuple
from unittest import mock

from udsoncan import Request, services
from udsoncan.exceptions import TimeoutException

from doip_tester.config.loader import load_app_config
from doip_tester.flash.transfer import (
    TransferItem,
    _run_flash_download_items,
)


class _FakeClient:
    """按 udsoncan Client 在 transfer.py 中用到的最小接口实现，记录事件序列。"""

    def __init__(self, unlock_seed: object = None) -> None:
        self.config = {"p2_timeout": 1.0, "p2_star_timeout": 5.0}
        self.session_timing = None
        self.events: List[Tuple] = []
        self._unlock_seed = unlock_seed
        # 功能寻址 raw 请求（suppress 语义）用到的 connector mock
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
        if self._unlock_seed is not None:
            return SimpleNamespace(
                service_data=SimpleNamespace(seed=self._unlock_seed)
            )
        return None

    def request_download(self, mem, dfi=None):
        self.events.append(
            ("request_download", mem.address, mem.memorysize)
        )
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


class TestV515FlashFlow(unittest.TestCase):
    """n80ks.yaml 加载后跑通整条刷写流程（mock 对端），验证会话/解锁/校验/复位顺序。"""

    def setUp(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.cfg = load_app_config(root / "project_configs" / "n80ks.yaml")

    def _make_items(self) -> List[TransferItem]:
        import tempfile

        td = tempfile.mkdtemp(prefix="n80ks_flow_")
        s19 = Path(td) / "flash.s19"
        zf = Path(td) / "flash.zip"
        s19.write_bytes(b"\x11" * 1000)
        zf.write_bytes(b"\x22" * 3000)
        self.addCleanup(s19.unlink, missing_ok=True)
        self.addCleanup(zf.unlink, missing_ok=True)
        return [
            TransferItem(
                name="flash.s19",
                path=s19,
                size=s19.stat().st_size,
                signature=bytes(range(256)),
            ),
            TransferItem(
                name="flash.zip",
                path=zf,
                size=zf.stat().st_size,
                signature=bytes(reversed(range(256))),
            ),
        ]

    def _index_of(self, events, kind, **kw) -> int:
        for i, e in enumerate(events):
            if e[0] != kind:
                continue
            if all(e[j + 1] == v for j, v in enumerate(kw.values())):
                return i
        return -1

    def test_full_flow_sequence(self) -> None:
        client = _FakeClient()
        post_client = _FakeClient()
        items = self._make_items()
        logs: list[str] = []
        cancel = threading.Event()
        _run_flash_download_items(
            client,
            self.cfg,
            items,
            None,
            log=logs.append,
            cancel=cancel,
            reconnect_after_ecu_reset=lambda: post_client,
        )
        ev = client.events

        # 1) 图7 预编程：功能 1003 → 物理 0203 → 功能 8502/280301（无物理 10 03）
        self.assertEqual(self.cfg.flash.post_transfer_session_reassert, "none")
        self.assertGreaterEqual(self._index_of(ev, "send", **{"": "31010203"}), 0)
        pre_conn = [e for e in ev if e[0] == "conn_send"]
        self.assertTrue(any(e[2] == "1003" and e[1] == "0xe400" for e in pre_conn))
        self.assertTrue(any(e[2] == "8502" and e[1] == "0xe400" for e in pre_conn))
        self.assertTrue(
            any(e[2] == "280301" and e[1] == "0xe400" for e in pre_conn)
        )

        # 2) 功能 10 03 后、进 programming 前先解 L1（TBX：27 01/02 在 03 会话）
        i_unlock_l1_ext = self._index_of(ev, "unlock", **{"": 0x01})
        i_prog = self._index_of(ev, "session", name="programming")
        self.assertGreaterEqual(i_prog, 0)
        self.assertLess(i_unlock_l1_ext, i_prog)

        # 3) 编程会话解 L1→L3
        i_unlock_l3 = self._index_of(ev, "unlock", **{"": 0x11})
        self.assertGreater(i_unlock_l3, i_prog)

        # 4) 指纹写 F184（programming + level3）
        i_fp = self._index_of(ev, "send", **{"": "2EF184260810414243444546"})
        self.assertGreaterEqual(i_fp, 0)

        # 5) 两次 34/36/37，S19 先 ZIP 后；34 前安全级别为 0x11
        rd_s19 = self._index_of(ev, "request_download", address=0, memorysize=1000)
        rd_zip = self._index_of(ev, "request_download", address=0, memorysize=3000)
        self.assertGreaterEqual(rd_s19, 0)
        self.assertGreater(rd_zip, rd_s19)
        self.assertLess(i_unlock_l3, rd_s19)
        self.assertGreater(
            self._index_of(ev, "transfer_data"), 0
        )

        # 6) 图8：37 后 none——到 0202 前不重切会话；1101 前才回 default
        exit_idxs = [i for i, e in enumerate(ev) if e[0] == "transfer_exit"]
        self.assertTrue(exit_idxs)
        after_exit = ev[exit_idxs[-1] + 1 :]
        i_0202 = next(
            i for i, e in enumerate(after_exit) if e[0] == "routine" and e[1] == 0x0202
        )
        self.assertNotIn(("session", "default"), after_exit[:i_0202])
        self.assertNotIn(("session", "extended"), after_exit[:i_0202])
        sessions = [e[1] for e in ev if e[0] == "session"]
        self.assertEqual(sessions[-1], "default")  # 复位前回到默认会话

        # 7) 31 01 0202 两次，data 为 S19/ZIP 的 256 字节 RSA 签名（正规流程）
        r1 = self._index_of(ev, "routine", **{"": 0x0202})
        self.assertGreaterEqual(r1, 0)
        crc_routines = [
            e[3] for e in ev if e[0] == "routine" and e[1] == 0x0202
        ]
        self.assertEqual(len(crc_routines), 2)
        self.assertEqual(crc_routines[0], bytes(range(256)))
        self.assertEqual(crc_routines[1], bytes(reversed(range(256))))

        # 8) FF00 / FF01 例程
        rids = [e[1] for e in ev if e[0] == "routine"]
        self.assertIn(0xFF00, rids)
        self.assertIn(0xFF01, rids)
        self.assertLess(rids.index(0x0202), rids.index(0xFF00))
        self.assertLess(rids.index(0xFF00), rids.index(0xFF01))

        # 9) 最后 11 01 触发 OTA（先回默认会话再复位）
        i_1101 = self._index_of(ev, "send", **{"": "1101"})
        self.assertGreaterEqual(i_1101, 0)

        # 10) 重连后按文档后编程（图9）：1003/280001/8501/1001/14FFFFFF，功能寻址 suppress 语义
        post_ev = post_client.events
        conn_sends = [e[2] for e in post_ev if e[0] == "conn_send"]
        self.assertEqual(
            conn_sends,
            ["1003", "280001", "8501", "1001", "14FFFFFF"],
        )
        # 每个功能寻址请求发送时刻的目标逻辑地址都切换为 0xE400
        targets = [e[1] for e in post_ev if e[0] == "conn_send"]
        self.assertEqual(targets, ["0xe400"] * 5)

    def test_full_flow_sequence_with_signatures(self) -> None:
        client = _FakeClient()
        post_client = _FakeClient()
        items = self._make_items()
        sig_s19 = bytes(range(256))
        sig_zip = bytes(reversed(range(256)))
        items[0].signature = sig_s19
        items[1].signature = sig_zip
        logs: list[str] = []
        cancel = threading.Event()
        _run_flash_download_items(
            client,
            self.cfg,
            items,
            None,
            log=logs.append,
            cancel=cancel,
            reconnect_after_ecu_reset=lambda: post_client,
        )
        ev = client.events
        crc_routines = [
            e[3] for e in ev if e[0] == "routine" and e[1] == 0x0202
        ]
        self.assertEqual(len(crc_routines), 2)
        # 正规流程：0202 注入 256 字节 RSA 签名（来自 5-*.xml），而非 CRC32
        self.assertEqual(crc_routines[0], sig_s19)
        self.assertEqual(crc_routines[1], sig_zip)
        self.assertTrue(any("RSA 签名" in m for m in logs))

    def test_config_algo_and_transfer_level(self) -> None:
        self.assertEqual(self.cfg.uds.security_algorithm, "baic-df-token")
        self.assertFalse(self.cfg.uds.use_server_timing)
        self.assertAlmostEqual(self.cfg.uds.p2_timeout, 0.05)
        self.assertEqual(self.cfg.flash.transfer_security_level, 0x11)
        # 图7 功能 10 03 在 pre_raw；图8 仅物理进 programming；37 后 none
        self.assertEqual(self.cfg.flash.diagnostic_sessions_before_download, ["programming"])
        self.assertEqual(self.cfg.flash.post_transfer_session_reassert, "none")
        self.assertEqual(self.cfg.flash.security_access_levels_before_download, [0x01, 0x11])
        pre_sends = [s.payload.hex().upper() for s in self.cfg.flash.pre_transfer_raw_requests]
        self.assertEqual(pre_sends[0], "1003")
        self.assertEqual(
            self.cfg.flash.pre_transfer_raw_requests[0].addressing, "functional"
        )
        self.assertIn("280301", pre_sends)
        self.assertNotIn("280003", pre_sends)
        self.assertEqual(
            self.cfg.flash.post_transfer_after_reconnect_raw_requests[0].addressing,
            "functional",
        )
        post_sends = [
            s.payload.hex().upper()
            for s in self.cfg.flash.post_transfer_after_reconnect_raw_requests
        ]
        self.assertEqual(post_sends, ["1003", "280001", "8501", "1001", "14FFFFFF"])

    def test_unlock_all_zero_seed_marks_already_unlocked(self) -> None:
        """对端返回全 0 seed（已解锁语义）时，工具标记该级别已解锁且不报错。"""
        from doip_tester.flash.transfer import (
            FlashFlowState,
            _unlock_security_level,
        )

        client = _FakeClient(unlock_seed=b"\x00\x00\x00\x00")
        state = FlashFlowState()
        logs: List[str] = []
        _unlock_security_level(client, 0x01, logs.append, state, "test")
        self.assertIn(0x01, state.unlocked_levels)
        self.assertEqual(state.active_security_level, 0x01)
        self.assertTrue(any("已解锁" in m and "27 02 未发送" in m for m in logs))
        # 事件里只有一次 unlock 调用（unlock_security_access 内部跳过 27 02）
        self.assertEqual([e[0] for e in client.events], ["unlock"])

    def test_unlock_real_seed_sends_key(self) -> None:
        from doip_tester.flash.transfer import (
            FlashFlowState,
            _unlock_security_level,
        )

        client = _FakeClient(unlock_seed=b"\xa7\xc1\x64\xd2\xfb\xb3\xd5\x2e\xb2\xc6\x9f\x55\x13\x93\x35\x48")
        state = FlashFlowState()
        logs: List[str] = []
        _unlock_security_level(client, 0x01, logs.append, state, "test")
        self.assertEqual(state.active_security_level, 0x01)
        self.assertFalse(any("27 02 未发送" in m for m in logs))


if __name__ == "__main__":
    unittest.main()
