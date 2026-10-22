"""DoIPClientPatched 回归测试：残留 PDU 必须被彻底清空，防止旧响应串台。"""

import socket
import time
import unittest
from collections import deque
from unittest import mock

from doipclient.client import Parser
from doipclient.messages import (
    DiagnosticMessage,
    DiagnosticMessagePositiveAcknowledgement,
)

from doip_tester.doip.patched_client import DoIPClientPatched, _is_response_to


def _make_client() -> DoIPClientPatched:
    """绕过 __init__（doipclient 构造时会真实 connect），只保留依赖的属性。"""
    client = object.__new__(DoIPClientPatched)
    client._pending_diag_payloads = deque()
    client._tcp_sock = None
    client._tcp_parser = mock.Mock()
    client._tcp_parser.reset = mock.Mock()
    client._tcp_parser.push_bytes = mock.Mock()
    client._last_ack_monotonic = None
    client._prev_ack_monotonic = None
    client._log_cb = None
    return client


class TestIsResponseTo(unittest.TestCase):
    def test_positive_response_matches(self) -> None:
        self.assertTrue(_is_response_to(b"\x50\x03", b"\x10\x03"))

    def test_negative_response_matches(self) -> None:
        self.assertTrue(_is_response_to(b"\x7f\x10\x22", b"\x10\x03"))

    def test_stale_frame_does_not_match(self) -> None:
        # 上一请求 85 02 的迟到响应，不是 10 03 的响应
        self.assertFalse(_is_response_to(b"\xc5\x02", b"\x10\x03"))

    def test_tester_present_heartbeat_does_not_match(self) -> None:
        self.assertFalse(_is_response_to(b"\x7e\x3e\x00", b"\x22\xf1\x84"))

    def test_empty_inputs(self) -> None:
        self.assertFalse(_is_response_to(b"", b"\x10\x03"))
        self.assertFalse(_is_response_to(b"\x50\x03", b""))


class TestEmptyRxQueue(unittest.TestCase):
    def test_drops_all_stale_payloads(self) -> None:
        """上一次请求超时后，ECU 迟到的响应（含非 TesterPresent 的 C5 02）必须被清空。"""
        client = _make_client()
        client._pending_diag_payloads = deque(
            [
                b"\xc5\x02",  # 8502 迟到最终响应（超时残留）
                b"\x7f\x3e\x78",  # TesterPresent NRC 78
                b"\x7e\x3e\x00",  # TesterPresent 正响应
            ]
        )
        client.empty_rxqueue()
        self.assertEqual(len(client._pending_diag_payloads), 0)
        client._tcp_parser.reset.assert_called_once()

    def test_drains_tcp_socket_stale_frames(self) -> None:
        """迟到帧若已到达 TCP 接收缓冲（尚未 recv），必须被读空丢弃。"""
        client = _make_client()
        sock = mock.Mock()
        sock.gettimeout.return_value = 0.05
        sock.recv.side_effect = [
            b"\x02\xfd\x80\x01\x00\x00\x00\x06\x07\xff\x0e\x80\xc5\x02",
            socket.error("EAGAIN"),
        ]
        client._tcp_sock = sock
        client.empty_rxqueue()
        # 读到的残留帧喂给了 parser（随后 reset 丢弃）
        client._tcp_parser.push_bytes.assert_called_once()
        client._tcp_parser.reset.assert_called_once()
        sock.settimeout.assert_any_call(0)

    def test_no_payloads_noop(self) -> None:
        client = _make_client()
        client.empty_rxqueue()
        self.assertEqual(len(client._pending_diag_payloads), 0)

    def test_pending_queue_initialized_empty(self) -> None:
        client = _make_client()
        self.assertEqual(len(client._pending_diag_payloads), 0)


class TestSendDiagnosticStaleFilter(unittest.TestCase):
    def _client(self):
        client = _make_client()
        client._client_logical_address = 0x0E80
        client.send_doip_message = mock.Mock()
        return client

    def test_drops_stale_frame_before_ack(self) -> None:
        """等 ACK 期间先收到上一次请求的迟到帧（SID 不匹配）→ 丢弃，不缓存。"""
        client = self._client()
        client.read_doip = mock.Mock(
            side_effect=[
                # 8502 的迟到最终响应（SID C5 与本次 10 03 不匹配）
                DiagnosticMessage(0x002B, 0x0E80, b"\xc5\x02"),
                # DoIP ACK
                DiagnosticMessagePositiveAcknowledgement(0x002B, 0x0E80, 0x00, b""),
            ]
        )
        client.send_diagnostic_to_address(0x002B, bytearray(b"\x10\x03"), 5.0)
        self.assertEqual(len(client._pending_diag_payloads), 0)

    def test_keeps_fast_response_before_ack(self) -> None:
        """ECU 响应（SID 匹配）比 ACK 早到时仍须缓存，供 wait_frame 取用。"""
        client = self._client()
        client.read_doip = mock.Mock(
            side_effect=[
                # 本次 10 03 的快速正响应（SID 50 匹配）
                DiagnosticMessage(0x002B, 0x0E80, b"\x50\x03\x00\x32\x13\x88"),
                DiagnosticMessagePositiveAcknowledgement(0x002B, 0x0E80, 0x00, b""),
            ]
        )
        client.send_diagnostic_to_address(0x002B, bytearray(b"\x10\x03"), 5.0)
        cached = [p for _, p in client._pending_diag_payloads]
        self.assertEqual(cached, [b"\x50\x03\x00\x32\x13\x88"])


class TestAckTimingLog(unittest.TestCase):
    def test_ack_recorded_and_logged(self) -> None:
        """每个 DoIP ACK 到达都标注时间（wall-clock + 距上个 ACK 间隔）。"""
        client = _make_client()
        client._client_logical_address = 0x0E80
        client.send_doip_message = mock.Mock()
        logs: list[str] = []
        client._log_cb = logs.append
        client.read_doip = mock.Mock(
            side_effect=[
                DiagnosticMessagePositiveAcknowledgement(0x002B, 0x0E80, 0x00, b""),
            ]
        )
        client.send_diagnostic_to_address(0x002B, bytearray(b"\x10\x03"), 5.0)
        self.assertIsNotNone(client._last_ack_monotonic)
        self.assertTrue(any("DoIP ACK @" in m and "SID 0x10" in m for m in logs))

    def test_response_delta_logged_after_ack(self) -> None:
        """pending(NRC78) 或最终响应到达时，计算与最近 ACK 的差值。"""
        client = _make_client()
        client._client_logical_address = 0x0E80
        client.send_doip_message = mock.Mock()
        logs: list[str] = []
        client._log_cb = logs.append
        # 先发 ACK 记录基准，再从 socket 读到 NRC 78 与最终响应
        client.read_doip = mock.Mock(
            side_effect=[
                DiagnosticMessagePositiveAcknowledgement(0x002B, 0x0E80, 0x00, b""),
                DiagnosticMessage(0x002B, 0x0E80, b"\x7f\x36\x78"),
                DiagnosticMessage(0x002B, 0x0E80, b"\x76\x05"),
            ]
        )
        client.send_diagnostic_to_address(0x002B, bytearray(b"\x36\x05\x01"), 5.0)
        payload1 = client.receive_diagnostic(timeout=5.0)
        payload2 = client.receive_diagnostic(timeout=5.0)
        self.assertEqual(payload1, b"\x7f\x36\x78")
        self.assertEqual(payload2, b"\x76\x05")
        self.assertTrue(
            any("pending(NRC78)" in m and "ACK 后" in m for m in logs)
        )
        self.assertTrue(any("正响应" in m and "ACK 后" in m for m in logs))

    def test_timeout_logs_ms_since_ack(self) -> None:
        """等待响应超时时也记录当前距 ACK 的差值（即使判定超时）。"""
        client = _make_client()
        client._last_ack_monotonic = time.monotonic() - 3.0
        logs: list[str] = []
        client._log_cb = logs.append
        client.read_doip = mock.Mock(side_effect=TimeoutError("late"))
        with self.assertRaises(TimeoutError):
            client.receive_diagnostic(timeout=1.0)
        self.assertTrue(any("超时" in m and "ACK" in m for m in logs))

    def test_drain_logs_late_frame_after_timeout(self) -> None:
        """上次请求超时后，ECU 的迟到响应在下一次 empty_rxqueue 排空时补记差值。"""
        client = _make_client()
        client._tcp_parser = Parser()
        client._last_ack_monotonic = time.monotonic() - 5.0
        logs: list[str] = []
        client._log_cb = logs.append
        sock = mock.Mock()
        sock.gettimeout.return_value = 0.05
        # 完整 DoIP DiagnosticMessage：payload = c5 02（8502 的迟到最终响应）
        sock.recv.side_effect = [
            b"\x02\xfd\x80\x01\x00\x00\x00\x06\x07\xff\x0e\x80\xc5\x02",
            socket.error("EAGAIN"),
        ]
        client._tcp_sock = sock
        client.empty_rxqueue()
        self.assertTrue(
            any("残留迟到帧" in m and "SID 0xC5" in m and "ACK 后" in m for m in logs)
        )

    def test_no_log_when_nothing_drained(self) -> None:
        client = _make_client()
        client._tcp_parser = Parser()
        logs: list[str] = []
        client._log_cb = logs.append
        sock = mock.Mock()
        sock.gettimeout.return_value = 0.05
        sock.recv.side_effect = [socket.error("EAGAIN")]
        client._tcp_sock = sock
        client.empty_rxqueue()
        self.assertFalse(any("残留" in m for m in logs))


if __name__ == "__main__":
    unittest.main()
