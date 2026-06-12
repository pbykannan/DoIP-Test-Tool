import threading
import unittest
from unittest import mock

from doip_tester.config.models import RawRequestStep
from doip_tester.flash.transfer import FlashFlowState, _run_raw_requests, _send_raw_uds_request
from udsoncan import Request
from udsoncan.exceptions import TimeoutException


def _mock_client_with_conn() -> mock.Mock:
    client = mock.Mock()
    client.config = {"p2_timeout": 0.05, "p2_star_timeout": 5.0}
    client.session_timing = mock.Mock(p2_server_max=None, p2_star_server_max=None)
    conn = mock.Mock()
    client.conn = conn
    return client


class TestSendRawUdsRequest(unittest.TestCase):
    def test_non_suppress_sends_directly(self) -> None:
        client = mock.Mock()
        req = Request.from_payload(bytes.fromhex("22F189"))

        _send_raw_uds_request(client, req)

        client.send_request.assert_called_once_with(req)

    def test_suppress_p2_silence_succeeds(self) -> None:
        client = _mock_client_with_conn()
        client.conn.wait_frame.side_effect = TimeoutException("p2")
        req = Request.from_payload(bytes.fromhex("288303"))

        _send_raw_uds_request(client, req)

        client.send_request.assert_not_called()
        client.conn.send.assert_called_once()

    def test_suppress_waits_78_then_final_positive(self) -> None:
        client = _mock_client_with_conn()
        client.conn.wait_frame.side_effect = [
            bytes.fromhex("7f2878"),
            bytes.fromhex("6803"),
        ]
        req = Request.from_payload(bytes.fromhex("288303"))

        _send_raw_uds_request(client, req)

        self.assertEqual(client.conn.wait_frame.call_count, 2)

    def test_suppress_pending_timeout_raises(self) -> None:
        client = _mock_client_with_conn()
        client.conn.wait_frame.side_effect = [
            bytes.fromhex("7f2878"),
            TimeoutException("p2*"),
        ]
        req = Request.from_payload(bytes.fromhex("288303"))

        with self.assertRaises(TimeoutException) as ctx:
            _send_raw_uds_request(client, req)
        self.assertIn("0x78", str(ctx.exception))


class TestRunRawRequestsSuppress(unittest.TestCase):
    def _run_steps(self, steps: list) -> mock.Mock:
        client = _mock_client_with_conn()
        client.conn.wait_frame.side_effect = [
            bytes.fromhex("7f2878"),
            bytes.fromhex("6803"),
        ]
        doip = mock.Mock()
        doip._uds_target_logical_address = 0x0001
        client.conn._connection = doip
        cancel = threading.Event()
        state = FlashFlowState()
        cfg = mock.Mock()
        cfg.doip.functional_logical_address = 0xE400
        cfg.doip.server_logical_address = 0x0001
        _run_raw_requests(
            client, steps, cfg, lambda _m: None, cancel, "TestRaw", state
        )
        return client

    def test_pre_transfer_suppress_then_normal(self) -> None:
        client = self._run_steps(
            [
                RawRequestStep(payload=bytes.fromhex("288303"), addressing="functional"),
                RawRequestStep(payload=bytes.fromhex("22F189"), addressing="physical"),
            ]
        )
        client.send_request.assert_called_once()
        self.assertEqual(client.conn.wait_frame.call_count, 2)

    def test_pending_failure_stops_before_next_step(self) -> None:
        client = _mock_client_with_conn()
        client.conn.wait_frame.side_effect = [
            bytes.fromhex("7f2878"),
            TimeoutException("p2*"),
        ]
        doip = mock.Mock()
        doip._uds_target_logical_address = 0x0001
        client.conn._connection = doip
        cancel = threading.Event()
        state = FlashFlowState()
        cfg = mock.Mock()
        cfg.doip.functional_logical_address = 0xE400
        cfg.doip.server_logical_address = 0x0001
        with self.assertRaises(TimeoutException):
            _run_raw_requests(
                client,
                [
                    RawRequestStep(payload=bytes.fromhex("288303"), addressing="functional"),
                    RawRequestStep(payload=bytes.fromhex("22F189"), addressing="physical"),
                ],
                cfg,
                lambda _m: None,
                cancel,
                "TestRaw",
                state,
            )
        client.send_request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
