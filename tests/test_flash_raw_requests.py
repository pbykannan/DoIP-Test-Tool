import threading
import unittest
from unittest import mock

from doip_tester.config.models import RawRequestStep
from doip_tester.flash.transfer import FlashFlowState, _run_raw_requests, _send_raw_uds_request
from udsoncan import Request


class _SuppressCtx:
    def __init__(self, client: mock.Mock) -> None:
        self._client = client

    def __enter__(self) -> None:
        self._client._suppress_entered = True

    def __exit__(self, *args) -> None:
        self._client._suppress_entered = False


class TestSendRawUdsRequest(unittest.TestCase):
    def test_suppress_waits_for_nrc(self) -> None:
        client = mock.Mock()
        ctx = _SuppressCtx(client)
        client.suppress_positive_response.return_value = ctx
        req = Request.from_payload(bytes.fromhex("288303"))

        _send_raw_uds_request(client, req)

        client.suppress_positive_response.assert_called_once_with(wait_nrc=True)
        client.send_request.assert_called_once_with(req)

    def test_non_suppress_sends_directly(self) -> None:
        client = mock.Mock()
        req = Request.from_payload(bytes.fromhex("22F189"))

        _send_raw_uds_request(client, req)

        client.suppress_positive_response.assert_not_called()
        client.send_request.assert_called_once_with(req)


class TestRunRawRequestsSuppress(unittest.TestCase):
    def _run_steps(self, steps: list) -> mock.Mock:
        client = mock.Mock()
        client._suppress_entered = False
        client.suppress_positive_response.side_effect = lambda **kw: _SuppressCtx(client)
        doip = mock.Mock()
        doip._uds_target_logical_address = 0x0001
        conn = mock.Mock()
        conn._connection = doip
        client.conn = conn
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
        self.assertEqual(client.send_request.call_count, 2)
        client.suppress_positive_response.assert_called_once_with(wait_nrc=True)

    def test_only_non_suppress_skips_context(self) -> None:
        client = self._run_steps(
            [RawRequestStep(payload=bytes.fromhex("22F189"), addressing="physical")]
        )
        client.suppress_positive_response.assert_not_called()
        client.send_request.assert_called_once()


if __name__ == "__main__":
    unittest.main()
