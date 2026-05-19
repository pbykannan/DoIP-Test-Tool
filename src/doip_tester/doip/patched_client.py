"""DoIPClient with configurable connect/read timeouts and UDS target logical address."""

import socket
import time
from collections import deque

from doipclient import DoIPClient
from doipclient.constants import A_PROCESSING_TIME
from doipclient.messages import (
    DiagnosticMessage,
    DiagnosticMessageNegativeAcknowledgement,
    DiagnosticMessagePositiveAcknowledgement,
)


class DoIPClientPatched(DoIPClient):
    """
    - read_doip default timeout raised for slow routing activation.
    - send_diagnostic targets uds_target_logical_address (physical=ECU, functional=group LA).
    """

    def __init__(
        self,
        *args,
        connect_timeout: float = 3.0,
        socket_read_timeout: float = 2.0,
        uds_target_logical_address=None,
        **kwargs,
    ):
        self._connect_timeout = float(connect_timeout)
        self._socket_read_timeout = float(socket_read_timeout)
        super().__init__(*args, **kwargs)
        if uds_target_logical_address is not None:
            self._uds_target_logical_address = int(uds_target_logical_address)
        else:
            self._uds_target_logical_address = self._ecu_logical_address
        # Cache UDS payloads that may arrive before DoIP ACK.
        self._pending_diag_payloads = deque()

    def _connect(self):
        """
        Override base _connect to apply an explicit TCP connect timeout.
        Upstream doipclient uses blocking connect() with OS timeout, which can
        freeze "连接中…" for a long time when ECU IP is unreachable.
        """
        self._tcp_sock = socket.socket(self._address_family, socket.SOCK_STREAM)
        self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self._tcp_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        if self._client_ip_address is not None:
            self._tcp_sock.bind((self._client_ip_address, 0))

        self._tcp_sock.settimeout(self._connect_timeout)
        self._tcp_sock.connect((self._ecu_ip_address, self._tcp_port))

        # keep library's normal runtime read timeout behavior for TCP parser loop
        self._tcp_sock.settimeout(A_PROCESSING_TIME)
        self._tcp_close_detected = False

        self._udp_sock = socket.socket(self._address_family, socket.SOCK_DGRAM)
        self._udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp_sock.settimeout(A_PROCESSING_TIME)
        if self._client_ip_address is not None:
            self._udp_sock.bind((self._client_ip_address, 0))

        if self._use_secure:
            # Reuse upstream helper, preserving original TLS behavior
            import ssl

            if isinstance(self._use_secure, ssl.SSLContext):
                ssl_context = self._use_secure
            else:
                ssl_context = ssl.create_default_context()
            self._wrap_socket(ssl_context)

    def empty_rxqueue(self):
        """udsoncan 每请求开头调用：只移除队列里 TesterPresent NRC（7F 3E xx），不把其它 PDU 整体丢弃。"""
        dq = self._pending_diag_payloads
        if not dq:
            return super().empty_rxqueue()
        kept = deque()
        while dq:
            item = dq.popleft()
            if (
                isinstance(item, (bytes, bytearray))
                and len(item) >= 2
                and item[0] == 0x7F
                and item[1] == 0x3E
            ):
                continue
            kept.append(bytes(item))
        self._pending_diag_payloads = kept
        super().empty_rxqueue()

    def read_doip(self, timeout=None, transport=DoIPClient.TransportType.TRANSPORT_TCP):
        if timeout is None:
            timeout = self._socket_read_timeout
        try:
            return super().read_doip(timeout=timeout, transport=transport)
        except TimeoutError as exc:
            if getattr(self, "_tcp_close_detected", False):
                raise TimeoutError(
                    str(exc)
                    + " （对端在未回复 DoIP 的情况下关闭了 TCP；Wireshark 常见：有 Routing activation request，"
                    "无 Routing activation response，随后 FIN）"
                ) from exc
            raise

    def send_diagnostic(self, diagnostic_payload, timeout=None):
        if timeout is None:
            timeout = self._socket_read_timeout
        return self.send_diagnostic_to_address(
            self._uds_target_logical_address,
            diagnostic_payload,
            timeout,
        )

    def send_diagnostic_to_address(
        self, address, diagnostic_payload, timeout=A_PROCESSING_TIME
    ):
        # Upstream drops early DiagnosticMessage while waiting DoIP ACK.
        # Cache those payloads so receive_diagnostic can return them later.
        message = DiagnosticMessage(
            self._client_logical_address, address, diagnostic_payload
        )
        self.send_doip_message(message)
        start_time = time.time()
        while True:
            elapsed_time = time.time() - start_time
            if timeout and elapsed_time > timeout:
                raise TimeoutError("Timed out waiting for diagnostic response")
            result = self.read_doip(timeout=(timeout - elapsed_time) if timeout else None)
            if type(result) == DiagnosticMessageNegativeAcknowledgement:
                raise IOError(
                    "Diagnostic request rejected with negative acknowledge code: {}".format(
                        result.nack_code
                    )
                )
            elif type(result) == DiagnosticMessagePositiveAcknowledgement:
                return
            elif type(result) == DiagnosticMessage:
                self._pending_diag_payloads.append(bytes(result.user_data))

    def receive_diagnostic(self, timeout=None):
        if self._pending_diag_payloads:
            return self._pending_diag_payloads.popleft()
        start_time = time.time()
        while True:
            elapsed_time = time.time() - start_time
            if timeout and elapsed_time > timeout:
                raise TimeoutError("Timed out waiting for diagnostic response")
            result = self.read_doip(timeout=(timeout - elapsed_time) if timeout else None)
            if type(result) == DiagnosticMessage:
                return result.user_data
