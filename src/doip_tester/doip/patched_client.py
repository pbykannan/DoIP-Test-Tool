"""DoIPClient with configurable connect/read timeouts and UDS target logical address."""

import logging
import socket
import time
from collections import deque
from typing import Callable, List, Optional

from doipclient import DoIPClient
from doipclient.constants import A_PROCESSING_TIME
from doipclient.messages import (
    DiagnosticMessage,
    DiagnosticMessageNegativeAcknowledgement,
    DiagnosticMessagePositiveAcknowledgement,
)

logger = logging.getLogger("doipclient")

# 非阻塞读空 TCP 接收缓冲的最大迭代次数（防御性上限）
_MAX_DRAIN_ITERATIONS = 64


def _is_response_to(payload: bytes, request_payload: bytes) -> bool:
    """判断一个 UDS 帧是否为指定请求的响应。

    正响应：SID = 请求 SID + 0x40；负响应：0x7F + 请求 SID。
    TesterPresent 心跳（7E 3E）或上一次请求的迟到帧 SID 不匹配，返回 False。
    """
    if not payload or not request_payload:
        return False
    req_sid = request_payload[0]
    if payload[0] == ((req_sid + 0x40) & 0xFF):
        return True
    if payload[0] == 0x7F and len(payload) >= 2 and payload[1] == req_sid:
        return True
    return False


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
        log: Optional[Callable[[str], None]] = None,
        **kwargs,
    ):
        self._connect_timeout = float(connect_timeout)
        self._socket_read_timeout = float(socket_read_timeout)
        self._log_cb = log
        super().__init__(*args, **kwargs)
        if uds_target_logical_address is not None:
            self._uds_target_logical_address = int(uds_target_logical_address)
        else:
            self._uds_target_logical_address = self._ecu_logical_address
        # Cache UDS payloads that may arrive before DoIP ACK. (arrival_monotonic, payload)
        self._pending_diag_payloads = deque()
        # 最近一次 DoIP ACK 的 monotonic 时刻，用于计算后续 pending/响应相对 ACK 的延迟。
        self._last_ack_monotonic: Optional[float] = None
        self._prev_ack_monotonic: Optional[float] = None

    def _timing_log(self, msg: str) -> None:
        """输出到 GUI 日志回调（若配置了），同时落到 doipclient logger。"""
        if self._log_cb is not None:
            try:
                self._log_cb(msg)
            except Exception:
                pass
        logger.info(msg)

    @staticmethod
    def _classify_uds(payload: bytes) -> str:
        if not payload:
            return "空帧"
        if payload[0] == 0x7F:
            if len(payload) >= 3 and payload[2] == 0x78:
                return "pending(NRC78)"
            return "负响应"
        return "正响应"

    def _ms_since_ack(self) -> float:
        if self._last_ack_monotonic is None:
            return 0.0
        return (time.monotonic() - self._last_ack_monotonic) * 1000.0

    def _record_ack(self, request_payload: bytes) -> None:
        """记录 DoIP ACK 到达时刻，并标注（便于与 Wireshark 对照）。"""
        mono = time.monotonic()
        wall = time.localtime(time.time())
        prev = self._prev_ack_monotonic
        interval_ms = (mono - prev) * 1000.0 if prev is not None else 0.0
        self._last_ack_monotonic = mono
        self._prev_ack_monotonic = mono
        sid = bytes(request_payload)[0] if request_payload else 0x00
        self._timing_log(
            "DoIP ACK @ %s (SID 0x%02X, 距上个 ACK %.1f ms)"
            % (time.strftime("%H:%M:%S", wall), sid, interval_ms)
        )

    def _log_frame_vs_ack(
        self, what: str, payload: bytes, arrived_mono: Optional[float] = None
    ) -> None:
        """UDS pending/响应 相对最近 ACK 的差值（即使帧在 ACK 前到达也如实标注负值）。"""
        ack = self._last_ack_monotonic
        sid = payload[0] if payload else 0
        if ack is None:
            self._timing_log("UDS %s (SID 0x%02X) 收到（无 ACK 参考时间）" % (what, sid))
            return
        ref = arrived_mono if arrived_mono is not None else time.monotonic()
        delta_ms = (ref - ack) * 1000.0
        self._timing_log(
            "UDS %s (SID 0x%02X) 于 ACK 后 %.1f ms 收到" % (what, sid, delta_ms)
        )

    def _log_uds_timeout(self) -> None:
        self._timing_log(
            "UDS 响应等待超时（当前距最近 ACK %.1f ms）" % self._ms_since_ack()
        )

    def _log_drained_late(self, drained_bytes: int, frames: List[bytes]) -> None:
        """上次请求超时后迟到的残留帧：即使已判超时，也补记相对 ACK 的差值。"""
        delta_ms = self._ms_since_ack()
        if frames:
            for p in frames:
                sid = p[0] if p else 0
                self._timing_log(
                    "残留迟到帧: UDS %s (SID 0x%02X, %d bytes) 于 ACK 后 %.1f ms 才到"
                    % (self._classify_uds(p), sid, len(p), delta_ms)
                )
        else:
            self._timing_log(
                "残留排空: %d bytes（半帧/非诊断帧）于 ACK 后 %.1f ms 才到"
                % (drained_bytes, delta_ms)
            )

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

    def _drain_tcp_socket(self) -> None:
        """
        非阻塞读空 TCP 接收缓冲区里已到达但尚未读取的残留数据（上次请求的迟到帧/半帧），
        喂给 parser 后由调用方 reset 丢弃。不阻塞等待新数据。
        若其中含完整 UDS 帧（上次请求超时后才到），补记相对最近 ACK 的差值。
        """
        sock = getattr(self, "_tcp_sock", None)
        if sock is None:
            return
        try:
            prev = sock.gettimeout()
        except OSError:  # socket 已关闭
            return
        drained_bytes = 0
        late_frames: List[bytes] = []
        try:
            sock.settimeout(0)
            for _ in range(_MAX_DRAIN_ITERATIONS):
                try:
                    data = sock.recv(4096)
                except (BlockingIOError, socket.timeout, ConnectionResetError, BrokenPipeError):
                    break
                except OSError:
                    break
                if not data:
                    break
                drained_bytes += len(data)
                self._tcp_parser.push_bytes(data)
                # 从 parser 提取本次到达的完整 DoIP 帧；半帧数据随后由 empty_rxqueue reset 丢弃
                while True:
                    msg = self._tcp_parser.read_message(b"")
                    if msg is None:
                        break
                    if type(msg) == DiagnosticMessage:
                        late_frames.append(bytes(msg.user_data))
        finally:
            try:
                sock.settimeout(prev)
            except OSError:
                pass
        if drained_bytes > 0:
            self._log_drained_late(drained_bytes, late_frames)

    def empty_rxqueue(self):
        """udsoncan 每次发送请求前调用：丢弃所有残留 PDU，防止旧响应串台。

        残留来源有三处，缺一不可：
        - ``_pending_diag_payloads``：上个请求 send 等 ACK 期间已缓存进来的完整 UDS 帧；
        - TCP socket 接收缓冲区：上个请求超时后才到达、尚未被 recv 的迟到帧；
        - ``_tcp_parser.rx_buffer``：迟到的半帧/多帧粘包残留。
        这些都是"当前请求"的响应（当前请求尚未发送），必须全部清空，
        否则 wait_frame 会先读到旧响应造成 service ID 串台。
        """
        self._pending_diag_payloads.clear()
        self._drain_tcp_socket()
        self._tcp_parser.reset()
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
                sid = bytes(diagnostic_payload)[0] if diagnostic_payload else 0
                self._timing_log(
                    "等待 DoIP ACK 超时 (SID 0x%02X): %.1f ms" % (sid, elapsed_time * 1000.0)
                )
                raise TimeoutError("Timed out waiting for diagnostic response")
            result = self.read_doip(timeout=(timeout - elapsed_time) if timeout else None)
            if type(result) == DiagnosticMessageNegativeAcknowledgement:
                self._timing_log(
                    "DoIP ACK = NegativeAcknowledgement (NACK code %s)" % result.nack_code
                )
                raise IOError(
                    "Diagnostic request rejected with negative acknowledge code: {}".format(
                        result.nack_code
                    )
                )
            elif type(result) == DiagnosticMessagePositiveAcknowledgement:
                self._record_ack(bytes(diagnostic_payload))
                return
            elif type(result) == DiagnosticMessage:
                uds_payload = bytes(result.user_data)
                # 只缓存本次请求的响应（正/负响应 SID 匹配）；其余为上一次请求的
                # 迟到帧或 TesterPresent 心跳，直接丢弃，避免被下一次 wait_frame 误取。
                if _is_response_to(uds_payload, bytes(diagnostic_payload)):
                    self._pending_diag_payloads.append((time.monotonic(), uds_payload))
                else:
                    logger.warning(
                        "Dropping stale UDS frame not matching current request: %s",
                        uds_payload.hex(),
                    )

    def receive_diagnostic(self, timeout=None):
        if self._pending_diag_payloads:
            arrived_mono, payload = self._pending_diag_payloads.popleft()
            self._log_frame_vs_ack(self._classify_uds(payload), payload, arrived_mono)
            return payload
        start_time = time.time()
        while True:
            elapsed_time = time.time() - start_time
            if timeout and elapsed_time > timeout:
                self._log_uds_timeout()
                raise TimeoutError("Timed out waiting for diagnostic response")
            try:
                result = self.read_doip(
                    timeout=(timeout - elapsed_time) if timeout else None
                )
            except TimeoutError:
                self._log_uds_timeout()
                raise
            if type(result) == DiagnosticMessage:
                payload = bytes(result.user_data)
                self._log_frame_vs_ack(self._classify_uds(payload), payload)
                return payload
