"""Wrap DoIP–UDS connector to log each UDS payload with logical traffic direction (IP)."""

from __future__ import annotations

import binascii
from typing import Callable, Optional

from doipclient.connectors import DoIPClientUDSConnector

LogFn = Callable[[str], None]

# 超过此长度不再输出完整 hex，避免 TransferData 大块刷写时生成数百万字符拖死 Tk 日志与 UI
_MAX_FULL_HEX_PAYLOAD = 512


class LoggingDoIPClientUDSConnector(DoIPClientUDSConnector):
    """
    Logs lines like:
      TX src ip: 192.168.1.10, dst ip: 192.168.1.43, uds: 1001
      RX src ip: 192.168.1.43, dst ip: 192.168.1.10, uds: 5001
    """

    def __init__(
        self,
        doip_layer,
        ecu_ip: str,
        log: LogFn,
        name: Optional[str] = None,
        close_connection: bool = False,
    ):
        super().__init__(doip_layer, name=name, close_connection=close_connection)
        self._ecu_ip = (ecu_ip or "").strip() or "?"
        self._log = log

    def _local_ip(self) -> str:
        conn = self._connection
        sock = getattr(conn, "_tcp_sock", None)
        if sock is not None:
            try:
                addr = sock.getsockname()
                if addr and len(addr) >= 1:
                    return str(addr[0])
            except OSError:
                pass
        return "?"

    @staticmethod
    def _uds_hex(payload) -> str:
        b = bytes(payload)
        n = len(b)
        if n <= _MAX_FULL_HEX_PAYLOAD:
            return binascii.hexlify(b).decode("ascii")
        sid = b[0]
        if sid == 0x36 and n >= 2:
            return "36 %02x + %d byte(s) data (hex omitted)" % (b[1], n - 2)
        if sid == 0x76 and n >= 2:
            return "76 %02x + %d byte(s) (hex omitted)" % (b[1], n - 2)
        return "%02x ... %d byte(s) total (hex omitted)" % (sid, n)

    def specific_send(self, payload) -> None:
        src = self._local_ip()
        dst = self._ecu_ip
        self._log(
            "TX src ip: %s, dst ip: %s, uds: %s" % (src, dst, self._uds_hex(payload))
        )
        super().specific_send(payload)

    def specific_wait_frame(self, timeout=2):
        data = super().specific_wait_frame(timeout=timeout)
        self._log(
            "RX src ip: %s, dst ip: %s, uds: %s"
            % (self._ecu_ip, self._local_ip(), self._uds_hex(data))
        )
        return data
