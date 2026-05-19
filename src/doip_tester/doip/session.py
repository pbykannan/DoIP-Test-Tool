import logging
import re
from typing import Callable, Optional

from doipclient.messages import RoutingActivationRequest

from doip_tester.config.models import AppConfig
from doip_tester.doip.patched_client import DoIPClientPatched

LogFn = Callable[[str], None]


def _activation_type_from_config(name):
    at = RoutingActivationRequest.ActivationType
    if isinstance(name, int):
        return at(name)
    mapping = {
        "Default": at.Default,
        "DiagnosticRequiredByRegulation": at.DiagnosticRequiredByRegulation,
        "CentralSecurity": at.CentralSecurity,
        "0": at.Default,
        "1": at.DiagnosticRequiredByRegulation,
        "225": at.CentralSecurity,
        "0xE1": at.CentralSecurity,
    }
    key = name.strip() if isinstance(name, str) else str(name)
    if key in mapping:
        return mapping[key]
    try:
        return at[key]
    except KeyError as exc:
        raise ValueError("Unknown activation_type: %r" % (name,)) from exc


# ISO 13400-2 Table 19 — generic header negative acknowledge
_GENERIC_NACK_HINTS = {
    0: "IncorrectPatternFormat：常因协议版本（试将 doip.protocol_version 改为 3）或 对端非标准 DoIP/端口被占用。",
    1: "UnknownPayloadType：对端不支持该报文类型。",
    2: "MessageTooLarge。",
    3: "OutOfMemory。",
    4: "InvalidPayloadLength。",
}


def _enrich_timeout_error(exc: BaseException, cfg: Optional[AppConfig] = None) -> str:
    msg = (
        str(exc)
        + " 【路由激活/读 DoIP 超时】doipclient 默认约 2s；"
        "可在配置 doip.socket_read_timeout 增大（如 15～30）；"
        "并确认「本机 IP」与 ECU 同网段、server_logical_address 正确。"
    )
    if cfg is None:
        return msg
    d, host = cfg.doip, (cfg.network.host or "").strip()
    if d.server_logical_address == 0x0001 or d.client_logical_address == 0x0E00:
        msg += (
            " 【逻辑地址】对接 DOIP_UDS x86 台架时：server 通常为 ECU 的 **0x002B (43)**（勿用 0x0001）；"
            "client 须在服务端允许列表内，常用 **0x0E80 (3712)**（不是 0x0E00）。"
            "若仍显示旧值，请检查 exe 旁 **project_configs\\\\qirui.yaml** 是否为旧模板（可删除该文件后重开 exe 从内置模板重建，或点「YAML→表单」从仓库新 yaml 粘贴）。"
        )
    elif host.startswith("192.168.118.") and (
        d.server_logical_address != 0x002B or d.client_logical_address not in (0x0E80, 0x0F10, 0x002B, 0x000E)
    ):
        msg += (
            " 【逻辑地址】当前访问 192.168.118.x 台架时，请与服务端 **source_logic_address / target_logic_address** 对齐（见 docs/ALIGNMENT.md §6.2）。"
        )
    elif (
        d.server_logical_address == 0x002B
        and d.client_logical_address == 0x0E80
        and "对端在未回复" not in str(exc)
    ):
        msg += (
            " 【若逻辑地址已对齐仍失败】多为服务端未发 RoutingActivationResponse（查 DOIP_UDS 日志/配置、"
            "与 C 参考客户端对比同一条 Routing activation 十六进制）。增大 socket_read_timeout 不能解决「对端直接 FIN」。"
        )
    return msg


def _enrich_doip_error(exc: BaseException) -> str:
    s = str(exc)
    m = re.search(r"NACK Code:\s*(\d+)", s)
    if not m:
        return (
            s
            + " 提示：检查「本机 IP」是否与访问 ECU 的网卡一致；"
            "169.254.* 多为 APIPA，尽量选与 ECU 同网段的地址。"
        )
    code = int(m.group(1))
    hint = _GENERIC_NACK_HINTS.get(code, "")
    extra = (
        " 提示：确认13400为明文DoIP（非TLS 3496）；核对 ECU 逻辑地址；"
        "同网段绑定「本机 IP」。"
    )
    return "%s 【%s】%s" % (s, hint, extra)


class DoIPSession:
    """Wraps doipclient.DoIPClient: TCP connect + routing activation (unless disabled)."""

    def __init__(self, cfg: AppConfig, log: Optional[LogFn] = None):
        self._cfg = cfg
        self._log = log or (lambda m: None)
        self._client: Optional[DoIPClientPatched] = None
        logging.getLogger("doipclient").setLevel(logging.WARNING)

    @property
    def client(self) -> "DoIPClientPatched":
        if self._client is None:
            raise RuntimeError("DoIP session is not connected")
        return self._client

    def connect(self) -> None:
        self.close()
        n = self._cfg.network
        d = self._cfg.doip
        act = None
        if not d.activation_disabled:
            act = _activation_type_from_config(d.activation_type)
        sock_to = (
            float(d.socket_read_timeout)
            if d.socket_read_timeout is not None
            else 10.0
        )
        # 坏 IP 时不要被 OS 默认 connect 超时卡住太久；读超时仍按 socket_read_timeout
        connect_to = max(1.0, min(sock_to, 3.0))
        # doipclient sends 7-byte RoutingActivationRequest when vm_specific is None (!HBL),
        # and 11-byte when set (!HBLL). OEM stacks (e.g. CICVD expecting payload length 0x0B)
        # often require the 11-byte form — use 0 for trailing DWORD instead of omitting it.
        vm_eff = d.vm_specific if d.vm_specific is not None else 0
        uds_tgt = (
            int(d.functional_logical_address)
            if d.uds_addressing == "functional"
            else None
        )
        self._log(
            "DoIP connecting to %s:%s logical_address=0x%04X client=0x%04X proto=0x%02X "
            "connect_timeout=%ss read_timeout=%ss bind_ip=%s vm_specific=0x%08X"
            % (
                n.host,
                n.tcp_port,
                d.server_logical_address,
                d.client_logical_address,
                d.protocol_version,
                connect_to,
                sock_to,
                n.client_bind_ip or "(auto)",
                vm_eff,
            )
        )
        try:
            self._client = DoIPClientPatched(
                ecu_ip_address=n.host,
                ecu_logical_address=d.server_logical_address,
                tcp_port=n.tcp_port,
                udp_port=n.udp_port,
                activation_type=act,
                protocol_version=d.protocol_version,
                client_logical_address=d.client_logical_address,
                client_ip_address=n.client_bind_ip,
                vm_specific=vm_eff,
                connect_timeout=connect_to,
                socket_read_timeout=sock_to,
                uds_target_logical_address=uds_tgt,
            )
        except IOError as exc:
            raise ConnectionError(_enrich_doip_error(exc)) from exc
        except TimeoutError as exc:
            raise ConnectionError(_enrich_timeout_error(exc, self._cfg)) from exc
        self._log("DoIP routing activation OK")
        self._log(
            "UDS 寻址: %s，DoIP DiagnosticMessage 目标逻辑地址=0x%04X"
            % (d.uds_addressing, self._client._uds_target_logical_address)
        )

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception as exc:
                self._log("DoIP close: %s" % exc)
            self._client = None

    def __enter__(self) -> "DoIPSession":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
