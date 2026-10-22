from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _uds_secret_key_16(field: str, raw: Any) -> Optional[bytes]:
    """Parse optional 16-byte secret from YAML (hex string); empty/absent -> None."""
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        b = bytes(raw)
    else:
        s = str(raw).strip()
        if not s:
            return None
        b = bytes.fromhex(s.replace(" ", "").replace("0x", "").replace("0X", ""))
    if len(b) != 16:
        raise ValueError(
            "uds.%s must be exactly 16 bytes (32 hex characters), got %d bytes"
            % (field, len(b))
        )
    return b


# DoIP 发现方式：known_ip=已知 IP 直连；broadcast=UDP 广播；multicast=UDP 组播
DISCOVERY_MODES = ("known_ip", "broadcast", "multicast")
DEFAULT_MULTICAST_ADDRESS = "239.2.0.1"


@dataclass
class NetworkConfig:
    host: str
    tcp_port: int = 13400
    udp_port: int = 13400
    client_bind_ip: Optional[str] = None
    # known_ip | broadcast | multicast；默认 known_ip 保持与改造前一致
    discovery_mode: str = "known_ip"
    # IPv4 组播组地址；仅 discovery_mode=multicast 时使用
    multicast_address: str = DEFAULT_MULTICAST_ADDRESS


@dataclass
class DoipConfig:
    # 与当前默认项目模板一致（奇瑞/x86、N80）：Tester 0x0E80，ECU 0x002B
    client_logical_address: int = 0x0E80
    server_logical_address: int = 0x002B
    protocol_version: int = 3  # DoIP header byte 0x03 (ISO 13400-2:2019)；旧 ECU 仅支持 0x02 时再改为 2
    activation_type: str = "Default"
    activation_disabled: bool = False
    vm_specific: Optional[int] = None
    # doipclient 单次读超时（路由激活等），默认 2s 易超时，慢网关可设 10～30
    socket_read_timeout: Optional[float] = None
    # UDS 诊断报文在 DoIP DiagnosticMessage 中的目标逻辑地址：物理=ECU(server)，功能=组地址
    uds_addressing: str = "physical"  # physical | functional
    functional_logical_address: int = 0xE400


@dataclass
class UdsConfig:
    request_timeout: float = 5.0
    p2_timeout: float = 1.0
    p2_star_timeout: float = 5.0
    # True=采用 ECU 在 10 会话响应里宣告的 P2/P2*（ISO 标准行为）；False=一律用上面配置的 p2_timeout/p2_star_timeout
    use_server_timing: bool = True
    server_address_format: Optional[int] = None
    server_memorysize_format: Optional[int] = None
    # 0x27 SecurityAccess（AES-128-CMAC）：level 0x01 / 0x11 各一把；不配则用代码内参考默认值
    security_key_level1: Optional[bytes] = None
    security_key_level3: Optional[bytes] = None
    # 27 算法族：cmac-chery（奇瑞 v116：key=CMAC(secret, seed)）| baic-df-token（北汽 v2.0：
    # SK=CMAC(Key, DF)，Token=CMAC(SK, seed)，27 02 上传 DF||Token 32 字节）
    security_algorithm: str = "cmac-chery"


@dataclass
class DiagnosticsConfig:
    dids: List[int] = field(default_factory=list)
    dtc_status_mask: int = 0xFF
    service_presets: List["ServicePreset"] = field(default_factory=list)


@dataclass
class ServicePresetItem:
    request: bytes
    comment: str = ""


@dataclass
class ServicePreset:
    sid: int
    items: List[ServicePresetItem] = field(default_factory=list)


@dataclass
class RoutineStep:
    routine_id: int
    control_type: int
    data: bytes = field(default_factory=bytes)


@dataclass
class RawRequestStep:
    payload: bytes
    addressing: str = "physical"  # physical | functional


@dataclass
class FlashConfig:
    memory_address: int = 0
    address_format: int = 32
    memorysize_format: int = 32
    override_block_payload: Optional[int] = None
    # 34 正答后、首包 36 前等待（秒）；null 用代码默认 0.35s
    post_request_download_delay_sec: Optional[float] = None
    # L1(27 02) 成功后、解 L3(27 11) 前等待（秒）；null 用代码默认 0.35s
    security_l1_to_l3_delay_sec: Optional[float] = None
    transfer_exit_data: Optional[bytes] = None
    # 刷写前的原始 UDS 请求（hex），按顺序执行；可用于 10 83 / 85 82 / 28 83 等 OEM 步骤
    pre_transfer_raw_requests: List[RawRequestStep] = field(default_factory=list)
    pre_transfer_routines: List[RoutineStep] = field(default_factory=list)
    # 可选：刷写前写入指纹 DID（常见 0xF184）
    fingerprint_did: Optional[int] = None
    fingerprint_data: Optional[bytes] = None
    # 刷写后验签/后处理（ECU 仍在线、未复位）
    post_transfer_routines: List[RoutineStep] = field(default_factory=list)
    # 后编程例程与重连之间的原始 UDS（可为空；DD03 后 ECU 自动复位时通常不发 11 01）
    post_transfer_raw_requests: List[RawRequestStep] = field(default_factory=list)
    # ECU 复位后等待秒数再起新 TCP（仅当配置了 post_transfer_after_reconnect_* 时使用）
    post_transfer_reconnect_delay_sec: Optional[float] = None
    # 复位重连后继续执行的原始请求（1003 / 14 / 85 / 1081 等）
    post_transfer_after_reconnect_raw_requests: List[RawRequestStep] = field(
        default_factory=list
    )
    # 覆盖刷写内置默认会话顺序；留空则 transfer 内默认为 extended→programming
    diagnostic_sessions_before_download: List[str] = field(default_factory=list)
    # 覆盖刷写内置默认解锁级别；留空则 transfer 内默认为 L3（[0x11]）
    security_access_levels_before_download: List[int] = field(default_factory=list)
    # 34 RequestDownload 前确保的安全级别；null 用代码默认 0x01（v116 用 L1，北汽 v515 用 L3）
    transfer_security_level: Optional[int] = None
    # 数据传输结束后、后处理前重申会话：
    # default_extended_programming（默认，奇瑞 v116：01→03→02）
    # | none（北汽 N80/335 图8：37 后保持 programming，直接 checkMemory）
    # | programming | extended_programming
    post_transfer_session_reassert: str = "default_extended_programming"


@dataclass
class AppConfig:
    network: NetworkConfig
    doip: DoipConfig
    uds: UdsConfig
    diagnostics: DiagnosticsConfig
    flash: FlashConfig

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "AppConfig":
        n = data.get("network") or {}
        d = data.get("doip") or {}
        u = data.get("uds") or {}
        diag = data.get("diagnostics") or {}
        fl = data.get("flash") or {}

        def _parse_routines_field(field_name: str) -> List[RoutineStep]:
            raw_steps = fl.get(field_name) or []
            if not isinstance(raw_steps, list):
                raise ValueError("flash.%s must be a YAML list" % field_name)
            parsed: List[RoutineStep] = []
            for item in raw_steps:
                rid = int(item["routine_id"])
                ct = int(item["control_type"])
                raw = item.get("data")
                b = bytes()
                if isinstance(raw, str) and raw.strip():
                    b = bytes.fromhex(raw.replace(" ", "").replace("0x", ""))
                elif isinstance(raw, (bytes, bytearray)):
                    b = bytes(raw)
                parsed.append(RoutineStep(routine_id=rid, control_type=ct, data=b))
            return parsed

        routines = _parse_routines_field("pre_transfer_routines")
        post_routines = _parse_routines_field("post_transfer_routines")

        def _parse_raw_request_list(field_name: str) -> List[RawRequestStep]:
            raw_list = fl.get(field_name) or []
            if not isinstance(raw_list, list):
                raise ValueError("flash.%s must be a YAML list" % field_name)
            out: List[RawRequestStep] = []
            for item in raw_list:
                if isinstance(item, (bytes, bytearray)):
                    out.append(RawRequestStep(payload=bytes(item), addressing="physical"))
                    continue
                if isinstance(item, dict):
                    raw_payload = item.get("payload")
                    if raw_payload is None:
                        raw_payload = item.get("data")
                    s = str(raw_payload or "").strip()
                    if not s:
                        continue
                    addr = str(item.get("addressing", "physical")).strip().lower()
                    if addr not in ("physical", "functional"):
                        raise ValueError(
                            "flash.%s item.addressing must be 'physical' or 'functional'"
                            % field_name
                        )
                    out.append(
                        RawRequestStep(
                            payload=bytes.fromhex(
                                s.replace(" ", "").replace("0x", "").replace("0X", "")
                            ),
                            addressing=addr,
                        )
                    )
                    continue
                s = str(item).strip()
                if not s:
                    continue
                out.append(
                    RawRequestStep(
                        payload=bytes.fromhex(
                            s.replace(" ", "").replace("0x", "").replace("0X", "")
                        ),
                        addressing="physical",
                    )
                )
            return out

        pre_raw_requests = _parse_raw_request_list("pre_transfer_raw_requests")
        post_raw_requests = _parse_raw_request_list("post_transfer_raw_requests")
        post_after_re_raw = _parse_raw_request_list(
            "post_transfer_after_reconnect_raw_requests"
        )
        _re_dly = fl.get("post_transfer_reconnect_delay_sec")
        post_reconnect_delay: Optional[float] = (
            float(_re_dly) if _re_dly is not None else None
        )

        def _parse_service_presets() -> List[ServicePreset]:
            raw = diag.get("service_presets") or []
            if not isinstance(raw, list):
                raise ValueError("diagnostics.service_presets must be a YAML list")
            out: List[ServicePreset] = []
            sid_seen = set()
            for svc in raw:
                if not isinstance(svc, dict):
                    raise ValueError(
                        "diagnostics.service_presets items must be mappings"
                    )
                sid = int(svc.get("sid"))
                if sid < 0 or sid > 0xFF:
                    raise ValueError("diagnostics.service_presets[].sid out of range")
                if sid in sid_seen:
                    raise ValueError(
                        "diagnostics.service_presets contains duplicate sid=0x%02X" % sid
                    )
                sid_seen.add(sid)
                raw_items = svc.get("items") or []
                if not isinstance(raw_items, list):
                    raise ValueError(
                        "diagnostics.service_presets[].items must be a YAML list"
                    )
                items: List[ServicePresetItem] = []
                for it in raw_items:
                    if isinstance(it, dict):
                        req_raw = it.get("request")
                        req = bytes.fromhex(
                            str(req_raw or "")
                            .replace(" ", "")
                            .replace("0x", "")
                            .replace("0X", "")
                        )
                        cmt = str(it.get("comment") or "").strip()
                    else:
                        req = bytes.fromhex(
                            str(it).replace(" ", "").replace("0x", "").replace("0X", "")
                        )
                        cmt = ""
                    if not req:
                        continue
                    if req[0] != (sid & 0xFF):
                        raise ValueError(
                            "diagnostics.service_presets request SID mismatch: "
                            "sid=0x%02X request=%s"
                            % (sid & 0xFF, req.hex())
                        )
                    items.append(ServicePresetItem(request=req, comment=cmt))
                out.append(ServicePreset(sid=sid & 0xFF, items=items))
            return out

        _service_presets = _parse_service_presets()

        tex = fl.get("transfer_exit_data")
        exit_bytes: Optional[bytes] = None
        if isinstance(tex, str) and tex.strip():
            exit_bytes = bytes.fromhex(tex.replace(" ", "").replace("0x", ""))
        elif isinstance(tex, (bytes, bytearray)):
            exit_bytes = bytes(tex)

        fp_did = fl.get("fingerprint_did")
        fp_data_raw = fl.get("fingerprint_data")
        fp_data: Optional[bytes] = None
        if isinstance(fp_data_raw, str) and fp_data_raw.strip():
            fp_data = bytes.fromhex(fp_data_raw.replace(" ", "").replace("0x", ""))
        elif isinstance(fp_data_raw, (bytes, bytearray)):
            fp_data = bytes(fp_data_raw)

        _uds_addr = str(d.get("uds_addressing", "physical"))
        if _uds_addr not in ("physical", "functional"):
            raise ValueError("doip.uds_addressing must be 'physical' or 'functional'")

        _sess_list: List[str] = []
        _raw_seq = fl.get("diagnostic_sessions_before_download")
        _legacy_sess = fl.get("diagnostic_session_before_download")
        if _raw_seq is not None:
            if not isinstance(_raw_seq, list):
                raise ValueError(
                    "flash.diagnostic_sessions_before_download must be a YAML list"
                )
            for x in _raw_seq:
                s = str(x).strip().lower()
                if s not in ("programming", "extended"):
                    raise ValueError(
                        "flash.diagnostic_sessions_before_download items must be "
                        "'extended' or 'programming'"
                    )
                _sess_list.append(s)
        elif _legacy_sess is not None and str(_legacy_sess).strip():
            ls = str(_legacy_sess).strip().lower()
            if ls == "programming":
                _sess_list = ["extended", "programming"]
            elif ls == "extended":
                _sess_list = ["extended"]
            else:
                raise ValueError(
                    "flash.diagnostic_session_before_download must be "
                    "'programming' or 'extended' (deprecated; use "
                    "diagnostic_sessions_before_download list)"
                )

        _sec_levels: List[int] = []
        _raw_sec = fl.get("security_access_levels_before_download")
        if _raw_sec is not None:
            if not isinstance(_raw_sec, list):
                raise ValueError(
                    "flash.security_access_levels_before_download must be a YAML list"
                )
            for x in _raw_sec:
                _sec_levels.append(int(x))

        _discovery_mode = str(n.get("discovery_mode", "known_ip")).strip().lower()
        if _discovery_mode not in DISCOVERY_MODES:
            raise ValueError(
                "network.discovery_mode must be one of %s, got %r"
                % (DISCOVERY_MODES, _discovery_mode)
            )
        _mc_addr = str(n.get("multicast_address", DEFAULT_MULTICAST_ADDRESS) or DEFAULT_MULTICAST_ADDRESS).strip()
        if not _mc_addr:
            _mc_addr = DEFAULT_MULTICAST_ADDRESS

        return AppConfig(
            network=NetworkConfig(
                host=str(n["host"]),
                tcp_port=int(n.get("tcp_port", 13400)),
                udp_port=int(n.get("udp_port", 13400)),
                client_bind_ip=n.get("client_bind_ip"),
                discovery_mode=_discovery_mode,
                multicast_address=_mc_addr,
            ),
            doip=DoipConfig(
                client_logical_address=int(d.get("client_logical_address", 0x0E80)),
                server_logical_address=int(d.get("server_logical_address", 0x002B)),
                protocol_version=int(d.get("protocol_version", 3)),
                activation_type=str(d.get("activation_type", "Default")),
                activation_disabled=bool(d.get("activation_disabled", False)),
                vm_specific=(
                    int(d["vm_specific"]) if d.get("vm_specific") is not None else None
                ),
                socket_read_timeout=(
                    float(d["socket_read_timeout"])
                    if d.get("socket_read_timeout") is not None
                    else None
                ),
                uds_addressing=_uds_addr,
                functional_logical_address=int(
                    d.get("functional_logical_address", 0xE400)
                ),
            ),
            uds=UdsConfig(
                request_timeout=float(u.get("request_timeout", 5)),
                p2_timeout=float(u.get("p2_timeout", 1)),
                p2_star_timeout=float(u.get("p2_star_timeout", 5)),
                use_server_timing=bool(u.get("use_server_timing", True)),
                server_address_format=(
                    int(u["server_address_format"])
                    if u.get("server_address_format") is not None
                    else None
                ),
                server_memorysize_format=(
                    int(u["server_memorysize_format"])
                    if u.get("server_memorysize_format") is not None
                    else None
                ),
                security_key_level1=_uds_secret_key_16(
                    "security_key_level1", u.get("security_key_level1")
                ),
                security_key_level3=_uds_secret_key_16(
                    "security_key_level3", u.get("security_key_level3")
                ),
                security_algorithm=str(u.get("security_algorithm", "cmac-chery")),
            ),
            diagnostics=DiagnosticsConfig(
                dids=[int(x) for x in (diag.get("dids") or [])],
                dtc_status_mask=int(diag.get("dtc_status_mask", 0xFF)),
                service_presets=_service_presets,
            ),
            flash=FlashConfig(
                memory_address=int(fl.get("memory_address", 0)),
                address_format=int(fl.get("address_format", 32)),
                memorysize_format=int(fl.get("memorysize_format", 32)),
                override_block_payload=(
                    int(fl["override_block_payload"])
                    if fl.get("override_block_payload") is not None
                    else None
                ),
                post_request_download_delay_sec=(
                    float(fl["post_request_download_delay_sec"])
                    if fl.get("post_request_download_delay_sec") is not None
                    else None
                ),
                security_l1_to_l3_delay_sec=(
                    float(fl["security_l1_to_l3_delay_sec"])
                    if fl.get("security_l1_to_l3_delay_sec") is not None
                    else None
                ),
                transfer_exit_data=exit_bytes,
                pre_transfer_raw_requests=pre_raw_requests,
                pre_transfer_routines=routines,
                fingerprint_did=(int(fp_did) if fp_did is not None else None),
                fingerprint_data=fp_data,
                post_transfer_routines=post_routines,
                post_transfer_raw_requests=post_raw_requests,
                post_transfer_reconnect_delay_sec=post_reconnect_delay,
                post_transfer_after_reconnect_raw_requests=post_after_re_raw,
                diagnostic_sessions_before_download=_sess_list,
                security_access_levels_before_download=_sec_levels,
                transfer_security_level=(
                    int(fl["transfer_security_level"])
                    if fl.get("transfer_security_level") is not None
                    else None
                ),
                post_transfer_session_reassert=str(
                    fl.get(
                        "post_transfer_session_reassert",
                        "default_extended_programming",
                    )
                    or "default_extended_programming"
                ).strip().lower(),
            ),
        )
