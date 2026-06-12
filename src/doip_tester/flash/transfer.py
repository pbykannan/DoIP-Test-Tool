"""
刷写 34/36/37 与主机厂「预编程 / 编程」流程对齐要点（奇瑞 TBOX 对端 v116 等）：

- doip_callback.c：Programming(0x02) 仅能从 Extended(0x03) 或 Programming 进入；从 Default
  直切 Programming 会 NRC 0x7E。故典型顺序为 Extended →（扩展会话内 31/85/28 等）→ Programming。
  若对端会话编号为「0=default / 2=extended / 1=programming」则须在 **请求 10 02 前先有 03**；
  刷写结束前重新进编程会话时按 **Default(01) → Extended(03) → Programming(02)** 执行。
- DOIP_UDS examples/main-client.c 的 `full`：ext → prog → security → 再 38/34 等。

默认刷写前奏（配置里会话/解锁列表为空时自动采用）：
**Extended(0x03) → pre_transfer_routines → Programming(0x02) → SecurityAccess L1(0x01) → L3(0x11) → 0x34/36/37**。
对端要求从 lock 逐级解锁，**不可跳过 L1 直接 L3**；``flash.security_access_levels_before_download`` 若只写 ``0x11`` 也会自动补 ``0x01``。

顺序：
1. 第一个 extended；
2. pre_transfer_routines；
3. 其余会话（通常为 programming）；
4. 解锁；
5. RequestDownload → TransferData → RequestTransferExit。

可通过配置补齐 OEM 步骤：pre/post 原始 UDS、2E F184 指纹、post 例程（验签/后处理）。

后编程：**XML/ZIP 推导的 DD02** 早于 ``flash.post_transfer_routines``（如 FF01、DD03）执行，与同端流程一致时可保持此顺序。
"""

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
import re
import shutil
import tempfile
import zipfile
from typing import Callable, List, Optional, Sequence, Tuple

from udsoncan import Request, Response, services
from udsoncan.client import Client
from udsoncan.common.MemoryLocation import MemoryLocation
from udsoncan.exceptions import (
    InvalidResponseException,
    NegativeResponseException,
    TimeoutException,
    UnexpectedResponseException,
)

from doip_tester.config.models import AppConfig, RawRequestStep, RoutineStep

LogFn = Callable[[str], None]
ProgressFn = Callable[[int, int], None]
ReconnectAfterResetFn = Callable[[], Client]


@dataclass
class TransferItem:
    name: str
    path: Path
    size: int


@dataclass
class FlashFlowState:
    current_session: Optional[str] = None
    unlocked_levels: set = field(default_factory=set)
    active_security_level: Optional[int] = None


class FlashAborted(Exception):
    """User cancelled or worker stopped the transfer."""


TRANSFER_DATA_OVERHEAD = 2  # 0x36 + blockSequenceCounter per ISO-14229-1

# 未在 YAML 中指定时使用（奇瑞等对端：03→02→27 L3→34）
_DEFAULT_DIAGNOSTIC_SESSIONS_BEFORE_DOWNLOAD: List[str] = ["extended", "programming"]
_DEFAULT_SECURITY_LEVELS_BEFORE_DOWNLOAD: List[int] = [0x01, 0x11]  # L1 → L3，不可直跳 L3
_FLASH_SEC_L1 = 0x01
_FLASH_SEC_L3 = 0x11

# 对照 v116 config.xml：
# - session index 0/1/2 = default/programming/extended
# - security index 0/1/2 = 0x00 / 0x01 / 0x11
# 刷写流程中用到的 31 RID 约束（仅列我们当前链路会出现的）
_RID_REQUIRED_SESSION = {
    0x0203: "extended",    # CheckProgrammingPreconditions
    0xFF00: "programming", # EraseMemory
    0xFF01: "programming", # CheckProgrammingDependencies
    0xDD01: "programming", # StayInBoot
    0xDD02: "programming", # SecuritySignatureVerification
    0xDD03: "programming", # VersionInstallation
}

# 对照 v116 config.xml DID 访问约束（仅当前刷写链路）
# F184 写入：writeable_session_indexs=1(programming), writeable_security_indexs=2(0x11)
_DID_WRITE_REQUIREMENT = {
    0xF184: ("programming", 0x11),
}

# 刷写循环内周期性 3E（抑制正响应）；GUI 定时 TP 在 worker 持锁刷写时无法插队。
# TransferData 外：会话重申与安全访问之后由 _flash_tester_present_optional 再发 3E80，刷新 S3。
# 固定 2s 节拍（仅 34/36 循环内）。
_FLASH_KEEPALIVE_INTERVAL_SEC = 2.0
# 34 正答后 ECU 常需准备下载缓冲区；立即发 36 易 TCP/无 76。YAML 未配时用此默认值。
_POST_REQUEST_DOWNLOAD_DELAY_SEC = 0.35
# L1(27 02 成功) 后 ECU 常需间隔再收 L3(27 11)；YAML 未配时用此默认值。
_SECURITY_L1_TO_L3_DELAY_SEC = 0.35


def _delay_after_request_download(
    delay_sec: float, cancel: threading.Event, log: LogFn
) -> None:
    if delay_sec <= 0:
        return
    log("RequestDownload 后等待 %.2fs 再发 TransferData …" % delay_sec)
    deadline = time.monotonic() + delay_sec
    while True:
        if cancel.is_set():
            raise FlashAborted("cancelled")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.05, remaining))


def _delay_between_security_l1_and_l3(
    delay_sec: float,
    cancel: Optional[threading.Event],
    log: LogFn,
) -> None:
    if delay_sec <= 0:
        return
    log("SecurityAccess L1 解锁后等待 %.2fs 再解 L3 …" % delay_sec)
    deadline = time.monotonic() + delay_sec
    while True:
        if cancel is not None and cancel.is_set():
            raise FlashAborted("cancelled")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.05, remaining))


def _resolve_l1_to_l3_delay_sec(fl) -> float:
    v = getattr(fl, "security_l1_to_l3_delay_sec", None)
    if v is None:
        return _SECURITY_L1_TO_L3_DELAY_SEC
    return float(v)


def compute_transfer_payload_size(max_number_of_block_length: int) -> int:
    """Usable TransferData bytes from ECU maxNumberOfBlockLength (including UDS overhead)."""
    return max(1, int(max_number_of_block_length) - TRANSFER_DATA_OVERHEAD)


def _requeue_diag_payload_after_drain(doip_conn, payload: bytes) -> None:
    """把误读的 UDS 贴回 DoIP 层待读 deque，下一轮 wait_frame/receive_diagnostic 先取。"""
    if doip_conn is None or payload is None or not hasattr(
        doip_conn, "_pending_diag_payloads"
    ):
        return
    dq = getattr(doip_conn, "_pending_diag_payloads")
    dq.appendleft(bytes(payload))


def _uds_is_tester_present_negative(payload: bytes) -> bool:
    return len(payload) >= 2 and payload[0] == 0x7F and payload[1] == 0x3E


def _drain_late_responses_after_tester_present(
    client: Client,
    log: LogFn,
    max_total_sec: float = 0.35,
    slice_sec: float = 0.05,
) -> None:
    """
    刷写循环里在 36 块之间发 3E80 时，若对端回 7F 3E xx 较晚，可读尽以免串台。
    绝不能把其它 PDU（例如后续请求才该处理的 7F 37 78 / 76 xx）无脑丢掉，否则等价于丢弃 pending，
    send_request 会误判 P2 超时。
    """
    conn = getattr(client, "conn", None)
    if conn is None:
        return
    doip_conn = getattr(conn, "_connection", None)
    t0 = time.monotonic()
    drained_tp = 0
    while time.monotonic() - t0 < max_total_sec:
        try:
            recv_payload = conn.wait_frame(timeout=slice_sec, exception=True)
        except TimeoutException:
            break
        except Exception as exc:
            log("刷写保活: 排空迟到响应时出现异常（已停止排空）: %s" % exc)
            break
        if not recv_payload:
            continue
        if _uds_is_tester_present_negative(recv_payload):
            drained_tp += 1
            continue
        hex_preview = recv_payload[:24].hex()
        if len(recv_payload) > 24:
            hex_preview += "..."
        log(
            "刷写保活: 排空时读到非 TesterPresent PDU(%s)，已回填队列供后续 UDS 使用"
            % hex_preview
        )
        _requeue_diag_payload_after_drain(doip_conn, recv_payload)
        break
    if drained_tp:
        log(
            "刷写保活: 已丢弃 %d 条迟到的 TesterPresent NRC（7F 3E xx）再继续后续诊断"
            % drained_tp
        )


def _flash_tester_present_optional(client: Client, log: LogFn, detail: str) -> None:
    """
    TransferData 循环外也需刷新 S3：RequestTransferExit 后、会话重申与 27 之后若长时间无双工，
    部分 ECU 会掉会话或对后继 31 条件不一致。与同循环内一致的 3E80 + 排空迟到响应。
    """
    try:
        with client.suppress_positive_response(wait_nrc=True):
            client.tester_present()
        _drain_late_responses_after_tester_present(client, log)
        log("刷写: TesterPresent(3E 80) [%s]" % detail)
    except Exception as exc:
        log("刷写: TesterPresent [%s] 失败（继续流程）: %s" % (detail, exc))


def _apply_one_session(client: Client, mode: str, log: LogFn) -> str:
    m = mode.strip().lower()
    if m == "default":
        client.change_session(
            services.DiagnosticSessionControl.Session.defaultSession
        )
        log("DiagnosticSession: defaultSession (0x01)")
        return "default"
    elif m == "programming":
        client.change_session(
            services.DiagnosticSessionControl.Session.programmingSession
        )
        log("DiagnosticSession: programmingSession (0x02)")
        return "programming"
    elif m == "extended":
        client.change_session(
            services.DiagnosticSessionControl.Session.extendedDiagnosticSession
        )
        log("DiagnosticSession: extendedDiagnosticSession (0x03)")
        return "extended"
    else:
        raise ValueError("invalid session mode: %r" % mode)


def _ensure_session(client: Client, mode: str, log: LogFn, state: FlashFlowState) -> None:
    """Force switch to required session for guarded step."""
    if state.current_session == mode:
        return
    applied = _apply_one_session(client, mode, log)
    state.current_session = applied
    # 按常见 ECU 行为：切会话会使安全访问状态失效，避免误判“已解锁”。
    state.unlocked_levels.clear()
    state.active_security_level = None


def _ensure_programming_via_default_extended(
    client: Client, log: LogFn, state: FlashFlowState
) -> None:
    """
    v116/Chery：禁止 default 诊断会话后直接进 programming；
    须 default(会话 0) → extended(0x03, 配置里常为 index 2) → programming。
    """
    _ensure_session(client, "default", log, state)
    _ensure_session(client, "extended", log, state)
    _ensure_session(client, "programming", log, state)


def _normalize_flash_security_levels(levels: Sequence[int]) -> List[int]:
    """刷写 27：须 lock→L1→L3；含 L3 时保证 L1 在前且只出现一次。"""
    if not levels:
        return list(_DEFAULT_SECURITY_LEVELS_BEFORE_DOWNLOAD)
    out: List[int] = []
    seen: set[int] = set()
    for raw in levels:
        lvl = int(raw) & 0xFF
        if lvl in seen:
            continue
        out.append(lvl)
        seen.add(lvl)
    if _FLASH_SEC_L3 in seen and _FLASH_SEC_L1 not in seen:
        out.insert(out.index(_FLASH_SEC_L3), _FLASH_SEC_L1)
    elif _FLASH_SEC_L3 in seen and _FLASH_SEC_L1 in seen:
        if out.index(_FLASH_SEC_L1) > out.index(_FLASH_SEC_L3):
            out.remove(_FLASH_SEC_L1)
            out.insert(out.index(_FLASH_SEC_L3), _FLASH_SEC_L1)
    return out


def _unlock_security_level(
    client: Client, level: int, log: LogFn, state: FlashFlowState, reason: str
) -> None:
    lvl = int(level) & 0xFF
    log("SecurityAccess: unlock level=0x%02X（%s）" % (lvl, reason))
    client.unlock_security_access(lvl)
    state.unlocked_levels.add(lvl)
    state.active_security_level = lvl


def _ensure_security_level(
    client: Client,
    level: int,
    log: LogFn,
    state: FlashFlowState,
    reason: str,
    *,
    l1_to_l3_delay_sec: float = _SECURITY_L1_TO_L3_DELAY_SEC,
    cancel: Optional[threading.Event] = None,
) -> None:
    lvl = int(level) & 0xFF
    if state.active_security_level == lvl:
        return
    if lvl == _FLASH_SEC_L3:
        if state.active_security_level != _FLASH_SEC_L1:
            _unlock_security_level(
                client, _FLASH_SEC_L1, log, state, reason + "（L1→L3，不可直跳 L3）"
            )
        if state.active_security_level == _FLASH_SEC_L3:
            return
        _delay_between_security_l1_and_l3(l1_to_l3_delay_sec, cancel, log)
        _unlock_security_level(client, _FLASH_SEC_L3, log, state, reason)
        return
    _unlock_security_level(client, lvl, log, state, reason)


def _apply_flash_security_levels(
    client: Client,
    sec_levels: Sequence[int],
    state: FlashFlowState,
    cancel: threading.Event,
    log: LogFn,
    stage: str,
    l1_to_l3_delay_sec: float,
) -> None:
    for level in _normalize_flash_security_levels(sec_levels):
        if cancel.is_set():
            raise FlashAborted("cancelled")
        _ensure_security_level(
            client,
            int(level),
            log,
            state,
            stage,
            l1_to_l3_delay_sec=l1_to_l3_delay_sec,
            cancel=cancel,
        )


def _reassert_programming_session_and_unlock(
    client: Client,
    sec_levels: Sequence[int],
    state: FlashFlowState,
    cancel: threading.Event,
    log: LogFn,
    reason: str,
    l1_to_l3_delay_sec: float,
) -> None:
    """
    清除 FlashFlowState 会话假定后经 **Default→Extended→Programming** 再回到编程会话，再重温 SecurityAccess。

    仅用「本端 state」无法在长期例程后反映对端真实会话：若认为已是 programming，
    ``_ensure_session`` 会直接 return、不下发 10 02；后继 FF01 等可能 NRC **0x31** 等与
    「RequestOutOfRange / 会话或条件不符」混在一起的问题。在长例程边界（例如 37 后、
    DD02 后）强制执行本函数与刷写链路对齐；会话按 **default→extended→programming**；
    结束前发 TesterPresent(3E80) 刷新 S3。
    """
    state.current_session = None
    log(
        "刷写会话同步: %s — 路径 default(01)→extended(03)→programming(02)，再重温 27 …"
        % reason
    )
    _ensure_programming_via_default_extended(client, log, state)
    _apply_flash_security_levels(
        client,
        sec_levels,
        state,
        cancel,
        log,
        reason,
        l1_to_l3_delay_sec,
    )
    _flash_tester_present_optional(
        client,
        log,
        "%s — 会话 01→03→02 与 SecurityAccess 后刷新 S3" % reason,
    )


def _sessions_then_routines_then_rest(
    client: Client,
    sessions: List[str],
    pre_raw_requests: List[RawRequestStep],
    routines: list,
    cfg: AppConfig,
    log: LogFn,
    cancel: threading.Event,
    state: FlashFlowState,
) -> None:
    """
    先切第一个 extended（若存在），再跑 pre_transfer_routines，再切剩余会话。
    使 31 预条件等步骤落在扩展会话内，与对端 doip_callback 中 RID 要求一致。
    """
    idx = 0
    n = len(sessions)
    if idx < n and sessions[idx] == "extended":
        if cancel.is_set():
            raise FlashAborted("cancelled")
        _ensure_session(client, "extended", log, state)
        idx += 1

    _run_raw_requests(
        client,
        pre_raw_requests,
        cfg,
        log,
        cancel,
        stage_label="PreTransferRaw",
        state=state,
    )
    _run_routines(client, routines, log, cancel, state)

    while idx < n:
        if cancel.is_set():
            raise FlashAborted("cancelled")
        _ensure_session(client, sessions[idx], log, state)
        idx += 1


def _run_routines(
    client: Client,
    steps: list,
    log: LogFn,
    cancel: threading.Event,
    state: FlashFlowState,
    sec_levels_reunlock_after_rid_dd02: Optional[Sequence[int]] = None,
    l1_to_l3_delay_sec: float = _SECURITY_L1_TO_L3_DELAY_SEC,
) -> None:
    for step in steps:
        if cancel.is_set():
            raise FlashAborted("cancelled before routines")
        assert isinstance(step, RoutineStep)
        req_sess = _RID_REQUIRED_SESSION.get(int(step.routine_id) & 0xFFFF)
        if req_sess:
            _ensure_session(client, req_sess, log, state)
        log("RoutineControl 0x%04X type=%s" % (step.routine_id, step.control_type))
        client.routine_control(
            routine_id=step.routine_id,
            control_type=step.control_type,
            data=step.data or None,
        )
        if (
            sec_levels_reunlock_after_rid_dd02 is not None
            and (int(step.routine_id) & 0xFFFF) == 0xDD02
            and int(step.control_type) == 1
        ):
            _reassert_programming_session_and_unlock(
                client,
                sec_levels_reunlock_after_rid_dd02,
                state,
                cancel,
                log,
                reason="YAML 中 RoutineControl DD02(type=start)完成后",
                l1_to_l3_delay_sec=l1_to_l3_delay_sec,
            )


def _uds_p2_timeouts(client: Client) -> Tuple[float, float]:
    p2 = float(client.config["p2_timeout"])
    p2_star = float(client.config["p2_star_timeout"])
    timing = getattr(client, "session_timing", None)
    if timing is not None:
        if getattr(timing, "p2_server_max", None) is not None:
            p2 = float(timing.p2_server_max)
        if getattr(timing, "p2_star_server_max", None) is not None:
            p2_star = float(timing.p2_star_server_max)
    return p2, p2_star


def _send_suppress_positive_raw_request(client: Client, req: Request) -> None:
    """
    抑制正响应 UDS 请求：
    - P2 内无应答 → 视为成功（符合 suppress 语义）；
    - 收到 NRC 0x78 → 必须在 P2* 内等到最终正/负响应，否则报错（不继续后继步骤）。
    """
    conn = client.conn
    if conn is None:
        raise RuntimeError("UDS client has no connection")
    if req.service is None:
        raise ValueError("Request has no service")

    p2, p2_star = _uds_p2_timeouts(client)
    conn.empty_rxqueue()
    conn.send(req.get_payload())

    single_timeout = p2
    pending_seen = False

    while True:
        try:
            recv_payload = conn.wait_frame(timeout=single_timeout, exception=True)
        except TimeoutException:
            if pending_seen:
                raise TimeoutException(
                    "Suppress-positive UDS request (service 0x%02X) received NRC 0x78 "
                    "but no final response within P2* (timeout=%.3f sec)"
                    % (req.service.request_id(), single_timeout)
                )
            return

        response = Response.from_payload(recv_payload)
        client.last_response = response
        if not response.valid:
            raise InvalidResponseException(response)
        assert response.service is not None
        assert response.code is not None

        if response.service.response_id() != req.service.response_id():
            raise UnexpectedResponseException(
                response,
                "Response gotten from server has a service ID different than the request service ID. "
                "Received=0x%02x, Expected=0x%02x"
                % (response.service.response_id(), req.service.response_id()),
            )

        if response.positive:
            return

        if response.code == Response.Code.RequestCorrectlyReceived_ResponsePending:
            pending_seen = True
            single_timeout = p2_star
            continue

        raise NegativeResponseException(response)


def _send_raw_uds_request(client: Client, req: Request) -> None:
    if req.suppress_positive_response:
        _send_suppress_positive_raw_request(client, req)
    else:
        client.send_request(req)


def _run_raw_requests(
    client: Client,
    requests: List[RawRequestStep],
    cfg: AppConfig,
    log: LogFn,
    cancel: threading.Event,
    stage_label: str,
    state: FlashFlowState,
) -> None:
    @contextmanager
    def _switch_uds_target(addr_mode: str):
        conn = getattr(client, "conn", None)
        doip = getattr(conn, "_connection", None)
        prev = None
        has_target = doip is not None and hasattr(doip, "_uds_target_logical_address")
        if has_target:
            prev = int(getattr(doip, "_uds_target_logical_address"))
            if addr_mode == "functional":
                target = int(cfg.doip.functional_logical_address)
            else:
                target = int(cfg.doip.server_logical_address)
            setattr(doip, "_uds_target_logical_address", target)
        try:
            yield
        finally:
            if has_target and prev is not None:
                setattr(doip, "_uds_target_logical_address", prev)

    for i, step in enumerate(requests, start=1):
        if cancel.is_set():
            raise FlashAborted("cancelled before %s" % stage_label)
        payload = bytes(step.payload or b"")
        if not payload:
            continue
        # 31 RID 会话保护：按 v116 config.xml 要求自动切会话
        if payload[0] == 0x31 and len(payload) >= 4:
            rid = (int(payload[2]) << 8) | int(payload[3])
            req_sess = _RID_REQUIRED_SESSION.get(rid)
            if req_sess:
                log(
                    "%s #%d: RID 0x%04X 要求会话=%s，发送前自动切换"
                    % (stage_label, i, rid, req_sess)
                )
                _ensure_session(client, req_sess, log, state)

        is_hard_reset_ecu = (
            payload[0] == 0x11
            and len(payload) >= 2
            and (payload[1] & 0x7F) == 0x01
        )
        if is_hard_reset_ecu:
            # 编程/扩展会话下常见 NRC 0x7F；先回默认会话再发复位
            if state.current_session in ("programming", "extended"):
                log(
                    "%s #%d: ECUReset(hardReset) 前会先切默认会话（当前=%s）"
                    % (stage_label, i, state.current_session)
                )
                _ensure_session(client, "default", log, state)

        mode = (step.addressing or "physical").lower()
        log("%s #%d (%s): %s" % (stage_label, i, mode, payload.hex()))
        with _switch_uds_target(mode):
            req = Request.from_payload(payload)
            if is_hard_reset_ecu:
                try:
                    client.send_request(req)
                except TimeoutException:
                    log(
                        "%s #%d: ECUReset(hardReset) 应答超时（对端可能已直接复位），按无应答处理"
                        % (stage_label, i)
                    )
                state.current_session = None
                state.unlocked_levels.clear()
                state.active_security_level = None
            else:
                _send_raw_uds_request(client, req)
        if payload[0] == 0x10 and len(payload) >= 2:
            sf = payload[1] & 0x7F
            if sf == 0x01:
                state.current_session = "default"
                state.unlocked_levels.clear()
                state.active_security_level = None
            elif sf == 0x02:
                state.current_session = "programming"
                state.unlocked_levels.clear()
                state.active_security_level = None
            elif sf == 0x03:
                state.current_session = "extended"
                state.unlocked_levels.clear()
                state.active_security_level = None


def _extract_dd02_signature_from_xml(xml_bytes: bytes, target_zip_name: str) -> bytes:
    text = None
    for enc in ("utf-8", "gb18030", "latin1"):
        try:
            text = xml_bytes.decode(enc)
            break
        except Exception:
            continue
    if text is None:
        raise ValueError("签名 XML 解码失败")

    target = Path(target_zip_name).name.strip()
    list_pat = re.compile(r"<list>(.*?)</list>", re.IGNORECASE | re.DOTALL)
    name_pat = re.compile(r"<fileName>\s*(.*?)\s*</fileName>", re.IGNORECASE | re.DOTALL)
    sig_pat = re.compile(r"<fileSIG>\s*([0-9A-Fa-f\s]+)\s*</fileSIG>", re.IGNORECASE | re.DOTALL)
    for block in list_pat.findall(text):
        m_name = name_pat.search(block)
        m_sig = sig_pat.search(block)
        if not m_name or not m_sig:
            continue
        name = str(m_name.group(1) or "").strip()
        if Path(name).name != target:
            continue
        sig_hex = re.sub(r"\s+", "", str(m_sig.group(1) or ""))
        if not sig_hex:
            break
        try:
            sig = bytes.fromhex(sig_hex)
        except Exception as exc:
            raise ValueError("XML 中 fileSIG 不是合法十六进制") from exc
        if len(sig) < 256:
            raise ValueError(
                "XML 签名长度过短：%d bytes（DD02 通常需 >=256 bytes）" % len(sig)
            )
        return sig
    raise ValueError("未在签名 XML 中找到 %s 对应的 fileSIG" % target)


def _write_fingerprint_with_fallback(
    client: Client,
    did: int,
    data: bytes,
    req_sess: Optional[str],
    req_sec: Optional[int],
    state: FlashFlowState,
    log: LogFn,
    *,
    l1_to_l3_delay_sec: float = _SECURITY_L1_TO_L3_DELAY_SEC,
    cancel: Optional[threading.Event] = None,
) -> None:
    if req_sess:
        _ensure_session(client, req_sess, log, state)
    if req_sec is not None:
        _ensure_security_level(
            client,
            int(req_sec),
            log,
            state,
            "WriteDataByIdentifier DID=0x%04X" % did,
            l1_to_l3_delay_sec=l1_to_l3_delay_sec,
            cancel=cancel,
        )

    payload = bytes([0x2E, (did >> 8) & 0xFF, did & 0xFF]) + bytes(data)
    log("WriteDataByIdentifier DID=0x%04X (fingerprint)" % did)
    try:
        client.send_request(Request.from_payload(payload))
        return
    except NegativeResponseException as exc:
        # 对手件存在差异：F184 在 programming 返回 0x7F 时，自动尝试 extended 一次。
        code = int(getattr(exc.response, "code", 0) or 0)
        if did != 0xF184 or code != 0x7F:
            raise
        log("DID=0xF184 在当前会话返回 NRC=0x7F，自动切到 extended 并重试一次")
        _ensure_session(client, "extended", log, state)
        if req_sec is not None:
            _ensure_security_level(
                client,
                int(req_sec),
                log,
                state,
                "DID=0x%04X fallback retry" % did,
                l1_to_l3_delay_sec=l1_to_l3_delay_sec,
                cancel=cancel,
            )
        client.send_request(Request.from_payload(payload))


def _prepare_transfer_items_from_path(
    path: Path, temp_dir: Path, log: LogFn
) -> Tuple[List[TransferItem], Optional[bytes]]:
    if not path.exists():
        raise FileNotFoundError("刷写输入不存在: %s" % path)

    if path.is_dir():
        t0 = time.monotonic()
        files = [p for p in path.iterdir() if p.is_file()]
        zip_files = [p for p in files if p.suffix.lower() == ".zip"]
        xml_files = [p for p in files if p.suffix.lower() == ".xml"]
        if not zip_files or not xml_files:
            raise ValueError("目录内需同时包含升级 zip 与签名 xml: %s" % path)
        zip_file = max(zip_files, key=lambda p: p.stat().st_size)
        preferred_xml = [
            p for p in xml_files if ("sig" in p.name.lower() or "crc" in p.name.lower())
        ]
        xml_file = preferred_xml[0] if preferred_xml else xml_files[0]
        dd02_signature = _extract_dd02_signature_from_xml(xml_file.read_bytes(), zip_file.name)
        log(
            "刷写准备: 目录模式，解析耗时=%.2fs，升级包=%s (%d bytes), 签名=%s (%d bytes), DD02签名字节=%d"
            % (
                time.monotonic() - t0,
                zip_file.name,
                zip_file.stat().st_size,
                xml_file.name,
                xml_file.stat().st_size,
                len(dd02_signature),
            )
        )
        return [
            TransferItem(name=zip_file.name, path=zip_file, size=zip_file.stat().st_size),
            TransferItem(name=xml_file.name, path=xml_file, size=xml_file.stat().st_size),
        ], dd02_signature

    if path.suffix.lower() != ".zip":
        return [TransferItem(name=path.name, path=path, size=path.stat().st_size)], None

    t0 = time.monotonic()
    with zipfile.ZipFile(path, "r") as zf:
        members = [n for n in zf.namelist() if n and not n.endswith("/")]
        zip_members = [n for n in members if n.lower().endswith(".zip")]
        xml_members = [n for n in members if n.lower().endswith(".xml")]
        if not zip_members or not xml_members:
            log("外层 ZIP 内未同时发现升级 ZIP + 签名 XML，按单文件直传")
            return [TransferItem(name=path.name, path=path, size=path.stat().st_size)], None

        zip_member = max(zip_members, key=lambda n: zf.getinfo(n).file_size)
        preferred_xml = [n for n in xml_members if ("sig" in n.lower() or "crc" in n.lower())]
        xml_member = preferred_xml[0] if preferred_xml else xml_members[0]

        zip_name = Path(zip_member).name
        xml_name = Path(xml_member).name
        extracted_zip = temp_dir / zip_name
        extracted_xml = temp_dir / xml_name

        t_extract = time.monotonic()
        with zf.open(zip_member, "r") as src, extracted_zip.open("wb") as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
        with zf.open(xml_member, "r") as src, extracted_xml.open("wb") as dst:
            shutil.copyfileobj(src, dst, length=64 * 1024)
        t_extract_done = time.monotonic()

    xml_bytes = extracted_xml.read_bytes()
    dd02_signature = _extract_dd02_signature_from_xml(xml_bytes, zip_name)
    log(
        "刷写准备: 检测到双文件包，提取耗时=%.2fs，总准备耗时=%.2fs，升级包=%s (%d bytes), 签名=%s (%d bytes), DD02签名字节=%d"
        % (
            t_extract_done - t_extract,
            time.monotonic() - t0,
            zip_name,
            extracted_zip.stat().st_size,
            xml_name,
            extracted_xml.stat().st_size,
            len(dd02_signature),
        )
    )
    return [
        TransferItem(name=zip_name, path=extracted_zip, size=extracted_zip.stat().st_size),
        TransferItem(name=xml_name, path=extracted_xml, size=extracted_xml.stat().st_size),
    ], dd02_signature


def _transfer_one_file(
    client: Client,
    fl,
    item: TransferItem,
    log: LogFn,
    cancel: threading.Event,
    progress: Optional[ProgressFn],
    bytes_done_before: int,
    total_all: int,
    state: FlashFlowState,
) -> int:
    # v116 对应链路：34/36/37 在 programming + security(0/1)，这里固定切到 0x01。
    _ensure_security_level(client, 0x01, log, state, "before RequestDownload")
    mem = MemoryLocation(
        address=fl.memory_address,
        memorysize=item.size,
        address_format=fl.address_format,
        memorysize_format=fl.memorysize_format,
    )
    log(
        "RequestDownload file=%s address=0x%X size=%d"
        % (item.name, fl.memory_address, item.size)
    )
    rd_resp = client.request_download(mem, None)
    if rd_resp is None or rd_resp.service_data is None:
        raise RuntimeError("RequestDownload: empty response")

    max_len = rd_resp.service_data.max_length
    payload = compute_transfer_payload_size(max_len)
    if fl.override_block_payload is not None:
        payload = min(payload, int(fl.override_block_payload))
    log(
        "Using TransferData payload size=%d (ECU max_number_of_block_length=%d) file=%s"
        % (payload, max_len, item.name)
    )

    rd_delay = fl.post_request_download_delay_sec
    if rd_delay is None:
        rd_delay = _POST_REQUEST_DOWNLOAD_DELAY_SEC
    else:
        rd_delay = float(rd_delay)
    _delay_after_request_download(rd_delay, cancel, log)

    seq = 1
    offset = 0
    total = item.size
    next_keepalive = time.monotonic() + _FLASH_KEEPALIVE_INTERVAL_SEC
    keepalive_logged = False
    with item.path.open("rb") as fp:
        while offset < total:
            if cancel.is_set():
                raise FlashAborted("cancelled during transfer")
            now = time.monotonic()
            if now >= next_keepalive:
                try:
                    # wait_nrc=False：发完 3E 80 不等待回包，直接继续发下一条 36
                    with client.suppress_positive_response(wait_nrc=False):
                        client.tester_present()
                    if not keepalive_logged:
                        log(
                            "刷写保活: 已启用周期性 TesterPresent（3E 80），固定每 %.0fs"
                            % _FLASH_KEEPALIVE_INTERVAL_SEC
                        )
                        keepalive_logged = True
                except Exception as exc:
                    log("刷写保活 TesterPresent 失败: %s" % exc)
                while next_keepalive <= now:
                    next_keepalive += _FLASH_KEEPALIVE_INTERVAL_SEC
            chunk = fp.read(payload)
            if not chunk:
                break
            client.transfer_data(seq, chunk)
            offset += len(chunk)
            seq = (seq + 1) & 0xFF
            if seq == 0:
                seq = 1
            if progress:
                progress(bytes_done_before + offset, total_all)

    exit_data = fl.transfer_exit_data
    # 使用 udsoncan 默认 send_request（use_server_timing 下首轮 min(request_timeout, ECU-P2)，通常 ~50ms）
    client.request_transfer_exit(exit_data if exit_data else None)
    log("RequestTransferExit OK file=%s" % item.name)
    return total


def _run_flash_download_items(
    client: Client,
    cfg: AppConfig,
    items: Sequence[TransferItem],
    dd02_signature: Optional[bytes],
    log: LogFn,
    cancel: threading.Event,
    progress: Optional[ProgressFn] = None,
    reconnect_after_ecu_reset: Optional[ReconnectAfterResetFn] = None,
) -> None:
    fl = cfg.flash
    if fl.post_transfer_after_reconnect_raw_requests and reconnect_after_ecu_reset is None:
        raise RuntimeError(
            "已配置 flash.post_transfer_after_reconnect_raw_requests，"
            "刷写入口必须提供 reconnect_after_ecu_reset（复位后断开、等待、重连并返回新 Client）。"
        )
    state = FlashFlowState()
    if not items:
        raise ValueError("no transfer items")

    sessions = (
        list(fl.diagnostic_sessions_before_download)
        if fl.diagnostic_sessions_before_download
        else list(_DEFAULT_DIAGNOSTIC_SESSIONS_BEFORE_DOWNLOAD)
    )
    sec_levels = _normalize_flash_security_levels(
        fl.security_access_levels_before_download
        if fl.security_access_levels_before_download
        else _DEFAULT_SECURITY_LEVELS_BEFORE_DOWNLOAD
    )
    sec_l1_l3_delay = _resolve_l1_to_l3_delay_sec(fl)

    log("刷写前准备：切换会话/执行预例程/安全解锁…")
    _sessions_then_routines_then_rest(
        client,
        sessions,
        fl.pre_transfer_raw_requests,
        fl.pre_transfer_routines,
        cfg,
        log,
        cancel,
        state,
    )
    if cancel.is_set():
        raise FlashAborted("cancelled")

    _apply_flash_security_levels(
        client,
        sec_levels,
        state,
        cancel,
        log,
        "before RequestDownload",
        sec_l1_l3_delay,
    )

    if fl.fingerprint_did is not None and fl.fingerprint_data:
        did = int(fl.fingerprint_did) & 0xFFFF
        req = _DID_WRITE_REQUIREMENT.get(did)
        req_sess = req[0] if req is not None else None
        req_sec = req[1] if req is not None else None
        _write_fingerprint_with_fallback(
            client,
            did,
            bytes(fl.fingerprint_data),
            req_sess,
            req_sec,
            state,
            log,
            l1_to_l3_delay_sec=sec_l1_l3_delay,
            cancel=cancel,
        )

    total_all = sum(int(x.size) for x in items)
    done = 0
    for idx, item in enumerate(items, start=1):
        if cancel.is_set():
            raise FlashAborted("cancelled")
        log("开始传输文件 %d/%d: %s" % (idx, len(items), item.name))
        n = _transfer_one_file(
            client,
            fl,
            item,
            log,
            cancel,
            progress,
            done,
            total_all,
            state,
        )
        done += n

    has_dd02_in_cfg = any(
        int(step.routine_id) == 0xDD02 and int(step.control_type) == 1
        for step in fl.post_transfer_routines
    )
    dd02_from_zip = bool(dd02_signature and not has_dd02_in_cfg)
    need_post_download_session = bool(
        fl.post_transfer_routines
        or fl.post_transfer_raw_requests
        or dd02_from_zip
    )
    # RequestTransferExit 后许多 ECU 实际会话已回到默认或非编程会话，但 FlashFlowState
    # 仍记着 programming → _ensure_session 会误判跳过 10 02。
    if need_post_download_session:
        _reassert_programming_session_and_unlock(
            client,
            sec_levels,
            state,
            cancel,
            log,
            reason="数据传输结束(RequestTransferExit)后",
            l1_to_l3_delay_sec=sec_l1_l3_delay,
        )

    if dd02_from_zip:
        log(
            "RoutineControl 0xDD02 type=1 (携带 XML 签名, len=%d bytes)" % len(dd02_signature)
        )
        client.routine_control(routine_id=0xDD02, control_type=1, data=dd02_signature)
        _reassert_programming_session_and_unlock(
            client,
            sec_levels,
            state,
            cancel,
            log,
            reason="DD02(签名验签)长例程完成后",
            l1_to_l3_delay_sec=sec_l1_l3_delay,
        )

    _run_routines(
        client,
        fl.post_transfer_routines,
        log,
        cancel,
        state,
        sec_levels_reunlock_after_rid_dd02=(
            tuple(sec_levels) if fl.post_transfer_routines else None
        ),
        l1_to_l3_delay_sec=sec_l1_l3_delay,
    )
    _run_raw_requests(
        client,
        fl.post_transfer_raw_requests,
        cfg,
        log,
        cancel,
        stage_label="PostTransferRaw",
        state=state,
    )
    if fl.post_transfer_after_reconnect_raw_requests:
        assert reconnect_after_ecu_reset is not None
        dly = fl.post_transfer_reconnect_delay_sec
        if dly is not None:
            log("后编程: 配置了复位后延迟 %.1fs（由重连逻辑执行后再发剩余请求）" % float(dly))
        client = reconnect_after_ecu_reset()
        reconnect_state = FlashFlowState()
        _run_raw_requests(
            client,
            fl.post_transfer_after_reconnect_raw_requests,
            cfg,
            log,
            cancel,
            stage_label="PostTransferRawReconnect",
            state=reconnect_state,
        )


def run_flash_download(
    client: Client,
    cfg: AppConfig,
    firmware: bytes,
    log: LogFn,
    cancel: threading.Event,
    progress: Optional[ProgressFn] = None,
) -> None:
    if cfg.flash.post_transfer_after_reconnect_raw_requests:
        raise RuntimeError(
            "当前入口不支持 flash.post_transfer_after_reconnect_*；"
            "请改用 run_flash_download_from_path 或移除该列表。"
        )
    with tempfile.TemporaryDirectory(prefix="doip_flash_mem_") as td:
        p = Path(td) / "firmware.bin"
        p.write_bytes(firmware)
        _run_flash_download_items(
            client,
            cfg,
            [TransferItem(name="firmware.bin", path=p, size=len(firmware))],
            None,
            log=log,
            cancel=cancel,
            progress=progress,
        )


def run_flash_download_from_path(
    client: Client,
    cfg: AppConfig,
    firmware_path: str,
    log: LogFn,
    cancel: threading.Event,
    progress: Optional[ProgressFn] = None,
    reconnect_after_ecu_reset: Optional[ReconnectAfterResetFn] = None,
) -> None:
    path = Path(firmware_path)
    t0 = time.monotonic()
    log("刷写准备: 开始解析文件并准备传输项…")
    with tempfile.TemporaryDirectory(prefix="doip_flash_") as td:
        items, dd02_signature = _prepare_transfer_items_from_path(path, Path(td), log)
        log(
            "刷写准备: 完成，共 %d 个传输文件，总大小=%d bytes，耗时=%.2fs"
            % (len(items), sum(x.size for x in items), time.monotonic() - t0)
        )
        _run_flash_download_items(
            client,
            cfg,
            items,
            dd02_signature,
            log=log,
            cancel=cancel,
            progress=progress,
            reconnect_after_ecu_reset=reconnect_after_ecu_reset,
        )
