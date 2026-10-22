"""
刷写 34/36/37 与主机厂「预编程 / 编程」流程对齐要点（奇瑞 TBOX 对端 v116 等）：

- doip_callback.c：Programming(0x02) 仅能从 Extended(0x03) 或 Programming 进入；从 Default
  直切 Programming 会 NRC 0x7E。故典型顺序为 Extended →（扩展会话内 31/85/28 等）→ Programming。
  若对端会话编号为「0=default / 2=extended / 1=programming」则须在 **请求 10 02 前先有 03**；
  刷写结束后重申会话默认 **Default→Extended→Programming**（奇瑞 v116）；
  北汽 N80/335 在 YAML 设 ``post_transfer_session_reassert: none``（图8：37 后直接 checkMemory）。
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

后编程（奇瑞 CBF/RSA 新流程）：先 **0x34/36/37 传 .cbf**，再传 **.rsa 原文**（2302 字节文本）；
随后 **DD02（31 01 DD 02 + 384 字节签名）→ FF01 → DD03**（见 ``flash.post_transfer_routines``）。
34/36/37 传 .rsa 时不截断；DD02 的 option record 从 .rsa 解析出 384 字节二进制签名（EEA5.0 规范 #5…#N）。
**DD03 后设备自行升级，勿发 11 01**；断开等待后由 ``post_transfer_after_reconnect_raw_requests`` 做通信恢复。

后编程（北汽 N80KS v515 文档图9 流程）：11 01 触发 OTA 后设备复位掉线，工具轮询重连直到 PHY 重建，
随后按 ``post_transfer_after_reconnect_raw_requests`` 以**功能寻址**依次执行 10 03 → 28 00 01 → 85 01 →
10 01 → 14 FF FF FF（功能寻址请求无应答视为成功，见 ``uds.use_server_timing``/``addressing`` 配置）。
"""

import threading
import time
import xml.etree.ElementTree as ET
import shutil
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
import tempfile
import re
from typing import Callable, Dict, List, Optional, Sequence, Tuple

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
    # 北汽 v515：文件对应 31 01 0202 完整性校验用的 256 字节 RSA 签名（来自 5-*.xml）
    signature: Optional[bytes] = None


@dataclass
class FlashFlowState:
    current_session: Optional[str] = None
    unlocked_levels: set = field(default_factory=set)
    active_security_level: Optional[int] = None


class FlashAborted(Exception):
    """User cancelled or worker stopped the transfer."""


TRANSFER_DATA_OVERHEAD = 2  # 0x36 + blockSequenceCounter per ISO-14229-1
# ISO 14229-1：块序号 0x01…0xFF 后下一块为 0x00，再 0x01…（不可 FF 后直接回 0x01）
_TRANSFER_DATA_FIRST_BLOCK_SEQ = 0x01


def next_transfer_data_block_sequence(current: int) -> int:
    """Return next TransferData blockSequenceCounter (single byte, wraps FF→00→01)."""
    return (int(current) + 1) & 0xFF

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
    0x0202: "programming", # CheckRoutine（北汽 v515 完整性校验：CRC32/签名）
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
# 块间隙：仅当距上次 UDS 活动超过该间隔才发 3E；每块 36/76 本身会刷新 S3，不得每块都插 3E。
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


def _uds_is_tester_present_positive(payload: bytes) -> bool:
    return len(payload) >= 1 and payload[0] == 0x7E


def _uds_is_tester_present_pending(payload: bytes) -> bool:
    return (
        len(payload) >= 3
        and payload[0] == 0x7F
        and payload[1] == 0x3E
        and payload[2] == Response.Code.RequestCorrectlyReceived_ResponsePending
    )


def _drain_late_responses_after_tester_present(
    client: Client,
    log: LogFn,
    max_total_sec: float = 2.0,
    slice_sec: float = 0.05,
) -> None:
    """
    发完 3E80 后排空对端回包，再发下一条 36，避免 7E / 7F 3E 78 串进 TransferData 等待。
    遇到 7F 3E 78 时延长等待以收齐最终 3E 应答；其它非 3E PDU 回填队列。
    """
    conn = getattr(client, "conn", None)
    if conn is None:
        return
    doip_conn = getattr(conn, "_connection", None)
    t0 = time.monotonic()
    drained_tp = 0
    pending_78 = False
    while time.monotonic() - t0 < max_total_sec:
        try:
            recv_payload = conn.wait_frame(timeout=slice_sec, exception=True)
        except TimeoutException:
            if pending_78:
                continue
            break
        except Exception as exc:
            log("刷写保活: 排空迟到响应时出现异常（已停止排空）: %s" % exc)
            break
        if not recv_payload:
            continue
        if _uds_is_tester_present_pending(recv_payload):
            pending_78 = True
            drained_tp += 1
            continue
        if _uds_is_tester_present_negative(recv_payload) or _uds_is_tester_present_positive(
            recv_payload
        ):
            pending_78 = False
            drained_tp += 1
            break
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
            "刷写保活: 已消化 %d 条 TesterPresent 相关回包后再继续后续诊断"
            % drained_tp
        )


def _flash_tester_present_between_blocks(client: Client, log: LogFn) -> None:
    """36 块间隙保活：必须收齐/排空 3E 相关应答后再发下一块，禁止 fire-and-forget。"""
    try:
        with client.suppress_positive_response(wait_nrc=True):
            client.tester_present()
    except Exception as exc:
        # 部分 ECU 忽略 suppress 回 7E，或回其它 NRC；先排空再继续，避免卡死整次刷写
        log("刷写保活 TesterPresent 异常（将排空后继续）: %s" % exc)
    _drain_late_responses_after_tester_present(client, log)


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


# 数据传输结束后、后处理前重申编程会话的路径（见 flash.post_transfer_session_reassert）
_REASSERT_DEFAULT_EXTENDED_PROGRAMMING = "default_extended_programming"
_REASSERT_EXTENDED_PROGRAMMING = "extended_programming"
_REASSERT_PROGRAMMING = "programming"
_REASSERT_NONE = "none"
_VALID_POST_TRANSFER_SESSION_REASSERT = frozenset(
    {
        _REASSERT_DEFAULT_EXTENDED_PROGRAMMING,
        _REASSERT_EXTENDED_PROGRAMMING,
        _REASSERT_PROGRAMMING,
        _REASSERT_NONE,
    }
)


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


def _normalize_post_transfer_session_reassert(mode: Optional[str]) -> str:
    m = (mode or _REASSERT_DEFAULT_EXTENDED_PROGRAMMING).strip().lower()
    if m not in _VALID_POST_TRANSFER_SESSION_REASSERT:
        raise ValueError(
            "flash.post_transfer_session_reassert 未知: %r（允许: %s）"
            % (mode, ", ".join(sorted(_VALID_POST_TRANSFER_SESSION_REASSERT)))
        )
    return m


def _post_transfer_session_reassert_label(mode: str) -> str:
    return {
        _REASSERT_NONE: "none（保持当前会话）",
        _REASSERT_PROGRAMMING: "programming(02)",
        _REASSERT_EXTENDED_PROGRAMMING: "extended(03)→programming(02)",
        _REASSERT_DEFAULT_EXTENDED_PROGRAMMING: (
            "default(01)→extended(03)→programming(02)"
        ),
    }[mode]


def _apply_post_transfer_session_reassert(
    client: Client, log: LogFn, state: FlashFlowState, mode: str
) -> None:
    """
    按配置重申会话。
    V335：勿走 default——10 01 会清掉 0203 预编程条件缓存，随后 10 02 车速检查失败。
    """
    m = _normalize_post_transfer_session_reassert(mode)
    if m == _REASSERT_NONE:
        return
    if m == _REASSERT_PROGRAMMING:
        _ensure_session(client, "programming", log, state)
        return
    if m == _REASSERT_EXTENDED_PROGRAMMING:
        _ensure_session(client, "extended", log, state)
        _ensure_session(client, "programming", log, state)
        return
    _ensure_programming_via_default_extended(client, log, state)


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
    resp = client.unlock_security_access(lvl)
    sd = getattr(resp, "service_data", None)
    seed = getattr(sd, "seed", None)
    if seed is not None and len(seed) > 0 and seed == b"\x00" * len(seed):
        # v515 协议栈：请求 level 已解锁时返回全 0 seed，udsoncan 据此跳过 27 02。
        log(
            "SecurityAccess: 对端返回全 0 seed → level 0x%02X 已解锁，27 02 未发送（正常）"
            % lvl
        )
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
    session_reassert: str = _REASSERT_DEFAULT_EXTENDED_PROGRAMMING,
) -> None:
    """
    按 ``session_reassert`` 在长传输/例程边界对齐会话与安全访问。

    默认 ``default_extended_programming``（奇瑞 v116：01→03→02 并重温 27）。
    北汽 N80/335 图8：YAML 设 ``none``——37 后保持 programming，直接 checkMemory，
    不切 10 xx、不重温 27。结束前发 TesterPresent(3E80) 刷新 S3。
    """
    mode = _normalize_post_transfer_session_reassert(session_reassert)
    path_desc = _post_transfer_session_reassert_label(mode)
    if mode == _REASSERT_NONE:
        # 图8：保持编程会话与已解锁状态，直接进入后处理例程
        state.current_session = "programming"
        log(
            "刷写会话同步: %s — %s（图8：37 后直接 checkMemory）"
            % (reason, path_desc)
        )
        _flash_tester_present_optional(
            client, log, "%s — 保持 programming，刷新 S3" % reason
        )
        return

    state.current_session = None
    log("刷写会话同步: %s — 路径 %s，再重温 27 …" % (reason, path_desc))
    _apply_post_transfer_session_reassert(client, log, state, mode)
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
        "%s — 会话重申(%s)与 SecurityAccess 后刷新 S3" % (reason, path_desc),
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
    sec_levels: Optional[Sequence[int]] = None,
    l1_to_l3_delay_sec: float = _SECURITY_L1_TO_L3_DELAY_SEC,
) -> None:
    """
    先切第一个 extended（若存在），再跑 pre_transfer_routines，再切剩余会话。
    使 31 预条件等步骤落在扩展会话内，与对端 doip_callback 中 RID 要求一致。

    ``sec_levels`` 非空时，若首会话为 extended 且含 Level1(0x01)，则在预例程之后、
    切到 programming 之前先解锁 L1（北汽 TBX 协议：27 01/02 仅在 extended 会话执行）。
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

    if sec_levels and 0x01 in set(int(x) & 0xFF for x in sec_levels):
        if cancel.is_set():
            raise FlashAborted("cancelled")
        log("安全访问: 按北汽 TBX 协议在 extended 会话先解锁 Level1(0x01)")
        _ensure_security_level(
            client,
            _FLASH_SEC_L1,
            log,
            state,
            "extended 会话解锁 Level1",
            l1_to_l3_delay_sec=l1_to_l3_delay_sec,
            cancel=cancel,
        )

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
    dd02_signature: Optional[bytes] = None,
) -> None:
    for step in steps:
        if cancel.is_set():
            raise FlashAborted("cancelled before routines")
        assert isinstance(step, RoutineStep)
        req_sess = _RID_REQUIRED_SESSION.get(int(step.routine_id) & 0xFFFF)
        if req_sess:
            _ensure_session(client, req_sess, log, state)
        rid = int(step.routine_id) & 0xFFFF
        routine_data = step.data or None
        if (
            rid == 0xDD02
            and int(step.control_type) == 1
            and not routine_data
            and dd02_signature
        ):
            routine_data = dd02_signature
            log(
                "RoutineControl 0xDD02 type=1 (携带 RSA 解析签名, len=%d bytes)"
                % len(dd02_signature)
            )
        else:
            log("RoutineControl 0x%04X type=%s" % (step.routine_id, step.control_type))
        client.routine_control(
            routine_id=step.routine_id,
            control_type=step.control_type,
            data=routine_data,
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
            elif mode == "functional":
                # 功能寻址请求：ECU 通常抑制正响应，无应答视为成功；
                # 收到 NRC 0x78 仍须等 P2* 内的最终正/负响应。
                _send_suppress_positive_raw_request(client, req)
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


def _parse_dd02_signature_from_rsa(rsa_path: Path) -> bytes:
    """从 .rsa 文本（0xNN, 0xNN, …）解析 DD02 option record 所需的二进制签名。"""
    raw = rsa_path.read_bytes()
    text = None
    for enc in ("utf-8", "ascii", "latin1"):
        try:
            text = raw.decode(enc)
            break
        except Exception:
            continue
    if text is None:
        raise ValueError("RSA 文件解码失败: %s" % rsa_path)
    vals = [int(x, 16) for x in re.findall(r"0x[0-9A-Fa-f]+", text)]
    if not vals:
        raise ValueError("RSA 文件中未找到 0xNN 格式的签名数据: %s" % rsa_path.name)
    sig = bytes(int(v) & 0xFF for v in vals)
    if len(sig) != 384:
        raise ValueError(
            "RSA 解析签名长度=%d bytes（DD02 期望 384 bytes）: %s"
            % (len(sig), rsa_path.name)
        )
    return sig


def generate_dummy_rsa(cbf_path: Path) -> Path:
    """为 .cbf 生成配套的临时 .rsa（384 字节全 0xFF），用于 server 跳过签名校验时的占位传输。"""
    rsa_path = cbf_path.with_suffix(".rsa")
    content = ", ".join("0xFF" for _ in range(384))
    rsa_path.write_text(content, encoding="ascii")
    return rsa_path


def _cbf_rsa_transfer_items(cbf: Path, rsa: Path, log: LogFn) -> Tuple[List[TransferItem], bytes]:
    if not cbf.is_file():
        raise FileNotFoundError("CBF 文件不存在: %s" % cbf)
    if not rsa.is_file():
        raise FileNotFoundError("RSA 文件不存在: %s" % rsa)
    dd02_signature = _parse_dd02_signature_from_rsa(rsa)
    log(
        "刷写准备: CBF/RSA 模式，第1个传输=%s (%d bytes)，第2个传输=%s (%d bytes，原文直传)，DD02签名=%d bytes"
        % (cbf.name, cbf.stat().st_size, rsa.name, rsa.stat().st_size, len(dd02_signature))
    )
    return [
        TransferItem(name=cbf.name, path=cbf, size=cbf.stat().st_size),
        TransferItem(name=rsa.name, path=rsa, size=rsa.stat().st_size),
    ], dd02_signature


def _resolve_cbf_rsa_pair(path: Path) -> Tuple[Path, Path]:
    suffix = path.suffix.lower()
    if suffix == ".cbf":
        cbf, rsa = path, path.with_suffix(".rsa")
    elif suffix == ".rsa":
        rsa, cbf = path, path.with_suffix(".cbf")
    else:
        raise ValueError("请选择 .cbf 或 .rsa 文件，或包含成对文件的目录: %s" % path)
    return cbf, rsa


def _find_cbf_rsa_in_directory(path: Path) -> Tuple[Path, Path]:
    files = [p for p in path.iterdir() if p.is_file()]
    cbf_by_stem = {p.stem: p for p in files if p.suffix.lower() == ".cbf"}
    rsa_by_stem = {p.stem: p for p in files if p.suffix.lower() == ".rsa"}
    common = sorted(set(cbf_by_stem) & set(rsa_by_stem))
    if not common:
        raise ValueError("目录内需同时包含成对的 .cbf 与 .rsa 文件: %s" % path)
    if len(common) > 1:
        stem = max(common, key=lambda s: cbf_by_stem[s].stat().st_size)
    else:
        stem = common[0]
    return cbf_by_stem[stem], rsa_by_stem[stem]


def _s19_zip_transfer_items(
    s19: Path, app_file: Path, log: LogFn, xml_path: Optional[Path] = None
) -> Tuple[List[TransferItem], None]:
    """北汽两文件刷写：34/36/37 先传 .s19，再传第 2 个应用包。

    - v515 / n80ks：第 2 个为 ``.zip``
    - B40L / v335：第 2 个为 ``.tar``（FOTA tar 原样）
    行为按所选文件扩展名区分；有 zip 时既有路径不变。

    ``xml_path`` 为签名清单（5-*.xml）时，解析其中每个文件的 256 字节 RSA 签名
    并附加到对应 TransferItem，供 31 01 0202 完整性校验使用。
    """
    if not s19.is_file():
        raise FileNotFoundError("S19 文件不存在: %s" % s19)
    if not app_file.is_file():
        raise FileNotFoundError("应用包文件不存在: %s" % app_file)
    if xml_path is None:
        raise FileNotFoundError(
            "未找到签名清单（5-*.xml）: %s。北汽刷写必须提供 S19/应用包对应的 RSA 签名文件。"
            % s19.parent
        )
    sig_map = parse_signature_xml(xml_path)
    if not sig_map:
        raise ValueError("签名清单 %s 未解析出任何有效签名（需 256 字节 RSA）" % xml_path)
    s19_sig = _match_signature(sig_map, s19)
    app_sig = _match_signature(sig_map, app_file)
    missing = []
    if s19_sig is None:
        missing.append(s19.name)
    if app_sig is None:
        missing.append(app_file.name)
    if missing:
        raise ValueError(
            "签名清单 %s 中缺少以下文件的签名: %s" % (xml_path.name, ", ".join(missing))
        )
    mode = "S19/TAR" if app_file.suffix.lower() == ".tar" else "S19/ZIP"
    log(
        "刷写准备: %s 模式，第1个传输=%s (%d bytes)，签名=%s，第2个传输=%s (%d bytes)，签名=%s"
        % (
            mode,
            s19.name,
            s19.stat().st_size,
            "256字节(%s...)" % s19_sig[:8].hex().upper(),
            app_file.name,
            app_file.stat().st_size,
            "256字节(%s...)" % app_sig[:8].hex().upper(),
        )
    )
    return [
        TransferItem(name=s19.name, path=s19, size=s19.stat().st_size, signature=s19_sig),
        TransferItem(
            name=app_file.name, path=app_file, size=app_file.stat().st_size, signature=app_sig
        ),
    ], None


def parse_signature_xml(xml_path: Path) -> Dict[str, bytes]:
    """解析北汽 5-*.xml 签名清单。

    返回 ``{fileName: 256 字节签名}``，fileName 为清单中的原始文件名（通常无扩展名，
    如 ``1-TBX_E00156231_V001`` / ``2-TBXE0015623112``）。非 256 字节签名项跳过。
    """
    root = ET.parse(str(xml_path)).getroot()
    out: Dict[str, bytes] = {}
    for node in root.iter("list"):
        name_el = node.find("fileName")
        sig_el = node.find("fileSIG")
        if name_el is None or sig_el is None or sig_el.text is None:
            continue
        hex_text = "".join(str(sig_el.text).split())
        if len(hex_text) != 512:
            continue
        try:
            sig = bytes.fromhex(hex_text)
        except ValueError:
            continue
        out[str(name_el.text).strip()] = sig
    return out


def _match_signature(sig_map: Dict[str, bytes], item_path: Path) -> Optional[bytes]:
    """按文件名从签名清单匹配：完整 stem 相等，或清单名是 stem 前缀（zip 常带版本后缀）。"""
    stem = item_path.stem
    for name, sig in sig_map.items():
        if stem == name or stem.startswith(name) or name.startswith(stem):
            return sig
    return None


def _find_signature_xml(directory: Path) -> Optional[Path]:
    """目录内找签名清单：优先 ``5-*.xml``，其次含 CRC 的 ``*.xml``，其次唯一 ``.xml``。"""
    files = [p for p in directory.iterdir() if p.is_file() and p.suffix.lower() == ".xml"]
    if not files:
        return None
    five = [p for p in files if p.name.startswith("5-")]
    if five:
        return max(five, key=lambda p: p.stat().st_size)
    crc = [p for p in files if "crc" in p.stem.lower()]
    if crc:
        return max(crc, key=lambda p: p.stat().st_size)
    if len(files) == 1:
        return files[0]
    return max(files, key=lambda p: p.stat().st_size)


def _pick_sibling_s19_zip(side_path: Path, want_suffix: str) -> Path:
    """单文件场景：优先同 stem 配对；否则目录内唯一匹配；多个时取最大。"""
    same_stem = side_path.with_suffix(want_suffix)
    if same_stem.is_file():
        return same_stem
    cands = [
        p
        for p in side_path.parent.iterdir()
        if p.is_file() and p.suffix.lower() == want_suffix
    ]
    if len(cands) == 1:
        return cands[0]
    if len(cands) > 1:
        return max(cands, key=lambda p: p.stat().st_size)
    raise ValueError(
        "未找到与 %s 配对的 %s 文件（期望同目录存在 .s19 与 .zip/.tar）"
        % (side_path.name, want_suffix)
    )


def _pick_sibling_app(side_path: Path) -> Path:
    """为 .s19 找第 2 个应用包：优先 .zip（n80ks），否则 .tar（B40L）。"""
    for suffix in (".zip", ".tar"):
        try:
            return _pick_sibling_s19_zip(side_path, suffix)
        except ValueError:
            continue
    raise ValueError(
        "未找到与 %s 配对的应用包（期望同目录存在 .zip 或 .tar）" % side_path.name
    )


def _resolve_s19_zip_pair(path: Path) -> Tuple[Path, Path, Optional[Path]]:
    suffix = path.suffix.lower()
    if suffix == ".s19":
        s19, app_file = path, _pick_sibling_app(path)
    elif suffix == ".zip":
        app_file, s19 = path, _pick_sibling_s19_zip(path, ".s19")
    elif suffix == ".tar":
        app_file, s19 = path, _pick_sibling_s19_zip(path, ".s19")
    else:
        raise ValueError(
            "请选择 .s19 / .zip / .tar 文件，或包含成对文件的目录: %s" % path
        )
    xml_path = _find_signature_xml(path.parent)
    return s19, app_file, xml_path


_EXTRACTED_TEMP_DIRS: List[Path] = []


def _is_doip_package(zip_path: Path) -> bool:
    """外层 DoIP 包：含 .s19、.xml，且含 .zip（n80ks）或 .tar（B40L）。"""
    try:
        with zipfile.ZipFile(str(zip_path)) as zf:
            lower = [n.lower() for n in zf.namelist()]
    except (zipfile.BadZipFile, OSError):
        return False
    has_app = any(n.endswith(".zip") for n in lower) or any(
        n.endswith(".tar") for n in lower
    )
    return (
        any(n.endswith(".s19") for n in lower)
        and any(n.endswith(".xml") for n in lower)
        and has_app
    )


def _extract_doip_package(zip_path: Path) -> Path:
    """解压外层 DoIP 包到临时目录并登记清理；返回临时目录路径。"""
    td = Path(tempfile.mkdtemp(prefix="doip_pkg_"))
    _EXTRACTED_TEMP_DIRS.append(td)
    with zipfile.ZipFile(str(zip_path)) as zf:
        zf.extractall(str(td))
    return td


def _cleanup_extracted_dirs() -> None:
    for td in _EXTRACTED_TEMP_DIRS:
        shutil.rmtree(str(td), ignore_errors=True)
    del _EXTRACTED_TEMP_DIRS[:]


def _locate_s19_zip_xml(
    directory: Path, depth: int = 3
) -> Optional[Tuple[Path, Path, Optional[Path]]]:
    """从目录树中递归定位 s19+应用包+签名xml，最多下探 depth 层。"""
    try:
        return _find_s19_zip_in_directory(directory)
    except ValueError:
        pass
    if depth <= 0:
        return None
    for sub in sorted(directory.iterdir(), key=lambda p: p.name):
        if sub.is_dir():
            found = _locate_s19_zip_xml(sub, depth - 1)
            if found is not None:
                return found
    return None


def _find_s19_zip_in_directory(
    path: Path,
) -> Tuple[Path, Path, Optional[Path]]:
    """目录内找 s19 + 应用包。有 .zip 时优先 zip（n80ks 不变）；否则用 .tar（B40L）。"""
    files = [p for p in path.iterdir() if p.is_file()]
    s19_by_stem = {p.stem: p for p in files if p.suffix.lower() == ".s19"}
    zip_by_stem = {p.stem: p for p in files if p.suffix.lower() == ".zip"}
    tar_by_stem = {p.stem: p for p in files if p.suffix.lower() == ".tar"}
    # 优先 zip，避免同目录偶发 .tar 时改变 n80ks 行为
    app_by_stem = zip_by_stem if zip_by_stem else tar_by_stem
    if not s19_by_stem or not app_by_stem:
        raise ValueError("目录内需同时包含 .s19 与 .zip/.tar 文件: %s" % path)
    common = sorted(set(s19_by_stem) & set(app_by_stem))
    if common:
        if len(common) > 1:
            stem = max(common, key=lambda s: s19_by_stem[s].stat().st_size)
        else:
            stem = common[0]
        s19, app_file = s19_by_stem[stem], app_by_stem[stem]
    else:
        s19 = max(s19_by_stem.values(), key=lambda p: p.stat().st_size)
        app_file = max(app_by_stem.values(), key=lambda p: p.stat().st_size)
    xml_path = _find_signature_xml(path)
    return s19, app_file, xml_path


def _prepare_transfer_items_from_path(
    path: Path, log: LogFn
) -> Tuple[List[TransferItem], Optional[bytes]]:
    if not path.exists():
        raise FileNotFoundError("刷写输入不存在: %s" % path)

    if path.is_dir():
        # 优先 S19+ZIP/TAR（北汽）；否则 CBF/RSA（奇瑞 v116）。
        try:
            s19, app_file, xml_path = _find_s19_zip_in_directory(path)
            return _s19_zip_transfer_items(s19, app_file, log, xml_path)
        except ValueError:
            pass
        cbf, rsa = _find_cbf_rsa_in_directory(path)
        return _cbf_rsa_transfer_items(cbf, rsa, log)

    suffix = path.suffix.lower()
    if suffix == ".zip":
        # 外层 DoIP 包（s19+xml+zip|tar）→ 解压后定位
        if _is_doip_package(path):
            log(
                "刷写准备: %s 识别为外层 DoIP 包，解压后定位其中 s19/xml/应用包"
                % path.name
            )
            extracted = _extract_doip_package(path)
            trio = _locate_s19_zip_xml(extracted)
            if trio is None:
                raise ValueError(
                    "外层 DoIP 包内未找到 s19+xml+zip/tar 三件套: %s" % path.name
                )
            s19, app_file, xml_path = trio
            return _s19_zip_transfer_items(s19, app_file, log, xml_path)
        # 否则视为内层升级包（2-TBX*.zip），同目录配对 s19 与签名
        s19, app_file, xml_path = _resolve_s19_zip_pair(path)
        return _s19_zip_transfer_items(s19, app_file, log, xml_path)
    if suffix in (".cbf", ".rsa"):
        cbf, rsa = _resolve_cbf_rsa_pair(path)
        return _cbf_rsa_transfer_items(cbf, rsa, log)
    if suffix == ".s19":
        s19, app_file, xml_path = _resolve_s19_zip_pair(path)
        return _s19_zip_transfer_items(s19, app_file, log, xml_path)
    if suffix == ".tar":
        # B40L：选了 2-*.tar，同目录配对 s19 + 5-*.xml
        s19, app_file, xml_path = _resolve_s19_zip_pair(path)
        return _s19_zip_transfer_items(s19, app_file, log, xml_path)
    if suffix == ".xml":
        # 签名清单：同目录找 s19 + 应用包（优先 zip，其次 tar）
        s19 = _pick_sibling_s19_zip(path, ".s19")
        app_file = _pick_sibling_app(path)
        return _s19_zip_transfer_items(s19, app_file, log, path)

    return [TransferItem(name=path.name, path=path, size=path.stat().st_size)], None


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
    # v116：34/36/37 在 programming + security(0/1)，默认确保 0x01；
    # 北汽 v515：34/36/37 需 Level3(0x11)，由 flash.transfer_security_level 指定。
    sec_lvl = int(getattr(fl, "transfer_security_level", None) or _FLASH_SEC_L1) & 0xFF
    _ensure_security_level(
        client,
        sec_lvl,
        log,
        state,
        "before RequestDownload (transfer_security_level=0x%02X)" % sec_lvl,
    )
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

    seq = _TRANSFER_DATA_FIRST_BLOCK_SEQ
    offset = 0
    total = item.size
    # 以「上次诊断活动」为基准；每块 36 成功后重置，避免几乎每块都插 3E 与 36 抢应答
    next_keepalive = time.monotonic() + _FLASH_KEEPALIVE_INTERVAL_SEC
    keepalive_logged = False
    prev_block_done: Optional[float] = None
    with item.path.open("rb") as fp:
        while offset < total:
            if cancel.is_set():
                raise FlashAborted("cancelled during transfer")
            now = time.monotonic()
            if now >= next_keepalive:
                try:
                    _flash_tester_present_between_blocks(client, log)
                    if not keepalive_logged:
                        log(
                            "刷写保活: 块间隙空闲超过 %.0fs 时发 TesterPresent（3E 80），"
                            "且必须收齐/排空后再发下一块 36"
                            % _FLASH_KEEPALIVE_INTERVAL_SEC
                        )
                        keepalive_logged = True
                except Exception as exc:
                    log("刷写保活 TesterPresent 失败: %s" % exc)
                next_keepalive = time.monotonic() + _FLASH_KEEPALIVE_INTERVAL_SEC
            read_start = time.monotonic()
            chunk = fp.read(payload)
            if not chunk:
                break
            read_sec = time.monotonic() - read_start
            send_start = time.monotonic()
            client.transfer_data(seq, chunk)
            send_sec = time.monotonic() - send_start
            tool_gap = 0.0
            if prev_block_done is not None:
                tool_gap = send_start - prev_block_done
            log(
                "TransferData 块#0x%02X: ECU处理 %.3fs | 工具间隔 %.3fs | 读文件 %.3fs"
                % (seq, send_sec, tool_gap, read_sec)
            )
            prev_block_done = time.monotonic()
            offset += len(chunk)
            seq = next_transfer_data_block_sequence(seq)
            # 36/76 已刷新 S3：从本块完成时刻重新计时
            next_keepalive = time.monotonic() + _FLASH_KEEPALIVE_INTERVAL_SEC
            if progress:
                progress(bytes_done_before + offset, total_all)

    exit_data = fl.transfer_exit_data
    # 使用 udsoncan 默认 send_request（P2 取 ECU 宣告值或配置 p2_timeout，见 uds.use_server_timing）
    client.request_transfer_exit(exit_data if exit_data else None)
    log("RequestTransferExit OK file=%s" % item.name)
    return total


def _inject_signatures_for_rid_0202(
    steps: Sequence[RoutineStep], items: Sequence[TransferItem], log: LogFn
) -> List[RoutineStep]:
    """
    北汽 v515：31 01 0202（完整性校验）RoutineControl option record 为对应文件的
    256 字节 RSA 签名（来自 5-*.xml）。data 留空的 0202 步骤按传输顺序依次填充
    （S19 先、ZIP 后）；文件缺签名时直接报错（v515 验签必须提供签名，不回退 CRC32）。
    """
    payload_iter = iter(
        _require_item_signature(item) for item in items
    )
    out: List[RoutineStep] = []
    for step in steps:
        rid = int(step.routine_id) & 0xFFFF
        if rid == 0x0202 and not bytes(step.data or b""):
            payload = next(payload_iter, None)
            if payload is None:
                raise RuntimeError(
                    "RoutineControl 0x0202 步骤数超过传输文件数（%d）" % len(items)
                )
            log(
                "RoutineControl 0x0202 自动填充 256 字节 RSA 签名（%s...）"
                % payload[:8].hex().upper()
            )
            out.append(
                RoutineStep(
                    routine_id=step.routine_id,
                    control_type=step.control_type,
                    data=payload,
                )
            )
        else:
            out.append(step)
    return out


def _require_item_signature(item: TransferItem) -> bytes:
    if item.signature is None:
        raise RuntimeError(
            "文件 %s 缺少 256 字节 RSA 签名（5-*.xml 未匹配）。v515 验签必须提供签名，不回退 CRC32。"
            % item.name
        )
    return item.signature


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
        sec_levels=sec_levels,
        l1_to_l3_delay_sec=sec_l1_l3_delay,
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

    need_post_download_session = bool(
        fl.post_transfer_routines or fl.post_transfer_raw_requests
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
            session_reassert=getattr(
                fl,
                "post_transfer_session_reassert",
                _REASSERT_DEFAULT_EXTENDED_PROGRAMMING,
            )
            or _REASSERT_DEFAULT_EXTENDED_PROGRAMMING,
        )

    post_steps = list(fl.post_transfer_routines or [])
    if post_steps and any(
        (int(s.routine_id) & 0xFFFF) == 0x0202 and not bytes(s.data or b"")
        for s in post_steps
    ):
        post_steps = _inject_signatures_for_rid_0202(post_steps, items, log)

    _run_routines(
        client,
        post_steps,
        log,
        cancel,
        state,
        sec_levels_reunlock_after_rid_dd02=(
            tuple(sec_levels) if post_steps else None
        ),
        l1_to_l3_delay_sec=sec_l1_l3_delay,
        dd02_signature=dd02_signature,
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
            log("后编程: 配置了 DD03 后等待 %.1fs（由重连逻辑执行后再发剩余请求）" % float(dly))
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
    try:
        items, dd02_signature = _prepare_transfer_items_from_path(path, log)
        log(
            "刷写准备: 完成，共 %d 个传输文件，总大小=%d bytes，DD02签名=%s，耗时=%.2fs"
            % (
                len(items),
                sum(x.size for x in items),
                "%d bytes" % len(dd02_signature) if dd02_signature else "无",
                time.monotonic() - t0,
            )
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
    finally:
        # 清理解压外层 DoIP 包产生的临时目录
        _cleanup_extracted_dirs()
