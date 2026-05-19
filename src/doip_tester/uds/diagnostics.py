import binascii
from typing import Any, Callable, List, Optional

from udsoncan import Request, services
from udsoncan.client import Client
from udsoncan.exceptions import NegativeResponseException

LogFn = Callable[[str], None]


class DiagnosticService:
    """High-level UDS helpers used by GUI / flash pipeline."""

    def __init__(self, client: Client, log: Optional[LogFn] = None):
        self._client = client
        self._log = log or (lambda m: None)

    @property
    def client(self) -> Client:
        return self._client

    def change_session_default(self) -> None:
        self._client.change_session(services.DiagnosticSessionControl.Session.defaultSession)
        self._log("Session: defaultSession")

    def change_session_extended(self) -> None:
        self._client.change_session(
            services.DiagnosticSessionControl.Session.extendedDiagnosticSession
        )
        self._log("Session: extendedDiagnosticSession")

    def change_session_programming(self) -> None:
        self._client.change_session(
            services.DiagnosticSessionControl.Session.programmingSession
        )
        self._log("Session: programmingSession")

    def tester_present(self) -> None:
        self._client.tester_present()

    def read_dids_raw(self, dids: List[int]) -> None:
        for did in dids:
            resp = self._client.test_data_identifier(did)
            if resp is None:
                self._log("DID 0x%04X: no response" % did)
                continue
            if resp.positive:
                blob = resp.original_payload
                if blob is None:
                    blob = resp.data or b""
                self._log(
                    "DID 0x%04X positive: %s"
                    % (did, binascii.hexlify(blob).decode("ascii"))
                )
            else:
                self._log(
                    "DID 0x%04X negative NRC=0x%02X"
                    % (did, resp.code if resp.code is not None else 0)
                )

    def read_dtcs_by_mask(self, status_mask: int) -> None:
        resp = self._client.get_dtc_by_status_mask(status_mask)
        if resp is None:
            self._log("ReadDTC: no response")
            return
        self._log("ReadDTC reportDTCByStatusMask OK")
        if resp.service_data is not None:
            dtcs = getattr(resp.service_data, "dtcs", None)
            if dtcs:
                for dtc in dtcs:
                    self._log("  %s" % dtc)
            else:
                self._log("  (no DTCs in response)")

    def clear_dtc(self) -> None:
        self._client.clear_dtc()
        self._log("ClearDTC OK")

    def ecu_reset_hard(self) -> None:
        self._client.ecu_reset(services.ECUReset.ResetType.hardReset)
        self._log("ECUReset hardReset requested")

    def format_negative(self, exc: NegativeResponseException) -> str:
        resp = exc.response
        sid = 0
        svc = getattr(resp, "service", None)
        if isinstance(svc, int):
            sid = svc
        elif svc is not None:
            rid = getattr(svc, "request_id", None)
            if callable(rid):
                try:
                    sid = int(rid())
                except Exception:
                    sid = 0
            else:
                try:
                    sid = int(svc)
                except Exception:
                    sid = 0
        return "NegativeResponse service=0x%02X NRC=0x%02X" % (
            sid,
            resp.code if resp.code is not None else 0,
        )

    def send_raw_payload(self, payload: bytes) -> None:
        """Send UDS request built from raw bytes (e.g. manual hex from GUI)."""
        req = Request.from_payload(payload)
        resp = self._client.send_request(req)
        self._log_generic_response(resp, label="Raw")

    def _log_generic_response(self, resp: Any, label: str = "UDS") -> None:
        if resp is None:
            self._log("%s: no response" % label)
            return
        if getattr(resp, "positive", False):
            blob = getattr(resp, "original_payload", None)
            if blob is None:
                blob = getattr(resp, "data", None) or b""
            self._log("%s positive: %s" % (label, binascii.hexlify(blob).decode("ascii")))
        else:
            self._log(
                "%s negative NRC=0x%02X"
                % (label, resp.code if getattr(resp, "code", None) is not None else 0)
            )

    def read_dtc_number_by_mask(self, status_mask: int) -> None:
        self._log("ReadDTC reportNumberOfDTCByStatusMask mask=0x%02X" % status_mask)
        resp = self._client.get_number_of_dtc_by_status_mask(status_mask)
        if resp is None or resp.service_data is None:
            self._log("  (no parsed data)")
            return
        n = getattr(resp.service_data, "dtc_count", None)
        if n is not None:
            self._log("  DTC count: %s" % n)
        else:
            self._log("  %s" % resp.service_data)

    def read_dtc_snapshot_identification(self) -> None:
        self._log("ReadDTC reportDTCSnapshotIdentification")
        resp = self._client.get_dtc_snapshot_identification()
        if resp is None:
            self._log("  no response")
            return
        sd = getattr(resp, "service_data", None)
        self._log("  OK%s" % (": %s" % sd if sd is not None else ""))

    def read_dtc_extended_by_record(self, record_number: int = 0xFF) -> None:
        self._log(
            "ReadDTC reportDTCExtendedDataRecordByRecordNumber record=0x%02X" % record_number
        )
        resp = self._client.get_dtc_extended_data_by_record_number(record_number)
        if resp is None:
            self._log("  no response")
            return
        self._log("  OK")

    def read_mirror_dtc_number_by_mask(self, status_mask: int) -> None:
        self._log(
            "ReadDTC reportNumberOfMirrorMemoryDTCByStatusMask mask=0x%02X" % status_mask
        )
        resp = self._client.get_mirrormemory_number_of_dtc_by_status_mask(status_mask)
        if resp is None:
            self._log("  no response")
            return
        self._log("  OK: %s" % getattr(resp, "service_data", resp))

    def security_request_seed(self, level: int) -> None:
        self._log("SecurityAccess requestSeed level=0x%02X" % level)
        resp = self._client.request_seed(level)
        self._log_generic_response(resp, label="SecurityAccess seed")

    def security_unlock(self, level: int) -> None:
        self._log("SecurityAccess unlock try level=0x%02X (依赖算法算 key)" % level)
        try:
            resp = self._client.unlock_security_access(level)
            self._log_generic_response(resp, label="SecurityAccess unlock")
        except Exception as exc:
            self._log("SecurityAccess unlock failed: %s" % exc)

    def routine_start(
        self, routine_id: int, data: Optional[bytes] = None
    ) -> None:
        self._log(
            "RoutineControl start rid=0x%04X data=%s"
            % (routine_id, binascii.hexlify(data or b"").decode("ascii"))
        )
        resp = self._client.routine_control(
            routine_id,
            services.RoutineControl.ControlType.startRoutine,
            data or b"",
        )
        if resp is None:
            self._log("  no response")
            return
        if getattr(resp, "positive", False):
            pl = getattr(resp, "original_payload", None) or getattr(resp, "data", None)
            if isinstance(pl, (bytes, bytearray)):
                self._log(
                    "RoutineControl positive: %s"
                    % binascii.hexlify(bytes(pl)).decode("ascii")
                )
            else:
                self._log("RoutineControl positive")
        else:
            self._log(
                "RoutineControl negative NRC=0x%02X"
                % (resp.code if getattr(resp, "code", None) is not None else 0)
            )

    def tester_present_once(self) -> None:
        # 单次 TesterPresent 也默认使用抑制正响应（3E 80）
        with self._client.suppress_positive_response(wait_nrc=False):
            self._client.tester_present()
        self._log("TesterPresent (3E) OK (suppress positive response)")
