"""DoIP Vehicle Identification / Announcement discovery (broadcast & multicast).

python-doipclient only supports IPv4 broadcast discovery. This module adds IPv4
multicast (239.x) join/send for DOIP_UDS stacks that announce on a multicast group.
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass
from typing import Callable, List, Optional

from doipclient.client import Parser
from doipclient.constants import A_DOIP_CTRL, UDP_DISCOVERY
from doipclient.messages import (
    VehicleIdentificationRequest,
    VehicleIdentificationResponse,
    payload_message_to_type,
)

LogFn = Callable[[str], None]


@dataclass(frozen=True)
class DiscoveryResult:
    ip: str
    port: int
    logical_address: int
    vin: str
    eid: bytes
    gid: bytes


def _pack_doip(protocol_version: int, payload_type: int, payload_data: bytes) -> bytes:
    header = struct.pack(
        "!BBHL",
        protocol_version & 0xFF,
        (0xFF ^ (protocol_version & 0xFF)) & 0xFF,
        payload_type & 0xFFFF,
        len(payload_data),
    )
    return header + payload_data


def _build_identification_request(protocol_version: int) -> bytes:
    message = VehicleIdentificationRequest()
    payload = bytes(message.pack())
    payload_type = payload_message_to_type[type(message)]
    return _pack_doip(protocol_version, payload_type, payload)


def _iface_ip_or_raise(bind_ip: Optional[str], mode: str) -> str:
    """Multicast requires an explicit IPv4 interface address on Windows/multi-NIC."""
    if bind_ip and bind_ip.strip():
        return bind_ip.strip()
    if mode == "multicast":
        raise ValueError(
            "组播发现需要指定「本机 IP」（顶部下拉框），"
            "否则 Windows 多网卡场景下无法确定加入组播组的网卡"
        )
    return ""


def discover_entities(
    mode: str,
    *,
    udp_port: int = UDP_DISCOVERY,
    protocol_version: int = 3,
    bind_ip: Optional[str] = None,
    multicast_address: str = "239.2.0.1",
    timeout: float = A_DOIP_CTRL,
    log: Optional[LogFn] = None,
) -> List[DiscoveryResult]:
    """Active discovery: send Vehicle Identification Request, collect responses.

    - ``broadcast``: destination ``255.255.255.255``
    - ``multicast``: destination ``multicast_address``; socket joins that group

    Returns unique entities keyed by (ip, logical_address). Empty list if none found
    within ``timeout`` (does not raise TimeoutError — caller decides).
    """
    _log = log or (lambda _m: None)
    mode = (mode or "").strip().lower()
    if mode not in ("broadcast", "multicast"):
        raise ValueError("discovery mode must be 'broadcast' or 'multicast', got %r" % mode)

    iface = _iface_ip_or_raise(bind_ip, mode)
    request = _build_identification_request(protocol_version)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        if mode == "broadcast":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            bind_host = iface if iface else ""
            sock.bind((bind_host, udp_port))
            destination = "255.255.255.255"
        else:
            # Bind to the chosen NIC unicast address (not INADDR_ANY).
            # On Windows multi-NIC, wildcard bind + IP_MULTICAST_IF alone often still
            # sends IGMP/UDP with the primary NIC's source IP (e.g. 192.168.10.1
            # while the UI selected 192.168.4.1). Binding to iface forces egress.
            sock.bind((iface, udp_port))
            group = multicast_address.strip()
            mreq = socket.inet_aton(group) + socket.inet_aton(iface)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface)
            )
            # Link-local TTL is enough for PC↔TBOX direct cable / same L2 segment
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            destination = group

        _log(
            "DoIP 发现(%s): dest=%s:%d bind=%s proto=0x%02X timeout=%.1fs"
            % (
                mode,
                destination,
                udp_port,
                iface or "(INADDR_ANY)",
                protocol_version,
                timeout,
            )
        )
        sock.sendto(request, (destination, udp_port))

        found: dict = {}
        parser = Parser()
        deadline = time.time() + float(timeout)
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            except OSError as exc:
                _log("DoIP 发现收包异常: %s" % exc)
                break

            parser.reset()
            result = parser.read_message(data)
            if type(result) is not VehicleIdentificationResponse:
                continue

            ip = addr[0]
            port = int(addr[1])
            la = int(result.logical_address) & 0xFFFF
            key = (ip, la)
            if key in found:
                continue

            vin = ""
            try:
                vin = str(result.vin or "")
            except Exception:
                vin = ""
            eid = bytes(getattr(result, "eid", b"") or b"")
            gid = bytes(getattr(result, "gid", b"") or b"")
            entity = DiscoveryResult(
                ip=ip,
                port=port,
                logical_address=la,
                vin=vin,
                eid=eid,
                gid=gid,
            )
            found[key] = entity
            _log(
                "发现 ECU: ip=%s logical_address=0x%04X vin=%r"
                % (ip, la, vin)
            )
    finally:
        if mode == "multicast" and iface:
            try:
                group = multicast_address.strip()
                mreq = socket.inet_aton(group) + socket.inet_aton(iface)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            except OSError:
                pass
        try:
            sock.close()
        except OSError:
            pass

    return list(found.values())
