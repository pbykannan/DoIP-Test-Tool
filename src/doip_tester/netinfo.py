"""Enumerate local IPv4 addresses for DoIP client bind (multi-NIC)."""

import socket
from typing import List


def enumerate_ipv4_addresses() -> List[str]:
    """Non-loopback IPv4 addresses on this machine, sorted."""
    try:
        import psutil

        seen = set()
        for _, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family != socket.AF_INET:
                    continue
                ip = addr.address
                if ip.startswith("127."):
                    continue
                seen.add(ip)
        # Prefer RFC1918 / global over APIPA (169.254.x) in dropdown order
        api = sorted(x for x in seen if x.startswith("169.254."))
        good = sorted(x for x in seen if x not in api)
        return good + api
    except ImportError:
        try:
            hostname = socket.gethostname()
            _, _, ips = socket.gethostbyname_ex(hostname)
            seen = {ip for ip in ips if not ip.startswith("127.")}
            api = sorted(x for x in seen if x.startswith("169.254."))
            good = sorted(x for x in seen if x not in set(api))
            return good + api
        except OSError:
            return []
