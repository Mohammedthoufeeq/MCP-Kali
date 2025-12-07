from __future__ import annotations

import platform
import socket
import subprocess
from typing import Dict


def icmp_ping(target: str, timeout: int = 3, count: int = 2) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), target]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), target]

    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout * (count + 1))
        return result.returncode == 0
    except Exception:
        return False


def tcp_port_check(target: str, port: int, timeout: int = 3) -> bool:
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except OSError:
        return False


def reachability_check(target: str) -> Dict[str, object]:
    result: Dict[str, object] = {"target": target, "icmp_reachable": False, "tcp_checks": {}}
    icmp_ok = icmp_ping(target)
    result["icmp_reachable"] = icmp_ok

    for port in (22, 80, 443):
        result["tcp_checks"][port] = tcp_port_check(target, port)

    return result
