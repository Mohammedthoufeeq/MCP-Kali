from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List


def parse_nmap_xml(xml_path: Path) -> Dict[str, Any]:
    if not xml_path.exists():
        raise FileNotFoundError(f"Nmap XML not found at {xml_path}")

    tree = ET.parse(str(xml_path))
    root = tree.getroot()

    hosts_summary: List[Dict[str, Any]] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        address_el = host.find("address")
        addr = address_el.get("addr") if address_el is not None else None
        addr_type = address_el.get("addrtype") if address_el is not None else None

        ports_info: List[Dict[str, Any]] = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                portid = port_el.get("portid")
                protocol = port_el.get("protocol")
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                state = state_el.get("state") if state_el is not None else None
                reason = state_el.get("reason") if state_el is not None else None
                service_name = service_el.get("name") if service_el is not None else None
                product = service_el.get("product") if service_el is not None else None
                version = service_el.get("version") if service_el is not None else None
                extrainfo = service_el.get("extrainfo") if service_el is not None else None

                ports_info.append(
                    {
                        "portid": portid,
                        "protocol": protocol,
                        "state": state,
                        "reason": reason,
                        "service_name": service_name,
                        "product": product,
                        "version": version,
                        "extrainfo": extrainfo,
                    }
                )

        os_guess = "Unknown"
        os_el = host.find("os")
        if os_el is not None:
            os_match = os_el.find("osmatch")
            if os_match is not None and os_match.get("name"):
                os_guess = os_match.get("name")

        hosts_summary.append(
            {
                "address": addr,
                "addr_type": addr_type,
                "os_guess": os_guess,
                "ports": ports_info,
            }
        )

    return {"hosts": hosts_summary}
