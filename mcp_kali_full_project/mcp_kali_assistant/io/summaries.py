from __future__ import annotations

from typing import Any, Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def summarize_reachability(reachability: Dict[str, Any]) -> None:
    lines: List[str] = []
    lines.append(f"Host: {reachability.get('target', 'unknown')}")
    lines.append(f"ICMP reachable: {reachability.get('icmp_reachable')}")
    lines.append("TCP checks:")
    for port, status in reachability.get("tcp_checks", {}).items():
        lines.append(f"  - Port {port}: {'open' if status else 'closed/unreachable'}")
    text = "\n".join(lines)
    style = "green" if reachability.get("icmp_reachable") or any(reachability.get("tcp_checks", {}).values()) else "red"
    console.print(Panel(text, title="Phase 1 – Reachability Summary", border_style=style))


def summarize_nmap(nmap_summary: Dict[str, Any]) -> None:
    hosts = nmap_summary.get("hosts", [])
    if not hosts:
        console.print(Panel("No hosts found in Nmap results.", title="Phase 2 – Nmap Summary", border_style="red"))
        return

    table = Table(title="Phase 2 – Nmap Service Discovery Summary", show_lines=True)
    table.add_column("Host")
    table.add_column("Address Type")
    table.add_column("OS Guess")
    table.add_column("Open Ports (proto/service)")

    for host in hosts:
        addr = host.get("address", "?")
        addr_type = host.get("addr_type", "?")
        os_guess = host.get("os_guess", "Unknown")
        ports_desc = []
        for p in host.get("ports", []):
            if p.get("state") == "open":
                ports_desc.append(f"{p.get('portid')}/{p.get('protocol')} ({p.get('service_name')})")
        table.add_row(addr, addr_type, os_guess, "\n".join(ports_desc) if ports_desc else "None")

    console.print(table)


def show_ai_command_table(commands: List[Dict[str, Any]]) -> None:
    if not commands:
        console.print(Panel("No AI recommendations available.", title="Phase 3 – AI Strategy", border_style="red"))
        return

    table = Table(title="Phase 3 – AI-Recommended Enumeration Commands", show_lines=True)
    table.add_column("#", justify="right")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Priority")
    table.add_column("Command")
    table.add_column("Rationale")

    for i, cmd in enumerate(commands, start=1):
        table.add_row(
            str(i),
            cmd.get("name", f"cmd_{i}"),
            cmd.get("category", "generic"),
            str(cmd.get("priority", 5)),
            cmd.get("command", ""),
            cmd.get("rationale", ""),
        )

    console.print(table)
