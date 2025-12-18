from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional, Tuple, List

from rich.console import Console
from rich.panel import Panel

from mcp_kali_assistant.core.modes import get_scan_profile

console = Console()


def _verbosity_flags(mode: str) -> List[str]:
    """
    Choose Nmap verbosity based on mode.
    - fast/balanced/low-noise: -v
    - aggressive: -vv (more detail)
    """
    if mode == "aggressive":
        return ["-vv"]
    return ["-v"]


def run_nmap_scan(target: str, mode: str, output_xml_path: Path) -> Tuple[bool, Optional[str]]:
    """
    Runs Nmap with a mode-based profile and streams output live to the console.
    Saves results to XML at output_xml_path.

    Returns:
      (success, error_message_or_none)
    """
    profile = get_scan_profile(mode)

    output_xml_path.parent.mkdir(parents=True, exist_ok=True)

    # Nmap profile args in modes.py are designed to include "-oX" at the end.
    # We insert verbosity near the start.
    cmd = ["nmap", *_verbosity_flags(mode), *profile.nmap_args, str(output_xml_path), target]

    console.print(
        Panel(
            f"[bold cyan]Phase 2 – Service Discovery (Nmap)[/bold cyan]\n"
            f"[bold]Mode:[/bold] {mode}\n"
            f"[bold]Command:[/bold] [italic]{' '.join(cmd)}[/italic]\n\n"
            f"[dim]Tip: Streaming output is enabled. If a scan takes time, you will see progress lines here.[/dim]",
            border_style="cyan",
            title="Nmap Launch",
        )
    )

    try:
        # Stream stdout/stderr live. This makes Nmap feel "interactive".
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,          # line-buffered
            universal_newlines=True,
        )

        output_lines: List[str] = []
        assert proc.stdout is not None  # for type-checkers

        for line in proc.stdout:
            line = line.rstrip("\n")
            output_lines.append(line)
            # Print live. Keep it readable (no extra styling on every line).
            console.print(line)

        rc = proc.wait()

        if rc != 0:
            # Show last part of output for quick debugging.
            tail = "\n".join(output_lines[-30:]) if output_lines else ""
            console.print(
                Panel(
                    f"[bold red]Nmap exited with code {rc}[/bold red]\n\n"
                    f"[bold]Last output lines:[/bold]\n{tail}",
                    border_style="red",
                    title="Nmap Error",
                )
            )
            return False, f"nmap failed with exit code {rc}"

        if not output_xml_path.exists():
            console.print(
                Panel(
                    "[bold red]Nmap completed but XML output was not found.[/bold red]\n"
                    f"Expected: {output_xml_path}",
                    border_style="red",
                    title="Nmap Output Missing",
                )
            )
            return False, "nmap completed but XML output file missing"

        console.print(
            Panel(
                f"[bold green]Nmap scan completed successfully.[/bold green]\n"
                f"[bold]XML saved to:[/bold] {output_xml_path}",
                border_style="green",
                title="Nmap Complete",
            )
        )
        return True, None

    except FileNotFoundError:
        console.print(
            Panel(
                "[bold red]Error: nmap binary not found.[/bold red]\n\n"
                "Install it on Kali with:\n"
                "  sudo apt-get update\n"
                "  sudo apt-get install -y nmap",
                border_style="red",
                title="Missing Dependency",
            )
        )
        return False, "nmap not found"

    except PermissionError as ex:
        console.print(
            Panel(
                f"[bold red]Permission error running Nmap:[/bold red] {ex}\n\n"
                "Some Nmap scan types may require elevated privileges.\n"
                "Try running the tool with appropriate permissions or reduce scan intensity.",
                border_style="red",
                title="Permission Error",
            )
        )
        return False, str(ex)

    except Exception as ex:
        console.print(
            Panel(
                f"[bold red]Unexpected error running Nmap:[/bold red] {ex}",
                border_style="red",
                title="Unexpected Error",
            )
        )
        return False, str(ex)
