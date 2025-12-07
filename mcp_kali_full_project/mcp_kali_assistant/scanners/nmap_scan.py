from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional, Tuple

from rich.console import Console
from rich.progress import Progress

from mcp_kali_assistant.core.modes import get_scan_profile

console = Console()


def run_nmap_scan(target: str, mode: str, output_xml_path: Path) -> Tuple[bool, Optional[str]]:
    profile = get_scan_profile(mode)

    if not output_xml_path.parent.exists():
        output_xml_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["nmap", *profile.nmap_args, str(output_xml_path), target]

    console.print(f"[bold cyan]Running Nmap ({mode}):[/bold cyan] [italic]{' '.join(cmd)}[/italic]")

    try:
        with Progress() as progress:
            task = progress.add_task("Nmap scan in progress...", start=False)
            progress.start_task(task)
            proc = subprocess.run(cmd, capture_output=True, text=True)
            progress.update(task, advance=100)
        if proc.returncode != 0:
            console.print(f"[bold red]Nmap exited with code {proc.returncode}[/bold red]")
            if proc.stderr:
                console.print(proc.stderr)
            return False, proc.stderr
        else:
            console.print("[bold green]Nmap scan completed.[/bold green]")
            return True, proc.stdout
    except FileNotFoundError:
        console.print("[bold red]Error: nmap binary not found. Please install nmap and ensure it is in PATH.[/bold red]")
        return False, "nmap not found"
    except Exception as ex:
        console.print(f"[bold red]Unexpected error running nmap: {ex}[/bold red]")
        return False, str(ex)
