from __future__ import annotations

from typing import Tuple

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

console = Console()

DISCLAIMER_TEXT = """[bold red]LEGAL / ETHICAL USE ONLY[/bold red]

This tool is designed only for:
- Educational use in controlled lab or CTF environments.
- Security testing on systems that you [bold]own[/bold] or are [bold]explicitly authorized[/bold] to test.

It must NOT be used for:
- Unauthorized scanning of networks or hosts.
- Exploitation of vulnerabilities on systems without written permission.

By continuing, you confirm that:
- You understand the legal and ethical implications.
- You accept full responsibility for how you use this tool.
- You will not use this tool for illegal or unethical purposes.
"""


def show_banner() -> None:
    banner = r"""
 __  __  _____   _____      _  __      _ _ 
|  \/  |/ ____| / ____|    | |/ /     (_) |
| \  / | |    | |     __ _ | ' / _ __  _| |
| |\/| | |    | |    / _` ||  < | '_ \| | |
| |  | | |____| |___| (_| || . \| |_) | | |
|_|  |_|\_____|\_____\__,_||_|\_\ .__/|_|_|
                                | |        
                                |_|        
"""
    console.print(f"[bold bright_magenta]{banner}[/bold bright_magenta]")


def confirm_disclaimer() -> bool:
    console.print(Panel(DISCLAIMER_TEXT, title="[bold red]DISCLAIMER[/bold red]", border_style="red"))
    return Confirm.ask(
        "[bold yellow]Do you confirm that you are authorized to test the specified target(s)?[/bold yellow]",
        default=False,
    )


def prompt_target_and_context() -> Tuple[str, str, str]:
    console.rule("[bold cyan]Phase 0 – Target & Context[/bold cyan]")
    target = Prompt.ask("[bold green]Target IP/hostname or small CIDR[/bold green]")
    hint = Prompt.ask("[bold green]Any CTF hint or context (optional)[/bold green]", default="")
    mode = Prompt.ask(
        "[bold green]Scan mode[/bold green] [fast/balanced/aggressive/low-noise]",
        choices=["fast", "balanced", "aggressive", "low-noise"],
        default="balanced",
    )
    return target.strip(), hint.strip(), mode.strip()
