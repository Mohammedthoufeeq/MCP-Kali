from __future__ import annotations

import shlex
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from mcp_kali_assistant.core.config import AppConfig
from mcp_kali_assistant.core.session import ExecutedCommand, Session
from mcp_kali_assistant.io.prompts import (
    confirm_disclaimer,
    prompt_target_and_context,
    show_banner,
)
from mcp_kali_assistant.io.summaries import (
    show_ai_command_table,
    summarize_nmap,
    summarize_reachability,
)
from mcp_kali_assistant.parsers.nmap_parser import parse_nmap_xml
from mcp_kali_assistant.scanners.nmap_scan import run_nmap_scan
from mcp_kali_assistant.scanners.ping_check import reachability_check
from mcp_kali_assistant.ai_engine.client import AIClient
from mcp_kali_assistant.ai_engine.strategy import call_ai_strategy
from mcp_kali_assistant.reports.markdown_report import generate_markdown_report

app = typer.Typer(help="MCP-like auto-analysis assistant for Kali CTF / authorized enumeration.")
console = Console()


def load_config() -> AppConfig:
    return AppConfig.from_cwd()


def build_ai_client(cfg: AppConfig) -> Optional[AIClient]:
    ai_cfg = cfg.ai_config
    base_url = ai_cfg.get("base_url")
    api_path = ai_cfg.get("api_path", "/api/generate")
    model_name = ai_cfg.get("model_name", "llama3:latest")
    timeout_seconds = int(ai_cfg.get("timeout_seconds", 90))
    api_key = ai_cfg.get("api_key", "")

    if not base_url:
        console.print("[bold yellow]AI base_url not configured. Phase 3 (AI Strategy) will be skipped.[/bold yellow]")
        return None

    return AIClient(
        base_url=base_url,
        api_path=api_path,
        model_name=model_name,
        timeout_seconds=timeout_seconds,
        api_key=api_key,
    )


def parse_command_selection(max_index: int, selection: str) -> List[int]:
    selection = selection.strip().lower()
    if selection in ("all", "a"):
        return list(range(1, max_index + 1))
    if not selection:
        return []
    indices: List[int] = []
    for part in selection.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            idx = int(part)
            if 1 <= idx <= max_index:
                indices.append(idx)
        except ValueError:
            continue
    return sorted(set(indices))


def ensure_tool_installed(tool: str) -> bool:
    """Check if a CLI tool is installed, and optionally ask to install it via apt-get."""
    if shutil.which(tool):
        return True

    console.print(f"[bold yellow]Tool '{tool}' is not installed.[/bold yellow]")
    if not Confirm.ask(f"Attempt to install '{tool}' via apt-get? (Requires sudo)", default=False):
        console.print(f"[bold yellow]Skipping commands that require '{tool}'.[/bold yellow]")
        return False

    try:
        console.print(f"[bold cyan]Running: sudo apt-get update && sudo apt-get install -y {tool}[/bold cyan]")
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        subprocess.run(["sudo", "apt-get", "install", "-y", tool], check=True)
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Failed to install '{tool}': {e}[/bold red]")
        return False

    return shutil.which(tool) is not None


def execute_commands(
    session: Session,
    commands: List[dict],
    selected_indices: List[int],
    cfg: AppConfig,
) -> None:
    if not selected_indices:
        console.print("[bold yellow]No commands selected for execution.[/bold yellow]")
        return

    session_dir = cfg.sessions_dir / session.session_id
    logs_dir = session_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    for idx in selected_indices:
        if idx < 1 or idx > len(commands):
            continue
        cmd_info = commands[idx - 1]
        raw_cmd = cmd_info.get("command", "").strip()
        if not raw_cmd:
            continue

        parts = shlex.split(raw_cmd)
        if not parts:
            continue
        tool = parts[0]

        if not ensure_tool_installed(tool):
            continue

        console.print(Panel(f"Executing command #{idx}: [bold]{raw_cmd}[/bold]", border_style="cyan"))
        started_at = datetime.utcnow().isoformat() + "Z"
        log_file = logs_dir / f"cmd_{idx:02d}.log"

        try:
            proc = subprocess.run(raw_cmd, shell=True, capture_output=True, text=True, timeout=600)
            ended_at = datetime.utcnow().isoformat() + "Z"
            log_file.write_text(proc.stdout + "\n\n[STDERR]\n" + proc.stderr, encoding="utf-8")
            preview = (proc.stdout or "")[:600]
            console.print(
                Panel(preview or "(no stdout output)", title=f"Output preview for #{idx}", border_style="green")
            )
            console.print(f"[bold]Exit code:[/bold] {proc.returncode}")
            session.executed_commands.append(
                ExecutedCommand(
                    index=idx,
                    name=cmd_info.get("name", f"cmd_{idx}"),
                    command=raw_cmd,
                    category=cmd_info.get("category", "generic"),
                    priority=int(cmd_info.get("priority", 5)),
                    rationale=cmd_info.get("rationale", ""),
                    started_at=started_at,
                    ended_at=ended_at,
                    exit_code=proc.returncode,
                    log_file=str(log_file),
                )
            )
        except subprocess.TimeoutExpired:
            ended_at = datetime.utcnow().isoformat() + "Z"
            console.print(f"[bold red]Command #{idx} timed out.[/bold red]")
            log_file.write_text("Command timed out.", encoding="utf-8")
            session.executed_commands.append(
                ExecutedCommand(
                    index=idx,
                    name=cmd_info.get("name", f"cmd_{idx}"),
                    command=raw_cmd,
                    category=cmd_info.get("category", "generic"),
                    priority=int(cmd_info.get("priority", 5)),
                    rationale=cmd_info.get("rationale", ""),
                    started_at=started_at,
                    ended_at=ended_at,
                    exit_code=-1,
                    log_file=str(log_file),
                )
            )


@app.command()
def auto_analyse() -> None:
    """Run the full auto-analysis pipeline."""
    cfg = load_config()
    show_banner()

    if not confirm_disclaimer():
        console.print("[bold yellow]Disclaimer not accepted. Exiting.[/bold yellow]")
        raise typer.Exit(code=1)

    target, hint, mode = prompt_target_and_context()
    session = Session(target=target, mode=mode, hint=hint)

    # Phase 1 – Reachability
    console.rule("[bold cyan]Phase 1 – Reachability[/bold cyan]")
    reach = reachability_check(target)
    session.reachability = reach
    summarize_reachability(reach)

    # Phase 2 – Nmap
    console.rule("[bold cyan]Phase 2 – Service Discovery (Nmap)[/bold cyan]")
    session_dir = cfg.sessions_dir / session.session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    nmap_xml_path = session_dir / "nmap.xml"
    ok, _ = run_nmap_scan(target, mode, nmap_xml_path)
    if ok and nmap_xml_path.exists():
        session.nmap_xml_path = str(nmap_xml_path)
        summary = parse_nmap_xml(nmap_xml_path)
        session.nmap_summary = summary
        summarize_nmap(summary)
    else:
        console.print("[bold red]Skipping Nmap parsing due to scan failure.[/bold red]")

    # Phase 3 – AI Strategy
    console.rule("[bold cyan]Phase 3 – AI Strategy[/bold cyan]")
    ai_client = build_ai_client(cfg)
    commands: List[dict] = []
    if ai_client is None:
        console.print("[bold yellow]AI client not configured. Skipping AI strategy phase.[/bold yellow]")
    else:
        ai_result = call_ai_strategy(
            ai_client,
            target=target,
            mode=mode,
            hint=hint,
            reachability=reach,
            nmap_summary=session.nmap_summary,
        )
        session.ai_raw_output = ai_result.get("raw")
        parsed = ai_result.get("parsed")
        if parsed is not None:
            session.ai_recommendations = ai_result.get("commands", [])
        commands = ai_result.get("commands", [])
        show_ai_command_table(commands)

    # Phase 4 – Enumeration & Findings
    console.rule("[bold cyan]Phase 4 – Enumeration & Findings[/bold cyan]")
    if commands:
        selection = Prompt.ask(
            "Which commands to run? [all / comma-separated indices / empty to skip]",
            default="",
        )
        selected_indices = parse_command_selection(len(commands), selection)
        execute_commands(session, commands, selected_indices, cfg)
    else:
        console.print("[bold yellow]No commands available to execute in this phase.[/bold yellow]")

    session_path = session.save(cfg.sessions_dir)
    console.print(f"[bold green]Session saved:[/bold green] {session_path}")

    report_path = generate_markdown_report(session, cfg.reports_dir)
    console.print(f"[bold green]Markdown report generated:[/bold green] {report_path}")


@app.command()
def report(session_id: Optional[str] = typer.Option(None, "--session-id", "-s", help="Session ID to report on")) -> None:
    """Generate or display a report for a previous session."""
    cfg = load_config()

    if not session_id:
        if not cfg.sessions_dir.exists():
            console.print("[bold red]No sessions directory found.[/bold red]")
            raise typer.Exit(code=1)
        console.print("[bold]Existing sessions:[/bold]")
        for item in sorted(cfg.sessions_dir.iterdir()):
            if item.is_dir() and (item / "session.json").exists():
                console.print(f"- {item.name}")
        console.print("Use --session-id to select one of the above.")
        raise typer.Exit()

    try:
        session = Session.load(cfg.sessions_dir, session_id)
    except FileNotFoundError as e:
        console.print(f"[bold red]{e}[/bold red]")
        raise typer.Exit(code=1)

    report_path = generate_markdown_report(session, cfg.reports_dir)
    console.print(Panel(f"Report generated at: [bold]{report_path}[/bold]", title="Report", border_style="green"))


if __name__ == "__main__":
    app()
