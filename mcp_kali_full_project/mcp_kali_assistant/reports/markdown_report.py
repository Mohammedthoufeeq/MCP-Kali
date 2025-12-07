from __future__ import annotations

from pathlib import Path

from mcp_kali_assistant.core.session import Session


def generate_markdown_report(session: Session, reports_root: Path) -> Path:
    reports_root.mkdir(parents=True, exist_ok=True)
    report_path = reports_root / f"{session.session_id}.md"

    lines = []
    lines.append(f"# MCP-Kali Assistant Report – Session {session.session_id}\n")
    lines.append("## Legal / Ethical Notice")
    lines.append("This report was generated for an **authorized** testing or CTF lab scenario only.")
    lines.append("Do not use this data for any form of unauthorized activity.\n")

    lines.append("## Target & Context")
    lines.append(f"- Target: `{session.target}`")
    lines.append(f"- Mode: `{session.mode}`")
    if session.hint:
        lines.append(f"- CTF Hint/Context: `{session.hint}`")
    lines.append("")

    lines.append("## Reachability Summary")
    r = session.reachability or {}
    lines.append(f"- ICMP reachable: `{r.get('icmp_reachable')}`")
    lines.append("- TCP checks:")
    for port, status in (r.get("tcp_checks") or {}).items():
        lines.append(f"  - {port}: {'open/reachable' if status else 'closed/unreachable'}")
    lines.append("")

    lines.append("## Nmap Summary")
    if not session.nmap_summary.get("hosts"):
        lines.append("No hosts or open ports discovered by Nmap.")
    else:
        for host in session.nmap_summary["hosts"]:
            lines.append(f"### Host {host.get('address')} ({host.get('addr_type')})")
            lines.append(f"- OS Guess: {host.get('os_guess', 'Unknown')}")
            lines.append("- Open Ports:")
            ports = host.get("ports") or []
            if not ports:
                lines.append("  - None")
            else:
                for p in ports:
                    if p.get("state") == "open":
                        lines.append(
                            f"  - {p.get('portid')}/{p.get('protocol')} "
                            f"({p.get('service_name')} {p.get('product') or ''} {p.get('version') or ''})"
                        )
            lines.append("")

    lines.append("## AI-Recommended Enumeration Steps")
    if not session.ai_recommendations:
        lines.append("No AI recommendations were recorded (AI offline or disabled).")
    else:
        for i, rcmd in enumerate(session.ai_recommendations, start=1):
            lines.append(f"### Step {i}: {rcmd.get('name')}")
            lines.append(f"- Category: `{rcmd.get('category', 'generic')}`")
            lines.append(f"- Priority: `{rcmd.get('priority', 5)}`")
            lines.append(f"- Command: `{rcmd.get('command')}`")
            if rcmd.get("rationale"):
                lines.append(f"- Rationale: {rcmd.get('rationale')}")
            if rcmd.get("notes"):
                lines.append(f"- Notes: {rcmd.get('notes')}")
            lines.append("")

    lines.append("## Commands Executed")
    if not session.executed_commands:
        lines.append("No enumeration commands were executed in this session.")
    else:
        for cmd in session.executed_commands:
            lines.append(f"### #{cmd.index} – {cmd.name}")
            lines.append(f"- Category: `{cmd.category}`")
            lines.append(f"- Priority: `{cmd.priority}`")
            lines.append(f"- Command: `{cmd.command}`")
            lines.append(f"- Started at: `{cmd.started_at}`")
            lines.append(f"- Ended at: `{cmd.ended_at}`")
            lines.append(f"- Exit code: `{cmd.exit_code}`")
            lines.append(f"- Log file: `{cmd.log_file}`")
            lines.append("")

    lines.append("## High-Level Next Steps (Educational)")
    lines.append(
        "Use this report to reflect on your enumeration process. "
        "Consider which services look most interesting or unusual. "
        "Without exploiting anything, think about: "
        "what information can be gathered next, what typical misconfigurations might exist, "
        "and how you would safely validate them within the rules of your CTF or authorized engagement."
    )
    lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path
