from __future__ import annotations

import json
from typing import Any, Dict, List

import yaml
from rich.console import Console

from mcp_kali_assistant.ai_engine.client import AIClient

console = Console()


PROMPT_TEMPLATE = """You are an experienced senior security engineer and CTF mentor.
You are helping a learner perform **authorized** reconnaissance and enumeration only.
You MUST follow these rules:

- ONLY provide enumeration and information-gathering commands (NO exploit payloads).
- DO NOT provide instructions to exploit vulnerabilities.
- DO NOT provide commands that modify, delete, or damage data.
- Assume this is a CTF-style lab or a system the user is explicitly authorized to test.
- Focus on learning, discovery, understanding likely attack surfaces, and safe enumeration.
- Provide minimal, high-level hints about how a flag might eventually be discovered,
  but do NOT give a full exploit chain or direct flag path.

Input context (JSON):
---------------------
{context_json}

Your task:
----------
Based on the context above, produce a STRICTLY machine-readable YAML document with this structure:

hosts:
  - host: "<ip or hostname>"
    os_guess: "<OS guess or Unknown>"
    key_services:
      - "short description of important service + port"
recommendations:
  - name: "Short name for this enumeration step"
    command: "SHELL COMMAND HERE (enumeration only, no exploits)"
    category: "one of: web, ssh, smb, rdp, database, ldap, ftp, smtp, dns, generic"
    priority: 1        # 1 = highest priority, larger number = lower priority
    rationale: "1-2 sentence explanation in simple language"
    notes: "Optional short comment, e.g. high-level hint about potential next steps"

Constraints:
------------
- The 'command' should be safe enumeration, e.g. nmap scripts, nikto, gobuster, enum4linux, smbclient, curl, wget, netcat, etc.
- DO NOT include exploit frameworks (no msfconsole exploit modules, no direct buffer overflow payloads).
- DO NOT attempt passwords or brute-force in your commands.
- Prefer read-only or discovery-focused tools.

Output:
-------
Return ONLY valid YAML. NO markdown, NO code fences, NO commentary outside the YAML itself.
"""


def build_context_json(target: str, mode: str, hint: str, reachability: Dict[str, Any], nmap_summary: Dict[str, Any]) -> str:
    context = {
        "target": target,
        "mode": mode,
        "hint": hint,
        "reachability": reachability,
        "nmap_summary": nmap_summary,
    }
    return json.dumps(context, indent=2)


def call_ai_strategy(
    client: AIClient,
    target: str,
    mode: str,
    hint: str,
    reachability: Dict[str, Any],
    nmap_summary: Dict[str, Any],
) -> Dict[str, Any]:
    context_json = build_context_json(target, mode, hint, reachability, nmap_summary)
    prompt = PROMPT_TEMPLATE.format(context_json=context_json)
    raw_output = client.generate(prompt)
    if raw_output is None:
        return {"raw": None, "parsed": None, "commands": []}

    try:
        data = yaml.safe_load(raw_output)
    except yaml.YAMLError:
        try:
            data = json.loads(raw_output)
        except Exception:
            console.print("[bold red]AI output could not be parsed as YAML or JSON.[/bold red]")
            console.print(str(raw_output)[:800])
            return {"raw": raw_output, "parsed": None, "commands": []}

    if not isinstance(data, dict):
        console.print("[bold red]AI parsed output is not a dict.[/bold red]")
        return {"raw": raw_output, "parsed": data, "commands": []}

    recs = data.get("recommendations", [])
    commands: List[Dict[str, Any]] = []
    if isinstance(recs, list):
        for r in recs:
            if not isinstance(r, dict):
                continue
            cmd = r.get("command")
            if not cmd or not isinstance(cmd, str):
                continue
            commands.append(
                {
                    "name": r.get("name", "Unnamed"),
                    "command": cmd.strip(),
                    "category": r.get("category", "generic"),
                    "priority": int(r.get("priority", 5)),
                    "rationale": r.get("rationale", ""),
                    "notes": r.get("notes", ""),
                }
            )

    commands.sort(key=lambda c: c.get("priority", 5))

    return {"raw": raw_output, "parsed": data, "commands": commands}
