from __future__ import annotations

import json
import random
import string
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


def _generate_session_id() -> str:
    ts = time.strftime("%Y%m%d-%H%M%S")
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    return f"{ts}-{rand}"


@dataclass
class ExecutedCommand:
    index: int
    name: str
    command: str
    category: str
    priority: int
    rationale: str
    started_at: str
    ended_at: str
    exit_code: int
    log_file: str


@dataclass
class Session:
    target: str
    mode: str
    hint: str = ""
    session_id: str = field(default_factory=_generate_session_id)
    reachability: Dict[str, Any] = field(default_factory=dict)
    nmap_xml_path: Optional[str] = None
    nmap_summary: Dict[str, Any] = field(default_factory=dict)
    ai_raw_output: Optional[str] = None
    ai_recommendations: List[Dict[str, Any]] = field(default_factory=list)
    executed_commands: List[ExecutedCommand] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["executed_commands"] = [asdict(c) for c in self.executed_commands]
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        cmds = [ExecutedCommand(**c) for c in data.get("executed_commands", [])]
        data = {**data, "executed_commands": cmds}
        return cls(**data)

    def save(self, sessions_root: Path) -> Path:
        session_dir = sessions_root / self.session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        path = session_dir / "session.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return path

    @classmethod
    def load(cls, sessions_root: Path, session_id: str) -> "Session":
        session_dir = sessions_root / session_id
        path = session_dir / "session.json"
        if not path.exists():
            raise FileNotFoundError(f"Session file not found: {path}")
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)
