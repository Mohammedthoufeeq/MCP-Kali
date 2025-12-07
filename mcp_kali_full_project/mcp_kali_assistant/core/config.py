from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml


class AppConfig:
    """Application configuration loader and path manager."""

    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.config_path = root_dir / "config.yaml"
        self.example_config_path = root_dir / "config.example.yaml"
        self._data: Dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        if self.config_path.exists():
            with self.config_path.open("r", encoding="utf-8") as f:
                self._data = yaml.safe_load(f) or {}
        elif self.example_config_path.exists():
            with self.example_config_path.open("r", encoding="utf-8") as f:
                self._data = yaml.safe_load(f) or {}
        else:
            self._data = {}

        general = self._data.get("general", {})
        sessions_dir = general.get("sessions_dir", "sessions")
        self.sessions_dir = (self.root_dir / sessions_dir).resolve()
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

        self.logs_dir = self.sessions_dir / "logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        self.reports_dir = self.sessions_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    @property
    def ai_config(self) -> Dict[str, Any]:
        return self._data.get("ai", {})

    @classmethod
    def from_cwd(cls) -> "AppConfig":
        root = Path(__file__).resolve().parents[2]
        return cls(root)
