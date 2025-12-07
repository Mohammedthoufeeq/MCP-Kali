from __future__ import annotations

import json
from typing import Any, Dict, Optional

import requests
from rich.console import Console

console = Console()


class AIClient:
    """HTTP client for talking to a local AI model (e.g., Ollama) on the Windows host."""

    def __init__(
        self,
        base_url: str,
        api_path: str,
        model_name: str,
        timeout_seconds: int = 60,
        api_key: str = "",
    ):
        self.base_url = base_url.rstrip("/")
        self.api_path = api_path
        self.model_name = model_name
        self.timeout = timeout_seconds
        self.api_key = api_key

    def _build_url(self) -> str:
        return f"{self.base_url}{self.api_path}"

    def generate(self, prompt: str) -> Optional[str]:
        """Call the AI model using an Ollama /api/generate-style endpoint."""

        url = self._build_url()
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload: Dict[str, Any] = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
        }

        try:
            resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=self.timeout)
        except requests.RequestException as e:
            console.print(f"[bold red]Error contacting AI endpoint: {e}[/bold red]")
            return None

        if not resp.ok:
            console.print(f"[bold red]AI endpoint returned HTTP {resp.status_code}[/bold red]")
            console.print(resp.text[:500])
            return None

        try:
            data = resp.json()
        except Exception as e:
            console.print(f"[bold red]Failed to parse AI response as JSON: {e}[/bold red]")
            console.print(resp.text[:500])
            return None

        text = data.get("response")
        if not isinstance(text, str):
            console.print("[bold red]AI response JSON did not contain a 'response' string.[/bold red]")
            console.print(str(data)[:500])
            return None

        return text
