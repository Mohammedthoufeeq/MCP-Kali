# Windows Host AI Setup (Ollama + RTX 3050)

This document describes how to set up a **local AI model on Windows** (with an RTX 3050)
that is used by the MCP-Kali Assistant running inside a **Kali Linux VirtualBox VM**.

The goal is:

- Run the AI model on the Windows host (GPU-accelerated).
- Expose a local HTTP endpoint (Ollama API).
- Allow Kali to call the endpoint for **enumeration strategy only** (no exploits).


## 1. Prerequisites on Windows

1. **NVIDIA GPU Drivers**
   - Ensure your RTX 3050 drivers are installed and up to date.

2. **Ollama Installation**
   - Install Ollama for Windows from the official website.
   - After installation, you should be able to run `ollama` from PowerShell.

## 2. Pull a Suitable Model

From **PowerShell** on Windows:

```powershell
ollama pull llama3:latest
```

Adjust the model name if desired. The config uses `llama3:latest` by default.


## 3. Verify the Ollama API

Ollama exposes an API at:

```text
http://127.0.0.1:11434
```

Test from Windows:

```powershell
curl http://127.0.0.1:11434/api/tags
```

You should see JSON with available models.


## 4. VirtualBox Host-Only Networking

1. In VirtualBox, open **Settings** for the Kali VM.
2. Go to **Network**.
3. Configure one adapter as a **Host-only Adapter** (e.g. `VirtualBox Host-Only Ethernet Adapter`).
4. Start the Kali VM.

On Windows, check the IP of the Host-only adapter, often something like:

```text
192.168.56.1
```

From **Kali**, run:

```bash
curl http://192.168.56.1:11434/api/tags
```

If you see JSON output, networking is working.


## 5. Configure MCP-Kali Assistant

In Kali, inside the project directory:

```bash
cp config.example.yaml config.yaml
nano config.yaml
```

Edit the `ai` section to match your environment:

```yaml
ai:
  base_url: "http://192.168.56.1:11434"
  api_path: "/api/generate"
  api_key: ""
  model_name: "llama3:latest"
  timeout_seconds: 90
```


## 6. Test the Full Flow

From Kali:

```bash
cd /path/to/mcp_kali_full_project
source .venv/bin/activate   # if using the venv from setup.sh
python3 mcp_cli.py auto-analyse
```

- Accept the disclaimer.
- Provide your target, hint, and scan mode.
- The tool runs reachability checks, Nmap, and then calls the AI endpoint.
- The AI returns enumeration-only commands, which you can choose to run or skip.


## 7. Legal and Ethical Reminder

All usage must remain within the bounds of **authorized security testing** and CTF rules.

- The prompts are designed to limit the AI to **enumeration and learning**, not exploitation.
- You are responsible for following all laws, regulations, and rules of engagement.
