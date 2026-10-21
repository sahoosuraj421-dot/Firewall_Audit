# 🛡️ Firewall File Downloader Agent

A deterministic LangGraph agent that detects authorized network targets and retrieves firewall configuration through vendor APIs.

Runs **100% locally and rule-based without requiring an LLM**. The legacy `--llm`/`use_llm` option does not call an LLM; it reports that rule-based classification was used.

---

## 🔄 Complete Execution Flow

```
1. Run Program (CLI or Streamlit UI)
   │
   ▼
2. Ask for Target IP or Subnet (e.g. 192.168.14.1 or 192.168.14.0/24)
   │
   ▼
3. Probe Reachability & Scan Target
   │
   ├── [If INACTIVE / Unreachable] ──► Report offline & terminate (No password prompt)
   │
   └── [If ACTIVE / Online] ──────────► Display active host & open ports
                                         │
                                         ▼
4. Prompt for Login Password or API Token (masked in CLI/UI)
   │
   ▼
5. Authenticate with Firewall Device / Gateway
   │
   ├── [If Authentication Fails] ────► Access denied. Abort download without saving.
   │
   └── [If Password CORRECT] ────────► Download Firewall Config File (.json & .cfg)
                                       Save to downloads/ & generate audit report
```

---

## 🚀 Quick Start

### 0. Activate Virtual Environment (Recommended on Windows)
```powershell
.\.venv\Scripts\Activate.ps1
```

### 1. Run Interactive CLI
```powershell
python cli.py
```
The CLI prompts for the password securely. Avoid passing credentials as command-line arguments because shell history and process listings may expose them.

### 2. Run Streamlit UI
Launch the interactive web application using the virtualenv Python:
```powershell
python -m streamlit run ui/app.py
```
*(Or directly: `.\.venv\Scripts\streamlit.exe run ui/app.py`)*

### 3. Run FastAPI Endpoint (Optional)
Set a non-empty `AUDIT_API_KEY` in the project-root `.env` before starting the API.
```powershell
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```
*(Or directly: `.\.venv\Scripts\uvicorn.exe api.main:app --host 127.0.0.1 --port 8000`)*


---

## 🧪 Run Tests

Execute the complete test suite:
```bash
pytest
```
The test suite validates:
- Authorization gatekeeping
- Fast active / inactive target detection
- API password non-disclosure and vendor connector authentication formats
- Download blocking when live authentication fails
- Synthetic configuration generation only when demo mode is explicitly enabled

---

## 📁 Project Structure

```
firewall-audit-agent/
├── cli.py                     # Interactive CLI entrypoint
├── ui/
│   └── app.py                 # Streamlit Web UI (no LLM required)
├── api/
│   └── main.py                # FastAPI REST endpoint
├── config/
│   ├── authorized_subnets.yaml# Authorized scan & download targets
│   ├── settings.yaml          # Scan timeouts & ports
│   ├── fingerprint_db.yaml    # Firewall vendor signatures
│   └── vendors.yaml           # Vendor API configurations
├── connectors/                # HTTP & REST connectors (FortiGate, PAN-OS, Cisco)
├── downloads/                 # Downloaded firewall configuration files (.json & .cfg)
├── reports/                   # Audit summary reports (JSON & Markdown)
├── langgraph_agent/
│   ├── graph.py               # LangGraph state machine
│   ├── security.py            # Password hashing, masking & verification
│   ├── downloader.py          # Config file parsing & backup generator
│   └── nodes/                 # Graph nodes (authorize, scanner, vendor_api, reporter)
└── tests/
    └── test_agent.py          # Pytest unit tests
```

---

## 🔐 Security Features

- **Masked Password Entry**: CLI and UI hide typed passwords. This is not encryption at rest; use HTTPS when exposing the API or UI beyond localhost.
- **Safety Gatekeeper**: Only authorized subnets or explicitly confirmed target networks can be scanned.
- **Zero Cloud / LLM Dependency**: Operates completely offline and deterministically without sending credentials to external APIs.

### Local demonstration mode

Without a reachable vendor API, the app does not claim a real firewall backup was downloaded. To generate a synthetic sample configuration for local demonstrations only, set `FIREWALL_DEMO_MODE=true` in `.env`. The built-in demonstration credentials are accepted only in this mode. Generated sample files are not device data.

The `.env` file is loaded from the project root. Keep it private and never commit it.
Vendor TLS certificate verification is enabled by default; set `verify_tls: false` only for a controlled lab with a self-signed certificate.
