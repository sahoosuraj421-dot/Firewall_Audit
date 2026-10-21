import json, os, time
from pathlib import Path
from langgraph_agent.paths import ROOT
from langgraph_agent.state import AuditState

def _write_private(path: Path, text: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # reports may hold firewall policy
    with os.fdopen(fd, "w") as f:
        f.write(text)

def _markdown(p: dict) -> str:
    L = ["# Firewall Audit & Download Report", "", f"- Target: `{p['target']}`",
         f"- Authorized: {p['authorized']} ({p['auth_reason']})",
         f"- Target Active: {p.get('is_active', False)}",
         f"- Auth Success: {p.get('auth_success', False)}",
         f"- Synthetic demo data: {p.get('demo_mode', False)}",
         f"- Vendor API host: `{p.get('vendor_api_host', 'None')}`",
         f"- Config file: `{p.get('downloaded_file', 'None')}`",
         f"- LLM used: {p['use_llm']}", ""]
    L += ["## Hosts", "", "| IP | Vendor | Confidence | Open ports | Reason |", "|---|---|---|---|---|"]
    ports = {f["ip"]: f["open_ports"] for f in p.get("fingerprints", [])}
    for c in p.get("classified", []):
        L.append(f"| {c.get('ip')} | {c.get('vendor')} | {c.get('confidence')} | {ports.get(c.get('ip'), [])} | {c.get('reason','')} |")
    if p.get("vendor_config"):
        L += ["", "## Vendor config pulled", ""] + [f"- {k}" for k in p["vendor_config"]]
    if p.get("errors"):
        L += ["", "## Errors / Warnings", ""] + [f"- {e}" for e in p["errors"]]
    return "\n".join(L) + "\n"

def reporter_node(state: AuditState) -> AuditState:
    out_dir = Path(state.get("output_dir") or ROOT / "reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    payload = {
        "target": state.get("target"), "authorized": state.get("authorized"),
        "auth_reason": state.get("auth_reason"), "use_llm": state.get("use_llm"),
        "is_active": state.get("is_active", False),
        "auth_success": state.get("auth_success", False),
        "demo_mode": state.get("demo_mode", False),
        "vendor_api_host": state.get("vendor_api_host"),
        "downloaded_file": state.get("downloaded_file"),
        "downloaded_cfg_file": state.get("downloaded_cfg_file"),
        "fingerprints": state.get("fingerprints", []), "classified": state.get("classified", []),
        "vendor_config": state.get("vendor_config", {}), "errors": state.get("errors", []),
    }
    jp, mp = out_dir / f"audit-{ts}.json", out_dir / f"audit-{ts}.md"
    _write_private(jp, json.dumps(payload, indent=2))
    _write_private(mp, _markdown(payload))
    return {"report_path": str(jp), "report_md_path": str(mp), "password": ""}
