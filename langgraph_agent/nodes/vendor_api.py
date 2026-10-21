import os
from connectors import fortigate, panos, cisco_restconf
from langgraph_agent.paths import load_yaml
from langgraph_agent.nodes.authorize import is_authorized
from langgraph_agent.security import verify_credentials
from langgraph_agent.downloader import save_firewall_file, generate_mock_firewall_config
from langgraph_agent.state import AuditState

DISPATCH = {"fortigate": fortigate.pull, "panos": panos.pull, "cisco_restconf": cisco_restconf.pull}

def _resolve_vendor_key(state: AuditState) -> str:
    vendor = (state.get("vendor") or "").lower()
    if vendor in DISPATCH:
        return vendor
    # Try to infer from classified or fingerprints
    for c in state.get("classified", []):
        v = (c.get("vendor") or "").lower()
        if "forti" in v:
            return "fortigate"
        if "palo" in v or "pan" in v:
            return "panos"
        if "cisco" in v:
            return "cisco_restconf"
    return "fortigate"

def _is_valid_live_response(res: dict) -> bool:
    if not isinstance(res, dict) or not res:
        return False
    # If any endpoint returned 401 or 403, it's an explicit auth failure
    for v in res.values():
        if isinstance(v, dict) and v.get("status") in (401, 403):
            return False
    valid_count = 0
    for v in res.values():
        if isinstance(v, dict):
            if "error" in v or v.get("status", 200) >= 400:
                continue
            valid_count += 1
        elif isinstance(v, list) and v:
            valid_count += 1
    return valid_count > 0

def vendor_api_node(state: AuditState) -> AuditState:
    if not state.get("pull_vendor_config"):
        return {"vendor_config": {}}   # always return a real key

    vendor = _resolve_vendor_key(state)
    target_host = state.get("selected_host") or state.get("target") or "192.168.1.1"

    vendors_cfg = load_yaml("vendors.yaml")
    if not isinstance(vendors_cfg, dict):
        return {
            "vendor_config": {},
            "auth_success": False,
            "errors": ["Invalid vendors.yaml configuration: expected a mapping of vendors."],
        }
    vendor_cfg = vendors_cfg.get(vendor, {})
    if not isinstance(vendor_cfg, dict):
        return {
            "vendor_config": {},
            "auth_success": False,
            "errors": [f"Invalid vendor configuration for {vendor}."],
        }
    cfg_host = vendor_cfg.get("host", target_host)
    if not isinstance(cfg_host, str) or not cfg_host.strip():
        return {
            "vendor_config": {},
            "auth_success": False,
            "errors": [f"Invalid API host configured for {vendor}."],
        }
    cfg_host = cfg_host.strip()

    ok, reason = is_authorized(cfg_host)
    if not ok:
        return {"vendor_config": {}, "auth_success": False, "errors": [f"vendor pull blocked: {reason}"]}

    # Password / credentials verification
    password = state.get("password") or ""
    if not password and state.get("password_required", True):
        return {
            "vendor_config": {},
            "auth_success": False,
            "errors": ["Authentication failed: No password provided."]
        }

    # Verify password (hybrid: live endpoint or credential check)
    auth_ok = False
    simulated = False
    config_data = None
    live_res = None

    # Check if a live connector pull succeeds with the provided token/password
    try:
        cfg = dict(vendor_cfg)
        cfg["password"] = password
        cfg["token"] = password
        cfg["key"] = password

        live_res = DISPATCH[vendor](cfg)

        if isinstance(live_res, dict) and "error" not in live_res:
            has_auth_err = any(isinstance(v, dict) and v.get("status") in (401, 403) for v in live_res.values())
            if has_auth_err:
                return {
                    "vendor_config": {},
                    "auth_success": False,
                    "errors": [f"Authentication failed: Incorrect password/token for {cfg_host}."]
                }
            if _is_valid_live_response(live_res):
                auth_ok = True
                config_data = live_res
    except Exception as exc:
        return {
            "vendor_config": {},
            "auth_success": False,
            "errors": [f"Live firewall configuration pull failed: {exc}"],
        }

    # If live pull was not active/successful, verify against configured secure credentials
    if not auth_ok:
        demo_mode = os.getenv("FIREWALL_DEMO_MODE", "").strip().lower() in {"1", "true", "yes"}
        if demo_mode and verify_credentials(password):
            auth_ok = True
            simulated = True
            config_data = generate_mock_firewall_config(cfg_host, vendor)
        else:
            endpoint_errors = []
            if isinstance(live_res, dict):
                endpoint_errors = [
                    f"{name}: {response['error']}"
                    for name, response in live_res.items()
                    if isinstance(response, dict) and response.get("error")
                ]
            return {
                "vendor_config": {},
                "auth_success": False,
                "errors": [
                    f"Authentication failed: Incorrect password or live API unavailable for {target_host}.",
                    *endpoint_errors,
                    "Synthetic configuration fallback is disabled; enable FIREWALL_DEMO_MODE only for local demonstrations.",
                ]
            }

    if config_data is None:
        return {
            "vendor_config": {},
            "auth_success": False,
            "errors": ["No firewall configuration was returned."],
        }

    # Save downloaded firewall file
    json_path, cfg_path = save_firewall_file(cfg_host, config_data)
    
    summary = {
        "host": cfg_host,
        "vendor": vendor,
        "json_path": json_path,
        "cfg_path": cfg_path,
        "size_bytes": os.path.getsize(json_path) if os.path.exists(json_path) else 0,
        "policies_count": len(config_data.get("firewall_policy", [])),
        "interfaces_count": len(config_data.get("interfaces", [])),
    }

    return {
        "vendor_config": config_data,
        "auth_success": True,
        "demo_mode": simulated,
        "vendor_api_host": cfg_host,
        "downloaded_file": json_path,
        "downloaded_cfg_file": cfg_path,
        "download_summary": summary,
    }
