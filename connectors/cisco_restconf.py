import os
from connectors._http import safe_get

def pull(cfg: dict) -> dict:
    u = cfg.get("username") or os.getenv(cfg.get("username_env", ""), "admin")
    p = cfg.get("password") or os.getenv(cfg.get("password_env", ""))
    if not (u and p):
        return {"error": "credentials not provided and env not set"}

    base = f"https://{cfg['host']}"
    headers = {"Accept": "application/yang-data+json"}
    return {ep["name"]: safe_get(f"{base}{ep['path']}", auth=(u, p), headers=headers,
                                 verify=cfg.get("verify_tls", True))
            for ep in cfg["endpoints"]}
