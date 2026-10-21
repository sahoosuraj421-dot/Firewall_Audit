import os
import xml.etree.ElementTree as ET
from connectors._http import safe_get

def pull(cfg: dict) -> dict:
    key = cfg.get("password") or cfg.get("key") or os.getenv(cfg.get("api_key_env", ""))
    if not key:
        return {"error": f"key / password not provided and env {cfg.get('api_key_env')} not set"}

    base = f"https://{cfg['host']}/api/"
    headers = {"X-PAN-KEY": key}   # header, so the key doesn't land in URLs/logs
    out = {}
    for ep in cfg["endpoints"]:
        params = ({"type": "op", "cmd": ep["cmd"]} if ep["type"] == "op"
                  else {"type": "config", "action": "get", "xpath": ep["xpath"]})
        response = safe_get(base, headers=headers, params=params,
                            verify=cfg.get("verify_tls", True))
        if isinstance(response, str):
            try:
                root = ET.fromstring(response)
            except ET.ParseError:
                out[ep["name"]] = {"error": "PAN-OS returned invalid XML"}
                continue
            if root.tag != "response" or root.get("status") != "success":
                out[ep["name"]] = {
                    "status": int(root.get("code", "400")),
                    "error": "PAN-OS rejected the request",
                }
                continue
            response = {"status": 200, "data": response}
        out[ep["name"]] = response
    return out
