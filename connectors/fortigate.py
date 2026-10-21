import os

from connectors._http import safe_get


def pull(cfg: dict) -> dict:
    token = cfg.get("password") or cfg.get("token") or os.getenv(cfg.get("api_token_env", ""))
    if not token:
        return {"error": f"token / password not provided and env {cfg.get('api_token_env')} not set"}

    base = f"https://{cfg['host']}"
    headers = {"Authorization": f"Bearer {token}"}
    return {
        ep["name"]: safe_get(
            f"{base}{ep['path']}",
            headers=headers,
            params={"vdom": cfg.get("vdom", "root")},
            verify=cfg.get("verify_tls", True),
        )
        for ep in cfg["endpoints"]
    }
