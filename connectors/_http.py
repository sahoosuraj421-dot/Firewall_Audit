import requests

def safe_get(url, **kw) -> object:
    """Per-endpoint error isolation: one failing endpoint must not kill the whole pull."""
    timeout = kw.pop("timeout", 5)
    try:
        r = requests.get(url, timeout=timeout, **kw)
    except requests.RequestException as e:
        return {"error": f"{type(e).__name__}: {e}"}

    if not r.ok:
        return {"status": r.status_code, "body": r.text[:500]}
    try:
        return r.json()
    except ValueError:
        return r.text[:5000]
