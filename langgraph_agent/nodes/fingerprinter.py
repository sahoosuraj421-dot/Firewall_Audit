from langgraph_agent.paths import load_yaml
from langgraph_agent.state import AuditState

def _score(host: dict, sig: dict) -> tuple[int, list[str]]:
    """banner match = 2 (strong), open port only = 1 (weak)."""
    score, why = 0, []
    for rule in sig["match"]:
        for p in host["ports"]:
            if p["port"] != rule.get("port"):
                continue
            if rule.get("any"):
                score += 1; why.append(f"port {p['port']} open")
                continue
            blob = f"{p.get('product','')} {p.get('version','')} {p.get('banner','')}".lower()
            hit = [n for n in rule.get("banner_contains", []) if n.lower() in blob]
            if hit:
                score += 2; why.append(f"port {p['port']} banner has {hit}")
    return score, why

def fingerprinter_node(state: AuditState) -> AuditState:
    sigs = load_yaml("fingerprint_db.yaml").get("signatures", [])
    out = []
    for h in state.get("hosts", []):
        scored = []
        for s in sigs:
            sc, why = _score(h, s)
            if sc:
                scored.append((sc, s["vendor"], why))
        scored.sort(reverse=True)
        out.append({
            "ip": h["ip"],
            "open_ports": [p["port"] for p in h["ports"]],
            "vendor_guesses": [v for _, v, _ in scored] or ["unknown"],
            "best_guess": scored[0][1] if scored else "unknown",
            "score": scored[0][0] if scored else 0,
            "evidence": scored[0][2] if scored else [],
        })
    return {"fingerprints": out}
