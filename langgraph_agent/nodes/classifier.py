from langgraph_agent.state import AuditState


def _rule_based(fps):
    return [{"ip": f["ip"], "vendor": f["best_guess"],
             "confidence": min(1.0, f["score"] / 4) if f.get("score") else 0.5,
             "reason": "; ".join(f["evidence"]) or "no signature matched"}
            for f in fps]

def classifier_node(state: AuditState) -> AuditState:
    fps = state.get("fingerprints", [])
    result: AuditState = {"classified": _rule_based(fps)}
    if state.get("use_llm"):
        result["use_llm"] = False
        result["errors"] = ["LLM classification is not implemented; rule-based classification was used."]
    return result
