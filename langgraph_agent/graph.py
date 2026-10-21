from langgraph.graph import StateGraph, END
from langgraph_agent.state import AuditState
from langgraph_agent.nodes.authorize import authorize_node
from langgraph_agent.nodes.scanner import scanner_node
from langgraph_agent.nodes.fingerprinter import fingerprinter_node
from langgraph_agent.nodes.classifier import classifier_node
from langgraph_agent.nodes.vendor_api import vendor_api_node
from langgraph_agent.nodes.reporter import reporter_node
from langgraph_agent.state import AuditState

def _after_auth(state: AuditState) -> str:
    return "scanner" if state.get("authorized") else "reporter"

def _after_scan(state: AuditState) -> str:
    return "fingerprinter" if state.get("is_active", True) else "reporter"

def build_graph():
    g = StateGraph(AuditState)
    for name, fn in [("authorize", authorize_node), ("scanner", scanner_node),
                     ("fingerprinter", fingerprinter_node), ("classifier", classifier_node),
                     ("vendor_api", vendor_api_node), ("reporter", reporter_node)]:
        g.add_node(name, fn)
    g.set_entry_point("authorize")
    g.add_conditional_edges("authorize", _after_auth, {"scanner": "scanner", "reporter": "reporter"})
    g.add_conditional_edges("scanner", _after_scan, {"fingerprinter": "fingerprinter", "reporter": "reporter"})
    g.add_edge("fingerprinter", "classifier")
    g.add_edge("classifier", "vendor_api")
    g.add_edge("vendor_api", "reporter")
    g.add_edge("reporter", END)
    return g.compile()
