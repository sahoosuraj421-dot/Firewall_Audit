import os, secrets, warnings
warnings.filterwarnings("ignore")

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel
from langgraph_agent.graph import build_graph
from langgraph_agent.state import AuditState

app = FastAPI(title="Firewall File Downloader Agent API")

@app.get("/")
def root():
    return {
        "service": "Firewall File Downloader Agent API",
        "status": "online",
        "docs_url": "http://127.0.0.1:8000/docs",
        "endpoints": {
            "POST /run": "Trigger active IP scan and firewall download"
        }
    }


def require_key(x_api_key: str = Header(default="")):
    expected = os.getenv("AUDIT_API_KEY")
    if not expected:
        raise HTTPException(503, "AUDIT_API_KEY is not configured")
    if not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(401, "bad API key")

class RunReq(BaseModel):
    target: str
    password: str = ""
    use_llm: bool = False
    pull_vendor_config: bool = True
    vendor: str = ""


@app.post("/run", dependencies=[Depends(require_key)])
def run(req: RunReq):
    graph_input: AuditState = {
        "target": req.target,
        "password": req.password,
        "use_llm": req.use_llm,
        "pull_vendor_config": req.pull_vendor_config,
        "vendor": req.vendor,
        "errors": [],
    }
    res = build_graph().invoke(graph_input)
    if not res.get("authorized"):
        raise HTTPException(403, res.get("auth_reason"))
    res.pop("password", None)
    return res
