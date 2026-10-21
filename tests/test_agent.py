import pytest
import requests
from fastapi.testclient import TestClient
from langgraph_agent.nodes.authorize import is_authorized
from langgraph_agent.nodes.classifier import classifier_node
from langgraph_agent.nodes import scanner
from langgraph_agent.graph import build_graph

XML = """<nmaprun><host><status state="up"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/><address addr="192.168.1.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="http" product="" tunnel="ssl"/><script id="http-title" output="FortiGate Login"/></port>
<port protocol="tcp" portid="10443"><state state="open"/><service name="https"/></port>
</ports></host></nmaprun>"""

@pytest.mark.parametrize("t,ok", [("192.168.1.0/24", True), ("192.168.1.55", True), ("192.168.1.0/16", False),
    ("8.8.8.8", False), ("::1", False), ("255.255.255.0", False), ("-iL /etc/passwd", False),
    ("", False), ("example.com", False)])
def test_authorize(t, ok):
    assert is_authorized(t)[0] is ok

def test_authorize_rejects_invalid_ip_before_scope_lookup():
    assert is_authorized("not-an-ip")[0] is False

def test_ui_refuses_to_scan_unscoped_target(monkeypatch):
    from pathlib import Path
    from streamlit.testing.v1 import AppTest

    monkeypatch.setattr(
        scanner,
        "check_target_active",
        lambda target: pytest.fail("unscoped target must not be scanned"),
    )
    app_file = Path(__file__).resolve().parents[1] / "ui" / "app.py"
    app = AppTest.from_file(str(app_file)).run()
    app.text_input[0].set_value("not-an-ip")
    app.button[0].click().run()

    assert not app.exception
    assert any("Target was not scanned" in element.value for element in app.error)

def test_parse_picks_ip_not_mac():
    h = scanner._parse_nmap_xml(XML)
    assert h[0]["ip"] == "192.168.1.1" and "FortiGate" in h[0]["ports"][0]["banner"]

def test_llm_flag_reports_rule_based_fallback():
    result = classifier_node({"use_llm": True, "fingerprints": []})
    assert result.get("use_llm") is False
    assert "not implemented" in (result.get("errors") or [""])[0]

def test_full_graph(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "_run_nmap", lambda t: XML)
    r = build_graph().invoke({"target": "192.168.1.1", "output_dir": str(tmp_path), "errors": []})
    assert r["classified"][0]["vendor"] == "Fortinet FortiGate"
    assert (tmp_path / r["report_path"].split("/")[-1]).exists()
    assert r["password"] == ""

def test_unauthorized_never_scans(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "_run_nmap", lambda t: pytest.fail("must not scan"))
    r = build_graph().invoke({"target": "8.8.8.8", "output_dir": str(tmp_path), "errors": []})
    assert r["authorized"] is False

def test_nmap_missing_is_handled(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner.shutil, "which", lambda x: None)
    r = build_graph().invoke({"target": "192.168.1.1", "output_dir": str(tmp_path), "errors": []})
    assert any("nmap is not installed" in e for e in r["errors"])

def test_vendor_host_out_of_scope_blocked(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "_run_nmap", lambda t: XML)
    from langgraph_agent.nodes import vendor_api
    monkeypatch.setattr(vendor_api, "load_yaml", lambda n: {"fortigate": {"host": "8.8.8.8"}})
    r = build_graph().invoke({"target": "192.168.1.1", "pull_vendor_config": True, "vendor": "fortigate",
                              "output_dir": str(tmp_path), "errors": []})
    assert any("blocked" in e for e in r["errors"])

def test_vendor_api_host_is_reported_and_used_for_file(monkeypatch, tmp_path):
    from langgraph_agent.nodes import vendor_api

    saved_hosts = []
    monkeypatch.setattr(scanner, "_run_nmap", lambda t: XML)
    monkeypatch.setattr(
        vendor_api,
        "load_yaml",
        lambda name: {"fortigate": {"host": "192.168.1.55"}} if name == "vendors.yaml" else {},
    )
    monkeypatch.setitem(
        vendor_api.DISPATCH,
        "fortigate",
        lambda cfg: {"system_status": {"hostname": "test-firewall"}},
    )

    def fake_save(host, config):
        saved_hosts.append(host)
        return str(tmp_path / "config.json"), str(tmp_path / "config.cfg")

    monkeypatch.setattr(vendor_api, "save_firewall_file", fake_save)
    result = build_graph().invoke({
        "target": "192.168.1.1",
        "pull_vendor_config": True,
        "password": "api-token",
        "output_dir": str(tmp_path),
        "errors": [],
    })
    assert result["vendor_api_host"] == "192.168.1.55"
    assert saved_hosts == ["192.168.1.55"]

def _mock_offline(*a, **k):
    raise requests.RequestException("offline in test")

def test_incorrect_password_blocks_download(monkeypatch, tmp_path):
    monkeypatch.delenv("FIREWALL_DEMO_MODE", raising=False)
    monkeypatch.setattr(scanner, "_run_nmap", lambda t: XML)
    monkeypatch.setattr(requests, "get", _mock_offline)
    r = build_graph().invoke({
        "target": "192.168.1.1",
        "pull_vendor_config": True,
        "password": "wrong_password_12345",
        "output_dir": str(tmp_path),
        "errors": []
    })
    assert r.get("auth_success") is False
    assert r.get("downloaded_file") is None
    assert any("Incorrect password" in e for e in r["errors"])

def test_demo_credentials_are_disabled_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("FIREWALL_DEMO_MODE", raising=False)
    monkeypatch.setattr(scanner, "_run_nmap", lambda t: XML)
    monkeypatch.setattr(requests, "get", _mock_offline)
    r = build_graph().invoke({
        "target": "192.168.1.1",
        "pull_vendor_config": True,
        "password": "admin",
        "output_dir": str(tmp_path),
        "errors": [],
    })
    assert r.get("auth_success") is False
    assert r.get("downloaded_file") is None

def test_correct_password_downloads_file(monkeypatch, tmp_path):
    monkeypatch.setenv("FIREWALL_DEMO_MODE", "true")
    monkeypatch.setattr(scanner, "_run_nmap", lambda t: XML)
    monkeypatch.setattr(requests, "get", _mock_offline)
    r = build_graph().invoke({
        "target": "192.168.1.1",
        "pull_vendor_config": True,
        "password": "admin",
        "output_dir": str(tmp_path),
        "errors": []
    })
    assert r.get("auth_success") is True
    assert r.get("demo_mode") is True
    assert r.get("downloaded_file") is not None
    assert (tmp_path / r["report_path"].split("/")[-1]).exists()


def test_inactive_target_handling(monkeypatch, tmp_path):
    empty_xml = "<nmaprun></nmaprun>"
    monkeypatch.setattr(scanner, "_run_nmap", lambda t: empty_xml)
    r = build_graph().invoke({
        "target": "192.168.1.1",
        "output_dir": str(tmp_path),
        "errors": []
    })
    assert r.get("is_active") is False
    assert any("INACTIVE" in e for e in r["errors"])

def test_api_does_not_echo_password(monkeypatch):
    from api import main

    class Graph:
        def invoke(self, state):
            return {"authorized": True, "password": state["password"]}

    monkeypatch.setenv("AUDIT_API_KEY", "test-api-key")
    monkeypatch.setattr(main, "build_graph", lambda: Graph())
    response = TestClient(main.app).post(
        "/run",
        json={"target": "192.168.1.1", "password": "secret-value"},
        headers={"X-API-Key": "test-api-key"},
    )
    assert response.status_code == 200
    assert "password" not in response.json()

def test_api_requires_configured_key(monkeypatch):
    from api import main

    monkeypatch.delenv("AUDIT_API_KEY", raising=False)
    response = TestClient(main.app).post("/run", json={"target": "192.168.1.1"})
    assert response.status_code == 503

def test_fortigate_connector_sends_token_as_bearer(monkeypatch):
    from connectors import fortigate

    captured = {}

    class Response:
        ok = True

        def json(self):
            return {"status": "ok"}

    def fake_get(url, **kwargs):
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr(requests, "get", fake_get)
    result = fortigate.pull({
        "host": "192.168.1.1",
        "password": "test-token",
        "endpoints": [{"name": "status", "path": "/api/status"}],
    })
    assert result == {"status": {"status": "ok"}}
    assert captured["headers"]["Authorization"] == "Bearer test-token"

def test_panos_connector_accepts_success_xml(monkeypatch):
    from connectors import panos

    monkeypatch.setattr(
        panos,
        "safe_get",
        lambda *args, **kwargs: '<response status="success"><result>ok</result></response>',
    )
    result = panos.pull({
        "host": "192.168.1.1",
        "password": "test-key",
        "endpoints": [{"name": "system_info", "type": "op", "cmd": "<show/>"}],
    })
    assert result["system_info"]["status"] == 200
