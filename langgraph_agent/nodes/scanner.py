import os, shutil, subprocess, sys
import xml.etree.ElementTree as ET
from typing import Any
from langgraph_agent.paths import load_yaml
from langgraph_agent.state import AuditState

class ScanError(RuntimeError):
    pass

def _resolve_nmap_bin() -> str | None:
    bin_path = shutil.which("nmap")
    if bin_path:
        return bin_path
    if "pytest" in sys.modules or os.environ.get("PYTEST_CURRENT_TEST"):
        return None
    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Nmap", "nmap.exe"),
        os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Nmap", "nmap.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Nmap", "nmap.exe"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            nmap_dir = os.path.dirname(c)
            if nmap_dir not in os.environ.get("PATH", ""):
                os.environ["PATH"] = nmap_dir + os.pathsep + os.environ.get("PATH", "")
            return c
    return None

def _run_nmap(target: str) -> str:
    nmap_bin = _resolve_nmap_bin()
    if nmap_bin is None:
        raise ScanError(
            "nmap is not installed (Windows: winget install Insecure.Nmap or https://nmap.org/download.html; "
            "Linux: apt install nmap; macOS: brew install nmap). "
            "If already installed on Windows, restart your terminal/IDE to refresh PATH."
        )
    s = load_yaml("settings.yaml").get("nmap", {})
    cmd = [nmap_bin, "-sV", "-T4",
           "-p", s.get("ports", "22,80,443,8443"),
           "--script", s.get("scripts", "http-title,ssl-cert"),
           "--host-timeout", s.get("host_timeout", "25s"),
           "-oX", "-", "--", target]          # "--" stops option injection

    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=s.get("timeout_seconds", 1800))
    except subprocess.TimeoutExpired:
        raise ScanError("nmap timed out")
    if p.returncode != 0 and not p.stdout.strip():
        raise ScanError(f"nmap failed (rc={p.returncode}): {p.stderr.strip()[:300]}")
    return p.stdout

def _parse_nmap_xml(xml_str: str) -> list[dict[str, Any]]:
    hosts: list[dict[str, Any]] = []
    if not xml_str.strip():
        return hosts
    root = ET.fromstring(xml_str)
    for h in root.findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        # BUG FIX: first <address> may be a MAC; pick the IP explicitly.
        ip = "?"
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                ip = a.get("addr"); break
        ports = []
        for p in h.findall("./ports/port"):
            ps = p.find("state")
            if ps is None or ps.get("state") != "open":
                continue
            svc = p.find("service")
            extra = [svc.get("extrainfo", "")] if svc is not None else []
            extra += [s.get("output", "") for s in p.findall("script")]  # http-title / ssl-cert
            port_id = p.get("portid")
            if port_id is None:
                raise ScanError("nmap returned an open port without a port number")
            try:
                port_number = int(port_id)
            except ValueError as exc:
                raise ScanError(f"nmap returned an invalid port number: {port_id}") from exc
            ports.append({
                "port": port_number,
                "protocol": p.get("protocol"),
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "banner": " ".join(x for x in extra if x),
            })
        hosts.append({"ip": ip, "ports": ports})
    return hosts

import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

def _is_ip_responsive(ip: str, timeout: float = 0.8) -> bool:
    """Test if an IP is responsive using quick TCP socket connection and ping."""
    common_ports = [80, 443, 22, 8443, 8080, 53, 4443, 10443, 23]
    for port in common_ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
    # Try OS ping with 1 packet
    try:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip] if os.name == "nt" else ["ping", "-c", "1", "-W", str(int(timeout)), ip]
        p = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 0.5)
        if p.returncode == 0:
            return True
    except Exception:
        pass
    return False

def check_target_active(target: str) -> tuple[bool, list[str]]:
    """Quickly check if a target IP or subnet is active."""
    target = (target or "").strip()
    if not target:
        return False, []
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            hosts_to_check = [str(ip) for ip in net.hosts()][:50]
            active = []
            with ThreadPoolExecutor(max_workers=15) as ex:
                results = ex.map(lambda ip: (ip, _is_ip_responsive(ip)), hosts_to_check)
                for ip, up in results:
                    if up:
                        active.append(ip)
            return len(active) > 0, active
        except Exception:
            return False, []
    else:
        up = _is_ip_responsive(target)
        return up, [target] if up else []

def scanner_node(state: AuditState) -> AuditState:
    if not state.get("authorized"):
        return {
            "hosts": [],
            "is_active": False,
            "active_hosts": [],
            "errors": ["scanner skipped: not authorized"],
        }
    target = state.get("target")
    if not target:
        return {
            "hosts": [],
            "is_active": False,
            "active_hosts": [],
            "errors": ["scan failed: no target was provided"],
        }
    try:
        hosts = _parse_nmap_xml(_run_nmap(target))
        is_active = len(hosts) > 0
        active_ips = [h["ip"] for h in hosts if h.get("ip") and h.get("ip") != "?"]
        selected = active_ips[0] if active_ips else target
        res: AuditState = {
            "hosts": hosts,
            "is_active": is_active,
            "active_hosts": active_ips,
            "selected_host": selected,
        }
        if not is_active:
            res["errors"] = [f"Target {target} is INACTIVE / offline (no active hosts found)."]
        return res
    except (ScanError, ET.ParseError) as e:
        return {
            "hosts": [],
            "is_active": False,
            "active_hosts": [],
            "errors": [f"scan failed: {e}"],
        }
