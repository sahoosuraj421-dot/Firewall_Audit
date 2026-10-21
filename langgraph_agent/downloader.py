import json
import time
from pathlib import Path
from typing import Any
from langgraph_agent.paths import ROOT

DOWNLOADS_DIR = ROOT / "downloads"

def get_downloads_dir() -> Path:
    DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
    return DOWNLOADS_DIR

def generate_mock_firewall_config(host: str, vendor: str = "Fortinet FortiGate") -> dict[str, Any]:
    """Generate realistic firewall config for validated host when live API is simulated."""
    clean_vendor = vendor or "Generic Firewall"
    return {
        "system_status": {
            "hostname": f"FW-{host.replace('.', '-')}",
            "vendor": clean_vendor,
            "version": "v7.2.5-build1517",
            "serial": f"FGT60E{hash(host) % 10000000:08d}",
            "mode": "NAT/Route",
            "uptime_seconds": 184520,
            "mgmt_ip": host,
        },
        "interfaces": [
            {"name": "wan1", "ip": host, "netmask": "255.255.255.0", "type": "physical", "allowaccess": "ping,https,ssh"},
            {"name": "internal", "ip": "10.0.1.1", "netmask": "255.255.255.0", "type": "switch", "allowaccess": "ping,https"},
            {"name": "dmz", "ip": "172.16.1.1", "netmask": "255.255.255.0", "type": "vlan", "allowaccess": "ping"}
        ],
        "firewall_policy": [
            {"id": 1, "name": "Corporate-Outbound", "srcintf": "internal", "dstintf": "wan1", "srcaddr": "10.0.1.0/24", "dstaddr": "all", "action": "accept", "schedule": "always", "service": "ALL", "nat": "enable"},
            {"id": 2, "name": "DMZ-Web-Access", "srcintf": "wan1", "dstintf": "dmz", "srcaddr": "all", "dstaddr": "172.16.1.10", "action": "accept", "schedule": "always", "service": "HTTPS,HTTP", "nat": "disable"},
            {"id": 3, "name": "Block-Malicious-Subnets", "srcintf": "all", "dstintf": "all", "srcaddr": "Threat_Feeds", "dstaddr": "all", "action": "deny", "schedule": "always", "service": "ALL", "nat": "disable"},
            {"id": 4, "name": "Default-Deny", "srcintf": "all", "dstintf": "all", "srcaddr": "all", "dstaddr": "all", "action": "deny", "schedule": "always", "service": "ALL", "nat": "disable"}
        ],
        "address_objects": [
            {"name": "LAN_Subnet", "subnet": "10.0.1.0/24"},
            {"name": "DMZ_Web_Server", "ip": "172.16.1.10"},
            {"name": "Threat_Feeds", "type": "dynamic-blocklist"}
        ],
        "routing": [
            {"destination": "0.0.0.0/0", "gateway": host, "interface": "wan1"}
        ]
    }

def format_cfg_text(config_data: dict[str, Any], host: str) -> str:
    """Format configuration dictionary as standard firewall .cfg format."""
    status = config_data.get("system_status", {})
    lines = [
        f"# Firewall Configuration Backup",
        f"# Host: {host}",
        f"# Hostname: {status.get('hostname', 'Firewall')}",
        f"# Vendor: {status.get('vendor', 'Security Appliance')}",
        f"# Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "config system global",
        f"    set hostname \"{status.get('hostname', 'Firewall')}\"",
        f"    set timezone \"04\"",
        "end",
        "",
        "config system interface"
    ]
    interfaces = config_data.get("interfaces", [])
    if isinstance(interfaces, list):
        for intf in interfaces:
            if isinstance(intf, dict):
                lines.extend([
                    f"    edit \"{intf.get('name', 'intf')}\"",
                    f"        set ip {intf.get('ip', '0.0.0.0')} {intf.get('netmask', '255.255.255.0')}",
                    f"        set allowaccess {intf.get('allowaccess', 'ping,https')}",
                    "    next"
                ])
    lines.append("end")
    lines.append("")
    lines.append("config firewall policy")
    policies = config_data.get("firewall_policy", [])
    if isinstance(policies, list):
        for pol in policies:
            if isinstance(pol, dict):
                lines.extend([
                    f"    edit {pol.get('id', 1)}",
                    f"        set name \"{pol.get('name', 'rule')}\"",
                    f"        set srcintf \"{pol.get('srcintf', 'any')}\"",
                    f"        set dstintf \"{pol.get('dstintf', 'any')}\"",
                    f"        set srcaddr \"{pol.get('srcaddr', 'all')}\"",
                    f"        set dstaddr \"{pol.get('dstaddr', 'all')}\"",
                    f"        set action {pol.get('action', 'accept')}",
                    f"        set schedule \"{pol.get('schedule', 'always')}\"",
                    f"        set service \"{pol.get('service', 'ALL')}\"",
                    f"        set nat {pol.get('nat', 'disable')}",
                    "    next"
                ])
    lines.append("end")

    return "\n".join(lines) + "\n"

def save_firewall_file(host: str, config_data: dict[str, Any]) -> tuple[str, str]:
    """
    Save firewall configuration as JSON and CFG files.
    Returns (json_file_path, cfg_file_path).
    """
    out_dir = get_downloads_dir()
    clean_host = host.replace(":", "_").replace("/", "_").replace(".", "_")
    ts = time.strftime("%Y%m%d_%H%M%S")
    
    json_path = out_dir / f"firewall_config_{clean_host}_{ts}.json"
    cfg_path = out_dir / f"firewall_config_{clean_host}_{ts}.cfg"

    # Write private JSON file
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)

    # Write text config (.cfg)
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write(format_cfg_text(config_data, host))

    return str(json_path), str(cfg_path)
