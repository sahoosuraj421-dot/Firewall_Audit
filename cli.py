#!/usr/bin/env python3
"""
Firewall File Downloader Agent
Flow:
1. Prompts for IP or Subnet.
2. Verifies if target is active (reachability/open ports).
3. If active, prompts for a masked password or API token.
4. If password is correct, downloads the firewall file and generates an audit report.
"""
import argparse
import io
import ipaddress
import os
import sys
import warnings

# Suppress library deprecation warnings for clean CLI output
warnings.filterwarnings("ignore")

from langgraph_agent.graph import build_graph
from langgraph_agent.nodes.authorize import is_authorized, add_authorized_target
from langgraph_agent.nodes.scanner import check_target_active
from langgraph_agent.security import prompt_password
from langgraph_agent.state import AuditState


BANNER = """
======================================================================
         FIREWALL FILE DOWNLOADER AGENT (Active IP Gateway)
======================================================================
"""

for stream in (sys.stdout, sys.stderr):
    if isinstance(stream, io.TextIOWrapper):
        stream.reconfigure(encoding="utf-8", errors="replace")


def parse_args():
    parser = argparse.ArgumentParser(description="Firewall File Downloader Agent")
    parser.add_argument("target", nargs="?", default=None, help="Target IP or Subnet (e.g., 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("--password", "-p", default=None, help="Password / API token (if omitted, will be prompted securely)")
    parser.add_argument("--vendor", choices=["fortigate", "panos", "cisco_restconf"], default=None, help="Firewall vendor")
    parser.add_argument("--llm", action="store_true", help="Use LLM for classification")
    parser.add_argument("--non-interactive", action="store_true", help="Fail instead of prompting if input is missing")
    return parser.parse_args()

def main():
    print(BANNER)
    args = parse_args()
    if args.llm:
        print("[!] LLM classification is not implemented; continuing with rule-based classification.")

    # Step 1: Ask for IP or Subnet if not provided
    target = args.target
    if not target:
        if args.non_interactive:
            print("[-] Error: Target IP or Subnet is required.", file=sys.stderr)
            sys.exit(1)
        try:
            target = input("[?] Enter IP or Subnet (e.g. 192.168.1.1 or 192.168.1.0/24): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)

    if not target:
        print("[-] Target cannot be empty. Exiting.")
        sys.exit(1)

    # Validate target format
    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
        else:
            ip_obj = ipaddress.ip_address(target)
            if str(ip_obj) in ("255.255.255.0", "255.255.0.0", "255.0.0.0", "255.255.255.255"):
                print(f"[-] '{target}' is a subnet mask, not a target IP or subnet.")
                print("[-] Tip: To scan a subnet, use CIDR notation like '192.168.14.0/24'.")
                sys.exit(1)
    except ValueError:
        print(f"[-] '{target}' is not a valid IP address or CIDR subnet (e.g. 192.168.14.1 or 192.168.14.0/24).")
        sys.exit(1)


    # Authorization Check
    authorized, reason = is_authorized(target)
    if not authorized:
        print(f"[!] Notice: {reason}")
        if not args.non_interactive:
            confirm = input(f"[?] Do you own or manage {target} and authorize downloading? [y/N]: ").strip().lower()
            if confirm in ("y", "yes"):
                add_authorized_target(target)
                authorized = True
            else:
                print("[-] Target not authorized. Operation cancelled.")
                sys.exit(1)
        else:
            print(f"[-] Operation refused: {reason}")
            sys.exit(1)

    # Step 2: Check if IP or Subnet is active
    print(f"\n[*] Probing reachability for: {target}...")
    is_active, active_hosts = check_target_active(target)

    if not is_active:
        print(f"\n[-] [FAIL] Target {target} is INACTIVE / Unreachable.")
        print("[-] No active hosts were found. Firewall file download cannot proceed.")
        sys.exit(1)

    print(f"[+] [OK] Target {target} is ACTIVE!")
    if "/" in target:
        print(f"[+] Discovered active host(s): {', '.join(active_hosts)}")
        selected_host = active_hosts[0]
        if len(active_hosts) > 1 and not args.non_interactive:
            print(f"[*] Defaulting to active host: {selected_host}")
    else:
        selected_host = target

    # Step 3: If active, ask for a masked password or API token
    password = args.password
    if not password:
        if args.non_interactive:
            print("[-] Error: Password is required for active host login.", file=sys.stderr)
            sys.exit(1)
        print(f"\n[+] Active firewall device detected at {selected_host}.")
        password = prompt_password("[?] Enter password or API token (input hidden): ").strip()

    if not password:
        print("[-] Password cannot be empty. Login cancelled.")
        sys.exit(1)

    # Step 4: Run agent to authenticate and download firewall file
    print("\n[*] Authenticating and downloading firewall configuration file...")
    graph = build_graph()
    state_input: AuditState = {
        "target": target,
        "selected_host": selected_host,
        "is_active": True,
        "password": password,
        "pull_vendor_config": True,
        "use_llm": args.llm,
        "vendor": args.vendor or "",
        "force_authorize": True,
        "errors": [],
    }

    result = graph.invoke(state_input)

    # Check authentication and download results
    if result.get("auth_success") and result.get("downloaded_file"):
        json_file = result.get("downloaded_file")
        cfg_file = result.get("downloaded_cfg_file")
        file_size = os.path.getsize(json_file) if json_file and os.path.exists(json_file) else 0

        print("\n" + "=" * 70)
        title = "  [DEMO] SYNTHETIC SAMPLE GENERATED" if result.get("demo_mode") else \
            "  [SUCCESS] FIREWALL CONFIGURATION RETRIEVED"
        print(title)
        print("=" * 70)
        print(f"  Target Host:          {selected_host}")
        if result.get("vendor_api_host"):
            print(f"  Firewall API Host:    {result['vendor_api_host']}")
        print(f"  Firewall File (JSON): {json_file}")
        if cfg_file:
            print(f"  Firewall File (CFG):  {cfg_file}")
        print(f"  File Size:            {file_size} bytes")
        if result.get("report_path"):
            print(f"  Audit Report (JSON):  {result.get('report_path')}")
            print(f"  Audit Report (MD):    {result.get('report_md_path')}")
        print("=" * 70)
        if result.get("demo_mode"):
            print("[!] This is synthetic demo data, not a backup from the firewall.\n")
        else:
            print("[+] Operation completed successfully.\n")
    else:
        print("\n" + "=" * 70)
        print("  [FAIL] AUTHENTICATION / DOWNLOAD FAILED")
        print("=" * 70)
        print(f"  Target: {selected_host}")
        errors = result.get("errors", [])
        if errors:
            print("  Details:")
            for err in errors:
                print(f"   - {err}")
        print("\n[-] Firewall file was NOT downloaded because password authentication failed.")
        print("=" * 70 + "\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
