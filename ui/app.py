import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st
from langgraph_agent.graph import build_graph
from langgraph_agent.paths import load_yaml
from langgraph_agent.state import AuditState
from langgraph_agent.nodes.scanner import check_target_active
from langgraph_agent.nodes.authorize import is_authorized

st.set_page_config(
    page_title="Firewall File Downloader Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for modern styling
st.markdown("""
<style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        color: #4B5563;
        font-size: 1.05rem;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #F3F4F6;
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 10px;
        border-left: 4px solid #3B82F6;
    }
    .stDownloadButton button {
        width: 100%;
        background-color: #2563EB !important;
        color: white !important;
        font-weight: 600 !important;
        border-radius: 6px !important;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=64)
    st.title("Settings & Scope")
    st.caption("Pure Rule-Based Network Agent • No LLM Required")

    cfg = load_yaml("authorized_subnets.yaml")
    authorized_cidrs = [e.get("cidr") for e in cfg.get("authorized_subnets", []) if e.get("cidr")]
    authorized_hosts = cfg.get("authorized_hosts", []) or []
    all_authorized = authorized_cidrs + authorized_hosts

    st.subheader("Authorized Targets")
    for t in all_authorized[:8]:
        st.markdown(f"- `{t}`")

    st.divider()
    st.info("💡 **Mode**: 100% Local Rule-Based. No OpenAI or cloud LLM required.")

# Main Header
st.markdown('<div class="main-title">🛡️ Firewall File Downloader Agent</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Download active firewall configuration files via authenticated gateway</div>', unsafe_allow_html=True)

# Session State Initialization
if "scan_target" not in st.session_state:
    st.session_state.scan_target = ""
if "is_active" not in st.session_state:
    st.session_state.is_active = None
if "active_hosts" not in st.session_state:
    st.session_state.active_hosts = []
if "auth_result" not in st.session_state:
    st.session_state.auth_result = None

# Step 1: Target Input
col1, col2 = st.columns([3, 1])
with col1:
    target_input = st.text_input(
        "Enter Target IP or Subnet:",
        value=st.session_state.scan_target or (authorized_hosts[0] if authorized_hosts else "192.168.14.1"),
        placeholder="e.g. 192.168.14.1 or 192.168.14.0/24",
        help="Specify a single firewall IP or a subnet CIDR"
    )
with col2:
    st.write("")
    st.write("")
    check_btn = st.button("🔍 Check Active IP", type="primary", width="stretch")

if check_btn:
    st.session_state.scan_target = target_input.strip()
    st.session_state.auth_result = None
    st.session_state.is_active = None
    st.session_state.active_hosts = []
    
    # Check authorization
    ok, reason = is_authorized(st.session_state.scan_target)
    if not ok:
        st.error(f"Target was not scanned. {reason} Add only targets you own or manage to the authorized scope first.")
    else:
        with st.spinner(f"Pinging and probing reachability for {st.session_state.scan_target}..."):
            is_up, hosts = check_target_active(st.session_state.scan_target)
            st.session_state.is_active = is_up
            st.session_state.active_hosts = hosts

# Step 2: Active Check Results
if st.session_state.is_active is False:
    st.error(f"❌ Target `{st.session_state.scan_target}` is INACTIVE / Offline. No active firewall device responded. Password prompt is disabled.")

elif st.session_state.is_active is True:
    st.success(f"✅ Target `{st.session_state.scan_target}` is ACTIVE and reachable!")
    
    active_ips = st.session_state.active_hosts
    if not active_ips:
        active_ips = [st.session_state.scan_target]
    
    m1, m2, m3 = st.columns(3)
    with m1:
        st.metric("Status", "ONLINE / ACTIVE")
    with m2:
        selected_ip = st.selectbox("Selected Firewall Host", active_ips) if len(active_ips) > 1 else active_ips[0]
        st.metric("Target IP", selected_ip)
    with m3:
        st.metric("Verification Mode", "Hybrid Secure Check")

    st.divider()

    # Step 3: Password Authentication (Masked / Encrypted input)
    st.subheader("🔑 Step 2: Firewall Login Authentication")
    st.caption("Password input is masked on screen. Use a trusted HTTPS deployment when accessing this app over a network.")

    pcol1, pcol2 = st.columns([2, 1])
    with pcol1:
        password = st.text_input(
            "Enter Firewall Password / API Token:",
            type="password",
            placeholder="••••••••••••",
            help="Input is hidden on screen."
        )
    with pcol2:
        vendor_choice = st.selectbox("Firewall Vendor:", ["Auto-Detect", "fortigate", "panos", "cisco_restconf"])
        v_key = "" if vendor_choice == "Auto-Detect" else vendor_choice

    download_btn = st.button("📥 Authenticate & Download Firewall File", type="primary")

    if download_btn:
        if not password:
            st.warning("⚠️ Please enter a password or API token to login.")
        else:
            with st.spinner("Authenticating with firewall and downloading policy files..."):
                graph = build_graph()
                state: AuditState = {
                    "target": st.session_state.scan_target,
                    "selected_host": selected_ip,
                    "is_active": True,
                    "password": password,
                    "pull_vendor_config": True,
                    "use_llm": False,  # 100% Rule-based, no LLM required
                    "vendor": v_key,
                    "force_authorize": True,
                    "errors": []
                }
                res = graph.invoke(state)
                st.session_state.auth_result = res

# Step 4: Display Download & Audit Results
if st.session_state.auth_result:
    res = st.session_state.auth_result
    auth_ok = res.get("auth_success")
    cfg_file = res.get("downloaded_file")
    text_cfg_file = res.get("downloaded_cfg_file")
    v_data = res.get("vendor_config", {})

    if not auth_ok or not cfg_file:
        st.error("❌ Firewall authentication or configuration download failed.")
        st.error("A configuration file was not downloaded.")
        if res.get("errors"):
            with st.expander("Error Details"):
                for err in (res.get("errors") or []):
                    st.write(f"- {err}")
    else:
        result_host = res.get("vendor_api_host") or res.get("selected_host") or st.session_state.scan_target
        if res.get("demo_mode"):
            st.warning("Demo mode generated synthetic sample data; this is not a firewall backup.")
        else:
            st.balloons()
            st.success(f"🎉 Firewall Configuration Retrieved Successfully for `{result_host}`!")

        # Download Buttons
        dcol1, dcol2, dcol3 = st.columns([1, 1, 2])
        if cfg_file and os.path.exists(cfg_file):
            with open(cfg_file, "r", encoding="utf-8") as f:
                json_str = f.read()
            with dcol1:
                st.download_button(
                    label="⬇️ Download JSON File",
                    data=json_str,
                    file_name=os.path.basename(cfg_file),
                    mime="application/json"
                )

        if text_cfg_file and os.path.exists(text_cfg_file):
            with open(text_cfg_file, "r", encoding="utf-8") as f:
                cfg_str = f.read()
            with dcol2:
                st.download_button(
                    label="⬇️ Download CFG File",
                    data=cfg_str,
                    file_name=os.path.basename(text_cfg_file),
                    mime="text/plain"
                )

        with dcol3:
            st.info(f"📁 Local Path: `{cfg_file}`")

        # Tabs for Config Details
        t1, t2, t3, t4 = st.tabs(["📋 Firewall Policies", "🌐 Interfaces", "⚙️ System Info", "📄 Raw Config"])

        with t1:
            policies = v_data.get("firewall_policy", [])
            if policies and isinstance(policies, list) and isinstance(policies[0], dict):
                st.dataframe(policies, width="stretch")
            else:
                st.json(policies)

        with t2:
            interfaces = v_data.get("interfaces", [])
            if interfaces and isinstance(interfaces, list) and isinstance(interfaces[0], dict):
                st.dataframe(interfaces, width="stretch")
            else:
                st.json(interfaces)

        with t3:
            st.json(v_data.get("system_status", {}))

        with t4:
            st.json(v_data)
