import ipaddress
from langgraph_agent.paths import load_yaml
from langgraph_agent.state import AuditState

def _target_in_cidr(target: str, cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if "/" in target:
            target_net = ipaddress.ip_network(target, strict=False)
            if isinstance(net, ipaddress.IPv4Network) and isinstance(target_net, ipaddress.IPv4Network):
                return target_net.subnet_of(net)
            if isinstance(net, ipaddress.IPv6Network) and isinstance(target_net, ipaddress.IPv6Network):
                return target_net.subnet_of(net)
            return False
        return ipaddress.ip_address(target) in net
    except (ValueError, TypeError):   # bad input or IPv4-vs-IPv6 mismatch
        return False

def is_authorized(target: str, allow_private_prompt: bool = False) -> tuple[bool, str]:
    """Shared gate: used for scan targets AND vendor-API hosts."""
    target = (target or "").strip()
    if not target:
        return False, "REFUSED: empty target."
    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
        else:
            ipaddress.ip_address(target)
    except ValueError:
        return False, f"REFUSED: {target} is not a valid IP address or CIDR subnet."

    cfg = load_yaml("authorized_subnets.yaml")
    cidrs = [e["cidr"] for e in cfg.get("authorized_subnets", []) or []]
    hosts = cfg.get("authorized_hosts", []) or []
    if target in hosts or any(_target_in_cidr(target, c) for c in cidrs):
        return True, f"{target} is in authorized scope."
    return False, (f"REFUSED: {target} is NOT in authorized_subnets.yaml. "
                   "Add it only if you own/manage that network.")

def add_authorized_target(target: str) -> bool:
    """Add a target IP or CIDR to authorized_subnets.yaml."""
    from langgraph_agent.paths import config_dir
    import yaml
    target = (target or "").strip()
    if not target:
        return False
    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
        else:
            ipaddress.ip_address(target)
    except ValueError:
        return False

    path = config_dir() / "authorized_subnets.yaml"
    cfg = load_yaml("authorized_subnets.yaml")
    if "/" in target:
        cidrs = cfg.setdefault("authorized_subnets", [])
        if not any(e.get("cidr") == target for e in cidrs):
            cidrs.append({"cidr": target, "label": "User Added Subnet", "owner": "user"})
    else:
        hosts = cfg.setdefault("authorized_hosts", [])
        if target not in hosts:
            hosts.append(target)
    try:
        with open(path, "w") as f:
            yaml.safe_dump(cfg, f, default_flow_style=False)
        return True
    except Exception:
        return False

def authorize_node(state: AuditState) -> AuditState:
    if state.get("force_authorize"):
        return {"authorized": True, "auth_reason": f"{state.get('target')} authorized by user."}
    ok, reason = is_authorized(state.get("target", ""))
    return {"authorized": ok, "auth_reason": reason}
