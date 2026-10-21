import operator
from typing import Annotated, Any, TypedDict

class AuditState(TypedDict, total=False):
    target: str
    use_llm: bool
    pull_vendor_config: bool
    vendor: str
    output_dir: str
    force_authorize: bool
    password_required: bool

    authorized: bool
    auth_reason: str

    # Active IP / Subnet reachability
    is_active: bool
    active_hosts: list[str]
    selected_host: str

    # Authentication & Password handling
    password: str
    password_provided: bool
    auth_success: bool
    auth_message: str
    demo_mode: bool

    # Firewall configuration & file downloading
    downloaded_file: str
    downloaded_cfg_file: str
    download_summary: dict[str, Any]

    hosts: list[dict[str, Any]]
    fingerprints: list[dict[str, Any]]
    classified: list[dict[str, Any]]
    vendor_config: dict[str, Any]
    vendor_api_host: str
    report_path: str
    report_md_path: str
    # reducer: nodes return only NEW errors, they get appended
    errors: Annotated[list[str], operator.add]
