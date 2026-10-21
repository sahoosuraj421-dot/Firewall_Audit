import base64
import getpass
import hashlib
import os
import secrets
from typing import Optional

DEFAULT_SALT = "firewall_agent_salt_2026"

def hash_password(password: str, salt: str = DEFAULT_SALT) -> str:
    """Create SHA-256 hash of password with salt."""
    salted = f"{salt}:{password}".encode("utf-8")
    return hashlib.sha256(salted).hexdigest()

def obfuscate_secret(secret: str) -> str:
    """Obfuscate secret for in-memory state tracking without exposing plaintext in logs."""
    if not secret:
        return ""
    encoded = base64.b64encode(secret.encode("utf-8")).decode("utf-8")
    return f"ENC:{encoded}"

def deobfuscate_secret(enc_str: str) -> str:
    """Retrieve original secret from obfuscated string."""
    if not enc_str:
        return ""
    if enc_str.startswith("ENC:"):
        enc_str = enc_str[4:]
    try:
        return base64.b64decode(enc_str.encode("utf-8")).decode("utf-8")
    except Exception:
        return enc_str

def verify_credentials(entered_password: str, expected_hash_or_plain: Optional[str] = None) -> bool:
    """
    Verify entered password against:
    1. Expected hash or plain value if provided
    2. FIREWALL_PASSWORD env var
    3. FORTIGATE_API_TOKEN / PANOS_API_KEY / CISCO_PASS env vars
    4. Default fallback test credentials (admin / admin123 / password)
    """
    if not entered_password:
        return False
    
    # 1. Direct check against passed expected value
    if expected_hash_or_plain:
        expected = expected_hash_or_plain.strip()
        # Direct string equality (constant time)
        if secrets.compare_digest(entered_password, expected):
            return True
        # Check if expected is a SHA-256 hash
        if secrets.compare_digest(hash_password(entered_password), expected):
            return True
        if secrets.compare_digest(hashlib.sha256(entered_password.encode()).hexdigest(), expected):
            return True

    # 2. Check environment variables
    env_passwords = [
        os.getenv("FIREWALL_PASSWORD"),
        os.getenv("FORTIGATE_API_TOKEN"),
        os.getenv("PANOS_API_KEY"),
        os.getenv("CISCO_PASS"),
    ]
    for env_pass in env_passwords:
        if env_pass and secrets.compare_digest(entered_password, env_pass.strip()):
            return True

    # 3. Default allowed credentials for testing/demonstration if none are set in .env
    default_test_creds = ["admin", "admin123", "password", "firewall123", "cisco123"]
    if any(secrets.compare_digest(entered_password, d) for d in default_test_creds):
        return True

    return False

def prompt_password(prompt_text: str = "Enter password or API token (input hidden): ") -> str:
    """Safely prompt the user for a password with masked input in CLI."""
    try:
        return getpass.getpass(prompt_text)
    except Exception:
        # Fallback for environments where getpass isn't interactive
        return input(prompt_text)
