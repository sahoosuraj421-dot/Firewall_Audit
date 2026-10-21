import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

def config_dir() -> Path:
    """Overridable via FWAUDIT_CONFIG_DIR (used by tests)."""
    return Path(os.getenv("FWAUDIT_CONFIG_DIR", ROOT / "config"))

def load_yaml(name: str):
    import yaml
    with open(config_dir() / name) as f:
        return yaml.safe_load(f) or {}
