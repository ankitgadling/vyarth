"""Vyarth: a scope-aware detector for unused Python code."""

from vyarth.config import Config, load_config
from vyarth.engine import scan
from vyarth.model import Finding, ParseError, ScanResult

__version__ = "0.1.0"

__all__ = [
    "Config",
    "Finding",
    "ParseError",
    "ScanResult",
    "__version__",
    "load_config",
    "scan",
]
