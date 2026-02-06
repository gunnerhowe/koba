"""
Koba SDK Configuration

Simple configuration for non-technical users.
"""

import os
from typing import Optional

_config = {
    "koba_url": os.environ.get("KOBA_URL", "http://localhost:8000"),
    "api_key": os.environ.get("KOBA_API_KEY", ""),
    "auto_approve_low_risk": True,
    "fail_safe": True,  # Block all actions if Koba unreachable
    "log_all_actions": True,
}


def configure(
    koba_url: Optional[str] = None,
    api_key: Optional[str] = None,
    auto_approve_low_risk: Optional[bool] = None,
    fail_safe: Optional[bool] = None,
    log_all_actions: Optional[bool] = None,
):
    """
    Configure Koba SDK settings.

    Example:
        from koba import configure

        configure(
            koba_url="https://your-koba-server.com",
            api_key="your-api-key",
            auto_approve_low_risk=False,  # Require approval for everything
        )

    Args:
        koba_url: URL of your Koba server
        api_key: Your Koba API key
        auto_approve_low_risk: Auto-approve low-risk actions
        fail_safe: Block actions if Koba is unreachable (recommended: True)
        log_all_actions: Log all actions, not just tool calls
    """
    if koba_url is not None:
        _config["koba_url"] = koba_url
    if api_key is not None:
        _config["api_key"] = api_key
    if auto_approve_low_risk is not None:
        _config["auto_approve_low_risk"] = auto_approve_low_risk
    if fail_safe is not None:
        _config["fail_safe"] = fail_safe
    if log_all_actions is not None:
        _config["log_all_actions"] = log_all_actions


def get_config():
    """Get current configuration."""
    return _config.copy()
