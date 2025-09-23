"""Security guards and access controls for the rt_evade toolkit.

This module provides security guards that enforce proper engagement
guardrails and access controls for red-team operations.
"""
import os


def require_redteam_mode() -> None:
    """Enforce engagement guardrails.

    Raises if REDTEAM_MODE is not explicitly enabled.
    """
    if os.getenv("REDTEAM_MODE") != "true":
        raise RuntimeError("REDTEAM_MODE not enabled; set REDTEAM_MODE=true to proceed")


def guard_can_write() -> None:
    """Gate file-system writes under explicit operator control."""
    if os.getenv("ALLOW_ACTIONS") != "true":
        raise PermissionError("Writes disabled without ALLOW_ACTIONS=true")
