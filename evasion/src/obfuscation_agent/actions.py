"""Single source of truth for agent actions.

Defines the canonical action names the agent can choose from. Other modules
should import from here to avoid drift between prompts, validation, and logic.
"""

from typing import List

# Basic obfuscation techniques
BASIC_ACTIONS: List[str] = [
    "add_junk_sections",
    "rearrange_sections",
    "change_section_names",
    "change_timestamp",
]

# Advanced techniques (should be used at most once each)
ADVANCED_ACTIONS: List[str] = ["rust_crypter"]

# Special control actions
SPECIAL_ACTIONS: List[str] = [
    "stop",
]

# All actions (order matters only for display)
ALL_ACTIONS: List[str] = BASIC_ACTIONS + ADVANCED_ACTIONS + SPECIAL_ACTIONS
