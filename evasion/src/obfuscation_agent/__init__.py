"""Obfuscation Agent Package.

This package contains the automated malware obfuscation agent and its supporting
components for applying various obfuscation techniques to PE files.
"""

from .agent import ObfuscationAgent
from .obfuscation_tools import (
    add_junk_sections,
    rearrange_sections,
    change_section_names,
    change_timestamp,
    validate_pe_file,
)
from .state_manager import (
    save_checkpoint,
    revert_to_checkpoint,
    cleanup_checkpoint,
    list_checkpoints,
    cleanup_old_checkpoints,
)
from .evasion_model import (
    evasion_model,
    evasion_model_with_entropy,
    evasion_model_deterministic,
)

__all__ = [
    "ObfuscationAgent",
    "add_junk_sections",
    "rearrange_sections",
    "change_section_names",
    "change_timestamp",
    "validate_pe_file",
    "save_checkpoint",
    "revert_to_checkpoint",
    "cleanup_checkpoint",
    "list_checkpoints",
    "cleanup_old_checkpoints",
    "evasion_model",
    "evasion_model_with_entropy",
    "evasion_model_deterministic",
]
