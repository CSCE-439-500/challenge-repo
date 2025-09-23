"""PE file manipulation module for red-team evasion toolkit.

This module provides PE file parsing, modification, and validation capabilities
for static ML evasion exercises. All operations respect ROE guardrails and
maintain PE file format integrity.
"""

from .reader import PEReader
from .writer import PEWriter
from .validator import PEValidator
from .mimicry import PEMimicryEngine
from .obfuscator import PEObfuscator

__all__ = [
    "PEReader",
    "PEWriter", 
    "PEValidator",
    "PEMimicryEngine",
    "PEObfuscator"
]
