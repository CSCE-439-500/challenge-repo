"""PE string obfuscation module for hiding suspicious strings.

This module provides string obfuscation capabilities that work with PE file structure
while maintaining execution compatibility.
"""

import logging
import base64
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..core.guards import require_redteam_mode
from ..core.constants import (
    MALWARE_STRINGS,
    SUSPICIOUS_API_FUNCTIONS,
    SUSPICIOUS_EXECUTABLES,
)
from .reader import PEReader
from .writer import PEWriter

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StringObfuscationConfig:
    """Configuration for PE string obfuscation."""

    enable_string_obfuscation: bool = True
    obfuscation_method: str = "base64"  # base64, xor, simple
    min_string_length: int = 4  # Minimum string length to obfuscate


class PEStringObfuscator:
    """PE string obfuscator for hiding suspicious strings.

    This class provides string obfuscation capabilities that work with PE file structure
    while maintaining execution compatibility.
    """

    def __init__(self, config: Optional[StringObfuscationConfig] = None):
        """Initialize PE string obfuscator with configuration.

        Args:
            config: String obfuscation configuration options
        """
        require_redteam_mode()

        self.config = config or StringObfuscationConfig()
        self.suspicious_patterns = self._load_suspicious_patterns()
        logger.info("action=pe_string_obfuscator_initialized config=%s", self.config)

    def obfuscate_strings(self, pe_data: bytes) -> bytes:
        """Apply string obfuscation to PE file.

        Args:
            pe_data: Raw PE file bytes to obfuscate

        Returns:
            String obfuscated PE file bytes

        Raises:
            ValueError: If string obfuscation fails
        """
        if not self.config.enable_string_obfuscation:
            logger.info("action=string_obfuscation_disabled")
            return pe_data

        try:
            with PEReader(pe_data) as reader:
                strings = reader.get_strings(min_length=self.config.min_string_length)

            # Identify suspicious strings to obfuscate
            suspicious_strings = self._identify_suspicious_strings(strings)

            if not suspicious_strings:
                logger.info("action=no_suspicious_strings_found")
                return pe_data

            # Create obfuscation mappings
            obfuscation_map = {}
            for string in suspicious_strings:
                obfuscated = self._obfuscate_string(string)
                obfuscation_map[string] = obfuscated

            # Apply string replacements
            with PEWriter(pe_data) as writer:
                writer.modify_strings(obfuscation_map)
                result = writer.get_modified_data()

            logger.info(
                "action=string_obfuscation_applied strings=%d", len(obfuscation_map)
            )
            return result

        except (OSError, IOError, ValueError, AttributeError) as e:
            logger.error("action=string_obfuscation_failed error=%s", e)
            return pe_data

    def _load_suspicious_patterns(self) -> List[str]:
        """Load suspicious string patterns to identify for obfuscation.

        Returns:
            List of suspicious string patterns
        """
        return MALWARE_STRINGS + SUSPICIOUS_API_FUNCTIONS + SUSPICIOUS_EXECUTABLES

    def _identify_suspicious_strings(self, strings: List[str]) -> List[str]:
        """Identify suspicious strings that should be obfuscated.

        Args:
            strings: List of strings found in the PE file

        Returns:
            List of suspicious strings to obfuscate
        """
        suspicious_strings = []
        for string in strings:
            string_lower = string.lower()
            if any(
                pattern.lower() == string_lower for pattern in self.suspicious_patterns
            ):
                suspicious_strings.append(string)

        return suspicious_strings

    def _obfuscate_string(self, string: str) -> str:
        """Obfuscate a single string using the configured method.

        Args:
            string: String to obfuscate

        Returns:
            Obfuscated string
        """
        method = self.config.obfuscation_method.lower()

        if method == "base64":
            return self._base64_obfuscate(string)
        if method == "xor":
            return self._xor_obfuscate(string)
        if method == "simple":
            return self._simple_obfuscate(string)
        logger.warning(
            "action=unknown_obfuscation_method method=%s using_base64", method
        )
        return self._base64_obfuscate(string)

    def _base64_obfuscate(self, string: str) -> str:
        """Obfuscate string using Base64 encoding.

        Args:
            string: String to obfuscate

        Returns:
            Base64 obfuscated string
        """
        obfuscated = base64.b64encode(string.encode("utf-8")).decode("ascii")
        return f"__b64_{obfuscated}__"

    def _xor_obfuscate(self, string: str) -> str:
        """Obfuscate string using XOR encoding.

        Args:
            string: String to obfuscate

        Returns:
            XOR obfuscated string
        """
        # Simple XOR with a fixed key
        key = 0x42
        obfuscated_bytes = []
        for byte in string.encode("utf-8"):
            obfuscated_bytes.append(byte ^ key)

        obfuscated = "".join(f"{b:02x}" for b in obfuscated_bytes)
        return f"__xor_{obfuscated}__"

    def _simple_obfuscate(self, string: str) -> str:
        """Obfuscate string using simple character substitution.

        Args:
            string: String to obfuscate

        Returns:
            Simply obfuscated string
        """
        # Simple character substitution
        substitution_map = {
            "a": "x",
            "e": "y",
            "i": "z",
            "o": "w",
            "u": "v",
            "A": "X",
            "E": "Y",
            "I": "Z",
            "O": "W",
            "U": "V",
        }

        obfuscated = string
        for original, replacement in substitution_map.items():
            obfuscated = obfuscated.replace(original, replacement)

        return f"__sub_{obfuscated}__"

    def get_string_obfuscation_report(
        self, original_data: bytes, obfuscated_data: bytes
    ) -> Dict[str, Any]:
        """Generate a report of string obfuscation changes.

        Args:
            original_data: Original PE file bytes
            obfuscated_data: String obfuscated PE file bytes

        Returns:
            Dictionary containing string obfuscation report
        """
        report = {
            "string_obfuscation_enabled": self.config.enable_string_obfuscation,
            "obfuscation_method": self.config.obfuscation_method,
            "min_string_length": self.config.min_string_length,
            "original_size": len(original_data),
            "obfuscated_size": len(obfuscated_data),
            "size_change": len(obfuscated_data) - len(original_data),
            "size_percentage": (len(obfuscated_data) / len(original_data)) * 100,
            "suspicious_patterns_count": len(self.suspicious_patterns),
        }

        return report
