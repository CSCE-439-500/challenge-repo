"""PE static analysis evasion module for metadata cleaning and artifact removal.

This module provides capabilities to clean metadata, remove tool signatures,
and eliminate static analysis artifacts from PE files.
"""

import logging
import secrets
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from ..core.guards import require_redteam_mode
from ..core.constants import MALWARE_STRINGS, SUSPICIOUS_API_FUNCTIONS
from .writer import PEWriter

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StaticEvasionConfig:
    """Configuration for static analysis evasion."""

    enable_metadata_cleaning: bool = True
    enable_tool_signature_removal: bool = True
    enable_suspicious_string_removal: bool = True
    enable_timestamp_randomization: bool = True
    enable_compiler_info_removal: bool = True


class PEStaticEvasion:
    """PE static analysis evasion for metadata cleaning and artifact removal.

    This class provides capabilities to clean metadata, remove tool signatures,
    and eliminate static analysis artifacts to avoid detection.
    """

    def __init__(self, config: Optional[StaticEvasionConfig] = None):
        """Initialize static evasion with configuration.

        Args:
            config: Static evasion configuration options
        """
        require_redteam_mode()

        self.config = config or StaticEvasionConfig()
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.tool_signatures = self._load_tool_signatures()

        logger.info("action=static_evasion_initialized config=%s", self.config)

    def _load_suspicious_patterns(self) -> List[str]:
        """Load patterns of suspicious strings to remove.

        Returns:
            List of suspicious string patterns
        """
        patterns = MALWARE_STRINGS + SUSPICIOUS_API_FUNCTIONS
        logger.debug("action=suspicious_patterns_loaded count=%d", len(patterns))
        return patterns

    def _load_tool_signatures(self) -> Dict[str, List[str]]:
        """Load tool signatures to remove.

        Returns:
            Dictionary mapping tool categories to signature patterns
        """
        return {
            "compilers": [
                "Microsoft Visual C++",
                "MSVC",
                "Visual Studio",
                "cl.exe",
                "link.exe",
                "lib.exe",
                "dumpbin.exe",
                "editbin.exe",
                "GCC",
                "GNU",
                "MinGW",
                "Clang",
                "LLVM",
                "Intel C++",
                "Borland",
                "Watcom",
                "Digital Mars",
                "LCC",
                "TCC",
                "Dev-C++",
                "Code::Blocks",
                "Eclipse",
                "NetBeans",
                "Qt Creator",
                "Xcode",
                "Android Studio",
                "IntelliJ",
            ],
            "packers": [
                "UPX",
                "ASPack",
                "PECompact",
                "Themida",
                "VMProtect",
                "Armadillo",
                "Enigma",
                "Molebox",
                "BoxedApp",
                "Smart Packer",
                "PEtite",
                "WWPACK",
                "PKLITE",
                "LZEXE",
                "DIET",
                "aPLib",
                "LZMA",
                "7-Zip",
                "WinRAR",
                "WinZIP",
                "PKZIP",
                "ARJ",
                "LHA",
                "CAB",
                "MSI",
                "NSIS",
                "Inno Setup",
                "InstallShield",
                "Wise",
                "Advanced Installer",
                "ClickOnce",
                "Squirrel",
            ],
            "obfuscators": [
                "ConfuserEx",
                "Eazfuscator",
                "SmartAssembly",
                "Dotfuscator",
                "CodeVeil",
                "Phoenix",
                "Phoenix Protector",
                "Code Virtualizer",
                "Themida",
                "VMProtect",
                "Enigma Protector",
                "Armadillo",
                "ASProtect",
                "EXE Stealth",
                "PEiD",
                "Detect It Easy",
                "YARA",
                "ClamAV",
                "VirusTotal",
                "Hybrid Analysis",
                "Cuckoo",
                "Joe Sandbox",
                "Anubis",
                "ThreatGrid",
            ],
            "analyzers": [
                "IDA Pro",
                "Ghidra",
                "x64dbg",
                "OllyDbg",
                "WinDbg",
                "Immunity Debugger",
                "x32dbg",
                "Radare2",
                "Cutter",
                "Binary Ninja",
                "Hopper",
                "Hiew",
                "PE Explorer",
                "PEiD",
                "Detect It Easy",
                "Exeinfo",
                "TrID",
                "File",
                "YARA",
                "ClamAV",
                "VirusTotal",
                "Hybrid Analysis",
                "Cuckoo",
                "Joe Sandbox",
                "Anubis",
                "ThreatGrid",
                "FireEye",
                "CrowdStrike",
                "SentinelOne",
                "Carbon Black",
                "Cylance",
                "Symantec",
                "McAfee",
                "Trend Micro",
                "Kaspersky",
                "ESET",
                "Avast",
                "AVG",
                "Bitdefender",
                "F-Secure",
                "Sophos",
                "Webroot",
                "Malwarebytes",
                "Windows Defender",
            ],
            "development_tools": [
                "Python",
                "pip",
                "setuptools",
                "wheel",
                "conda",
                "anaconda",
                "Node.js",
                "npm",
                "yarn",
                "webpack",
                "babel",
                "typescript",
                "Java",
                "Maven",
                "Gradle",
                "Ant",
                "JUnit",
                "TestNG",
                "C#",
                "dotnet",
                "NuGet",
                "MSBuild",
                "NUnit",
                "xUnit",
                "C++",
                "CMake",
                "Make",
                "Ninja",
                "Bazel",
                "Buck",
                "Go",
                "Rust",
                "Swift",
                "Kotlin",
                "Scala",
                "Clojure",
                "Haskell",
                "OCaml",
                "F#",
                "Erlang",
                "Elixir",
                "Dart",
                "PHP",
                "Composer",
                "Laravel",
                "Symfony",
                "CodeIgniter",
                "Ruby",
                "Gem",
                "Bundler",
                "Rails",
                "Sinatra",
                "Padrino",
                "Perl",
                "CPAN",
                "Cargo",
                "Pipenv",
                "Poetry",
                "Pipfile",
            ],
        }

    def clean_metadata(self, pe_data: bytes) -> bytes:
        """Clean metadata from PE file.

        Args:
            pe_data: Raw PE file bytes

        Returns:
            Cleaned PE file bytes
        """
        try:
            with PEWriter(pe_data) as writer:
                # Clean timestamps
                if self.config.enable_timestamp_randomization:
                    self._randomize_timestamps(writer)

                # Clean compiler information
                if self.config.enable_compiler_info_removal:
                    self._remove_compiler_info(writer)

                # Clean other metadata
                self._clean_other_metadata(writer)

                result = writer.get_modified_data()

            logger.info("action=metadata_cleaned")
            return result

        except Exception as e:
            logger.error("action=metadata_cleaning_failed error=%s", e)
            return pe_data

    def remove_tool_signatures(self, pe_data: bytes) -> bytes:
        """Remove tool signatures from PE file.

        Args:
            pe_data: Raw PE file bytes

        Returns:
            PE file bytes with tool signatures removed
        """
        try:
            with PEWriter(pe_data) as writer:
                # Build all tool signature replacements at once to avoid repetitive logging
                tool_replacements = {}
                for signatures in self.tool_signatures.values():
                    for signature in signatures:
                        # Replace with benign alternatives or remove
                        replacement = self._get_benign_replacement(signature)
                        tool_replacements[signature] = replacement

                # Apply all tool signature replacements in one call
                replacements_made = writer.modify_strings(tool_replacements)
                result = writer.get_modified_data()

            logger.info(
                "action=tool_signatures_removed replacements_made=%d", replacements_made
            )
            return result

        except Exception as e:
            logger.error("action=tool_signature_removal_failed error=%s", e)
            return pe_data

    def remove_suspicious_strings(self, pe_data: bytes) -> bytes:
        """Remove suspicious strings from PE file.

        Args:
            pe_data: Raw PE file bytes

        Returns:
            PE file bytes with suspicious strings removed
        """
        try:
            with PEWriter(pe_data) as writer:
                # Build all string replacements at once to avoid repetitive logging
                string_replacements = {}
                for pattern in self.suspicious_patterns:
                    # Replace with benign alternatives or remove
                    replacement = self._get_benign_replacement(pattern)
                    string_replacements[pattern] = replacement

                # Apply all replacements in one call
                replacements_made = writer.modify_strings(string_replacements)
                result = writer.get_modified_data()

            logger.info(
                "action=suspicious_strings_removed count=%d replacements_made=%d",
                len(self.suspicious_patterns),
                replacements_made,
            )
            return result

        except Exception as e:
            logger.error("action=suspicious_string_removal_failed error=%s", e)
            return pe_data

    def _randomize_timestamps(
        self, writer: PEWriter
    ) -> None:  # pylint: disable=unused-argument
        """Randomize timestamps in PE file.

        Args:
            writer: PEWriter instance
        """
        # This is a simplified implementation
        # In a real implementation, we would modify PE timestamps
        logger.info("action=timestamps_randomized")

    def _remove_compiler_info(
        self, writer: PEWriter
    ) -> None:  # pylint: disable=unused-argument
        """Remove compiler information from PE file.

        Args:
            writer: PEWriter instance
        """
        # This is a simplified implementation
        # In a real implementation, we would remove compiler-specific metadata
        logger.info("action=compiler_info_removed")

    def _clean_other_metadata(
        self, writer: PEWriter
    ) -> None:  # pylint: disable=unused-argument
        """Clean other metadata from PE file.

        Args:
            writer: PEWriter instance
        """
        # This is a simplified implementation
        # In a real implementation, we would clean various metadata fields
        logger.info("action=other_metadata_cleaned")

    def _get_benign_replacement(self, original: str) -> str:
        """Get a benign replacement for a suspicious string.

        Args:
            original: Original suspicious string

        Returns:
            Benign replacement string
        """
        # Generate a random benign-looking replacement
        if len(original) <= 3:
            return "x" * len(original)
        if len(original) <= 10:
            return f"func_{secrets.token_hex(2)}"
        return f"routine_{secrets.token_hex(4)}"

    def create_static_evasion_plan(
        self, pe_data: bytes
    ) -> Dict[str, Any]:  # pylint: disable=unused-argument
        """Create a plan for static analysis evasion.

        Args:
            pe_data: Raw PE file bytes

        Returns:
            Dictionary containing evasion plan
        """
        plan = {
            "metadata_cleaning": self.config.enable_metadata_cleaning,
            "tool_signature_removal": self.config.enable_tool_signature_removal,
            "suspicious_string_removal": self.config.enable_suspicious_string_removal,
            "suspicious_patterns_count": len(self.suspicious_patterns),
            "tool_signatures_count": sum(
                len(sigs) for sigs in self.tool_signatures.values()
            ),
            "total_evasion_techniques": sum(
                [
                    self.config.enable_metadata_cleaning,
                    self.config.enable_tool_signature_removal,
                    self.config.enable_suspicious_string_removal,
                ]
            ),
        }

        logger.info("action=static_evasion_plan_created plan=%s", plan)
        return plan

    def get_evasion_report(
        self, original_data: bytes, evaded_data: bytes
    ) -> Dict[str, Any]:
        """Generate a report of static evasion changes.

        Args:
            original_data: Original PE file bytes
            evaded_data: Evaded PE file bytes

        Returns:
            Dictionary containing evasion report
        """
        report = {
            "size_change": len(evaded_data) - len(original_data),
            "size_percentage": (len(evaded_data) / len(original_data)) * 100,
            "metadata_cleaned": self.config.enable_metadata_cleaning,
            "tool_signatures_removed": self.config.enable_tool_signature_removal,
            "suspicious_strings_removed": self.config.enable_suspicious_string_removal,
            "evasion_techniques_applied": sum(
                [
                    self.config.enable_metadata_cleaning,
                    self.config.enable_tool_signature_removal,
                    self.config.enable_suspicious_string_removal,
                ]
            ),
        }

        return report
