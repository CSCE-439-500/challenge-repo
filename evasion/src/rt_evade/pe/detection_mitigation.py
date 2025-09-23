"""PE detection vector mitigation module for file size control and stealth modification.

This module provides capabilities to monitor file size, preserve timestamps,
and manage PE section names to avoid immediate detection vectors.
"""

import logging
import random
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from ..core.guards import require_redteam_mode
from .reader import PEReader
from .writer import PEWriter

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DetectionMitigationConfig:
    """Configuration for detection vector mitigation."""

    enable_file_size_monitoring: bool = True
    enable_timestamp_preservation: bool = True
    enable_section_name_optimization: bool = True
    max_file_size: int = 5 * 1024 * 1024  # 5MB limit
    min_file_size: int = 1024  # 1KB minimum
    preserve_original_timestamps: bool = True
    use_benign_timestamps: bool = False


class PEDetectionMitigation:
    """PE detection vector mitigation for file size control and stealth modification.

    This class provides capabilities to monitor file size, preserve timestamps,
    and manage PE section names to avoid immediate detection vectors.
    """

    def __init__(self, config: Optional[DetectionMitigationConfig] = None):
        """Initialize detection mitigation with configuration.

        Args:
            config: Detection mitigation configuration options
        """
        require_redteam_mode()

        self.config = config or DetectionMitigationConfig()
        self.common_section_names = self._load_common_section_names()
        self.benign_timestamps = self._load_benign_timestamps()

        logger.info("action=detection_mitigation_initialized config=%s", self.config)

    def _load_common_section_names(self) -> Dict[str, List[str]]:
        """Load database of common PE section names.

        Returns:
            Dictionary mapping section categories to lists of names
        """
        return {
            "standard": [
                ".text",
                ".data",
                ".rdata",
                ".bss",
                ".idata",
                ".edata",
                ".rsrc",
                ".reloc",
                ".debug",
                ".pdata",
                ".xdata",
                ".tls",
                ".gfids",
                ".sxdata",
            ],
            "benign": [
                ".text",
                ".data",
                ".rdata",
                ".bss",
                ".idata",
                ".edata",
                ".rsrc",
                ".reloc",
                ".debug",
                ".pdata",
                ".xdata",
                ".tls",
                ".gfids",
                ".sxdata",
                ".init",
                ".fini",
                ".ctors",
                ".dtors",
                ".jcr",
                ".eh_frame",
                ".gcc_except_table",
                ".rodata",
                ".rodata1",
                ".comment",
                ".note",
                ".note.GNU-stack",
                ".note.ABI-tag",
                ".gnu.version",
                ".gnu.version_r",
                ".gnu.hash",
                ".dynsym",
                ".dynstr",
                ".plt",
                ".got",
                ".got.plt",
                ".dynamic",
                ".interp",
                ".shstrtab",
                ".symtab",
                ".strtab",
            ],
            "suspicious": [
                ".packed",
                ".upx",
                ".themida",
                ".vmprotect",
                ".enigma",
                ".aspack",
                ".pecompact",
                ".molebox",
                ".boxedapp",
                ".petite",
                ".wwpack",
                ".pklite",
                ".lzexe",
                ".diet",
                ".aplib",
                ".lzma",
                ".7zip",
                ".winrar",
                ".winzip",
                ".pkzip",
                ".arj",
                ".lha",
                ".cab",
                ".msi",
                ".nsis",
                ".inno",
                ".wise",
                ".confuser",
                ".eazfuscator",
                ".smartassembly",
                ".dotfuscator",
                ".codeveil",
                ".phoenix",
                ".codevirtualizer",
                ".asprotect",
                ".exestealth",
                ".peid",
            ],
            "system": [
                ".text",
                ".data",
                ".rdata",
                ".bss",
                ".idata",
                ".edata",
                ".rsrc",
                ".reloc",
                ".debug",
                ".pdata",
                ".xdata",
                ".tls",
                ".gfids",
                ".sxdata",
                ".init",
                ".fini",
                ".ctors",
                ".dtors",
                ".jcr",
                ".eh_frame",
                ".gcc_except_table",
                ".rodata",
                ".rodata1",
                ".comment",
                ".note",
                ".note.GNU-stack",
                ".note.ABI-tag",
                ".gnu.version",
                ".gnu.version_r",
                ".gnu.hash",
                ".dynsym",
                ".dynstr",
                ".plt",
                ".got",
                ".got.plt",
                ".dynamic",
                ".interp",
                ".shstrtab",
                ".symtab",
                ".strtab",
                ".crt",
                ".CRT",
                ".ctors",
                ".dtors",
                ".jcr",
                ".eh_frame",
                ".gcc_except_table",
                ".rodata",
                ".rodata1",
                ".comment",
                ".note",
                ".note.GNU-stack",
                ".note.ABI-tag",
            ],
            "development": [
                ".text",
                ".data",
                ".rdata",
                ".bss",
                ".idata",
                ".edata",
                ".rsrc",
                ".reloc",
                ".debug",
                ".pdata",
                ".xdata",
                ".tls",
                ".gfids",
                ".sxdata",
                ".init",
                ".fini",
                ".ctors",
                ".dtors",
                ".jcr",
                ".eh_frame",
                ".gcc_except_table",
                ".rodata",
                ".rodata1",
                ".comment",
                ".note",
                ".note.GNU-stack",
                ".note.ABI-tag",
                ".gnu.version",
                ".gnu.version_r",
                ".gnu.hash",
                ".dynsym",
                ".dynstr",
                ".plt",
                ".got",
                ".got.plt",
                ".dynamic",
                ".interp",
                ".shstrtab",
                ".symtab",
                ".strtab",
                ".crt",
                ".CRT",
                ".ctors",
                ".dtors",
                ".jcr",
                ".eh_frame",
                ".gcc_except_table",
                ".rodata",
                ".rodata1",
                ".comment",
                ".note",
                ".note.GNU-stack",
                ".note.ABI-tag",
                ".gnu.version",
                ".gnu.version_r",
                ".gnu.hash",
                ".dynsym",
                ".dynstr",
                ".plt",
                ".got",
                ".got.plt",
                ".dynamic",
                ".interp",
                ".shstrtab",
                ".symtab",
                ".strtab",
            ],
        }

    def _load_benign_timestamps(self) -> List[int]:
        """Load database of benign timestamps.

        Returns:
            List of benign timestamp values
        """
        # Generate timestamps for common Windows system files and applications
        # These are realistic timestamps from Windows 10/11 system files
        base_timestamps = [
            # Windows 10/11 system files (approximate)
            1609459200,  # 2021-01-01 00:00:00
            1612137600,  # 2021-02-01 00:00:00
            1614556800,  # 2021-03-01 00:00:00
            1617235200,  # 2021-04-01 00:00:00
            1619827200,  # 2021-05-01 00:00:00
            1622505600,  # 2021-06-01 00:00:00
            1625097600,  # 2021-07-01 00:00:00
            1627776000,  # 2021-08-01 00:00:00
            1630454400,  # 2021-09-01 00:00:00
            1633046400,  # 2021-10-01 00:00:00
            1635724800,  # 2021-11-01 00:00:00
            1638316800,  # 2021-12-01 00:00:00
            1640995200,  # 2022-01-01 00:00:00
            1643673600,  # 2022-02-01 00:00:00
            1646092800,  # 2022-03-01 00:00:00
            1648771200,  # 2022-04-01 00:00:00
            1651363200,  # 2022-05-01 00:00:00
            1654041600,  # 2022-06-01 00:00:00
            1656633600,  # 2022-07-01 00:00:00
            1659312000,  # 2022-08-01 00:00:00
            1661990400,  # 2022-09-01 00:00:00
            1664582400,  # 2022-10-01 00:00:00
            1667260800,  # 2022-11-01 00:00:00
            1669852800,  # 2022-12-01 00:00:00
            1672531200,  # 2023-01-01 00:00:00
            1675209600,  # 2023-02-01 00:00:00
            1677628800,  # 2023-03-01 00:00:00
            1680307200,  # 2023-04-01 00:00:00
            1682899200,  # 2023-05-01 00:00:00
            1685577600,  # 2023-06-01 00:00:00
            1688169600,  # 2023-07-01 00:00:00
            1690848000,  # 2023-08-01 00:00:00
            1693526400,  # 2023-09-01 00:00:00
            1696118400,  # 2023-10-01 00:00:00
            1698796800,  # 2023-11-01 00:00:00
            1701388800,  # 2023-12-01 00:00:00
            1704067200,  # 2024-01-01 00:00:00
            1706745600,  # 2024-02-01 00:00:00
            1709251200,  # 2024-03-01 00:00:00
            1711929600,  # 2024-04-01 00:00:00
            1714521600,  # 2024-05-01 00:00:00
            1717200000,  # 2024-06-01 00:00:00
            1719792000,  # 2024-07-01 00:00:00
            1722470400,  # 2024-08-01 00:00:00
            1725148800,  # 2024-09-01 00:00:00
            1727740800,  # 2024-10-01 00:00:00
            1730419200,  # 2024-11-01 00:00:00
            1733011200,  # 2024-12-01 00:00:00
        ]

        # Add some variation to make timestamps look more realistic
        varied_timestamps = []
        for base in base_timestamps:
            # Add random variation of up to 30 days
            variation = random.randint(-30 * 24 * 3600, 30 * 24 * 3600)
            varied_timestamps.append(base + variation)

        return varied_timestamps

    def monitor_file_size(self, pe_data: bytes) -> Dict[str, Any]:
        """Monitor file size and provide recommendations.

        Args:
            pe_data: Raw PE file bytes

        Returns:
            Dictionary containing size analysis and recommendations
        """
        file_size = len(pe_data)

        analysis = {
            "current_size": file_size,
            "max_size": self.config.max_file_size,
            "min_size": self.config.min_file_size,
            "size_percentage": (file_size / self.config.max_file_size) * 100,
            "within_limits": self.config.min_file_size
            <= file_size
            <= self.config.max_file_size,
            "recommendations": [],
        }

        # Generate recommendations based on size
        if file_size > self.config.max_file_size:
            analysis["recommendations"].append(
                "File exceeds maximum size limit - consider compression or payload reduction"
            )
        elif file_size < self.config.min_file_size:
            analysis["recommendations"].append(
                "File is very small - consider adding benign padding"
            )
        elif file_size > self.config.max_file_size * 0.8:
            analysis["recommendations"].append(
                "File is approaching size limit - monitor closely"
            )
        elif file_size < self.config.min_file_size * 2:
            analysis["recommendations"].append(
                "File is small - consider adding benign content"
            )
        else:
            analysis["recommendations"].append("File size is within acceptable range")

        logger.info(
            "action=file_size_monitored size=%d max=%d within_limits=%s",
            file_size,
            self.config.max_file_size,
            analysis["within_limits"],
        )

        return analysis

    def preserve_timestamps(self, pe_data: bytes) -> bytes:
        """Preserve or set benign timestamps in PE file.

        Args:
            pe_data: Raw PE file bytes

        Returns:
            PE file bytes with preserved/benign timestamps
        """
        try:
            with PEWriter(pe_data) as writer:
                if self.config.preserve_original_timestamps:
                    # Try to preserve original timestamps
                    self._preserve_original_timestamps(writer)
                elif self.config.use_benign_timestamps:
                    # Set benign timestamps
                    self._set_benign_timestamps(writer)

                result = writer.get_modified_data()

            logger.info(
                "action=timestamps_preserved preserve_original=%s use_benign=%s",
                self.config.preserve_original_timestamps,
                self.config.use_benign_timestamps,
            )

            return result

        except Exception as e:
            logger.error("action=timestamp_preservation_failed error=%s", e)
            return pe_data

    def optimize_section_names(self, pe_data: bytes) -> bytes:
        """Optimize PE section names to use common benign names.

        Args:
            pe_data: Raw PE file bytes

        Returns:
            PE file bytes with optimized section names
        """
        try:
            with PEWriter(pe_data) as writer:
                # Get current sections
                with PEReader(pe_data) as reader:
                    sections = reader.get_sections()

                # Replace suspicious section names with benign ones
                section_replacements = {}
                for section in sections:
                    current_name = section.name.rstrip("\x00")
                    if self._is_suspicious_section_name(current_name):
                        benign_name = self._get_benign_section_name(current_name)
                        section_replacements[current_name] = benign_name

                # Apply replacements
                for old_name, new_name in section_replacements.items():
                    writer.modify_section_name(old_name, new_name)

                result = writer.get_modified_data()

            logger.info(
                "action=section_names_optimized replacements=%d",
                len(section_replacements),
            )
            return result

        except Exception as e:
            logger.error("action=section_name_optimization_failed error=%s", e)
            return pe_data

    def _preserve_original_timestamps(
        self, writer: PEWriter
    ) -> None:  # pylint: disable=unused-argument
        """Preserve original timestamps in PE file.

        Args:
            writer: PEWriter instance
        """
        # This is a simplified implementation
        # In a real implementation, we would preserve PE timestamps
        logger.info("action=original_timestamps_preserved")

    def _set_benign_timestamps(
        self, writer: PEWriter
    ) -> None:  # pylint: disable=unused-argument
        """Set benign timestamps in PE file.

        Args:
            writer: PEWriter instance
        """
        # Select a random benign timestamp
        if self.benign_timestamps:
            timestamp = random.choice(self.benign_timestamps)
            # This is a simplified implementation
            # In a real implementation, we would set PE timestamps
            logger.info("action=benign_timestamps_set timestamp=%d", timestamp)

    def _is_suspicious_section_name(self, name: str) -> bool:
        """Check if a section name is suspicious.

        Args:
            name: Section name to check

        Returns:
            True if the section name is suspicious
        """
        suspicious_names = self.common_section_names["suspicious"]
        return any(suspicious in name.lower() for suspicious in suspicious_names)

    def _get_benign_section_name(self, current_name: str) -> str:
        """Get a benign replacement for a suspicious section name.

        Args:
            current_name: Current suspicious section name

        Returns:
            Benign replacement section name
        """
        # Map suspicious names to benign equivalents
        suspicious_to_benign = {
            ".packed": ".text",
            ".upx": ".data",
            ".themida": ".rdata",
            ".vmprotect": ".bss",
            ".enigma": ".idata",
            ".aspack": ".edata",
            ".pecompact": ".rsrc",
            ".molebox": ".reloc",
            ".boxedapp": ".debug",
            ".petite": ".pdata",
            ".wwpack": ".xdata",
            ".pklite": ".tls",
            ".lzexe": ".gfids",
            ".diet": ".sxdata",
            ".aplib": ".init",
            ".lzma": ".fini",
            ".7zip": ".ctors",
            ".winrar": ".dtors",
            ".winzip": ".jcr",
            ".pkzip": ".eh_frame",
            ".arj": ".gcc_except_table",
            ".lha": ".rodata",
            ".cab": ".rodata1",
            ".msi": ".comment",
            ".nsis": ".note",
            ".inno": ".note.GNU-stack",
            ".wise": ".note.ABI-tag",
            ".confuser": ".gnu.version",
            ".eazfuscator": ".gnu.version_r",
            ".smartassembly": ".gnu.hash",
            ".dotfuscator": ".dynsym",
            ".codeveil": ".dynstr",
            ".phoenix": ".plt",
            ".codevirtualizer": ".got",
            ".asprotect": ".got.plt",
            ".exestealth": ".dynamic",
            ".peid": ".interp",
        }

        # Check for exact matches first
        if current_name.lower() in suspicious_to_benign:
            return suspicious_to_benign[current_name.lower()]

        # Check for partial matches
        for suspicious, benign in suspicious_to_benign.items():
            if suspicious in current_name.lower():
                return benign

        # Default to a random benign name
        benign_names = self.common_section_names["benign"]
        return random.choice(benign_names)

    def create_detection_mitigation_plan(self, pe_data: bytes) -> Dict[str, Any]:
        """Create a plan for detection vector mitigation.

        Args:
            pe_data: Raw PE file bytes

        Returns:
            Dictionary containing mitigation plan
        """
        # Analyze file size
        size_analysis = self.monitor_file_size(pe_data)

        # Analyze section names
        with PEReader(pe_data) as reader:
            sections = reader.get_sections()

        suspicious_sections = []
        for section in sections:
            section_name = section.name.rstrip("\x00")
            if self._is_suspicious_section_name(section_name):
                suspicious_sections.append(section_name)

        plan = {
            "file_size_monitoring": self.config.enable_file_size_monitoring,
            "timestamp_preservation": self.config.enable_timestamp_preservation,
            "section_name_optimization": self.config.enable_section_name_optimization,
            "size_analysis": size_analysis,
            "suspicious_sections": suspicious_sections,
            "total_sections": len(sections),
            "suspicious_section_count": len(suspicious_sections),
            "mitigation_techniques": sum(
                [
                    self.config.enable_file_size_monitoring,
                    self.config.enable_timestamp_preservation,
                    self.config.enable_section_name_optimization,
                ]
            ),
        }

        logger.info("action=detection_mitigation_plan_created plan=%s", plan)
        return plan

    def get_mitigation_report(
        self, original_data: bytes, mitigated_data: bytes
    ) -> Dict[str, Any]:
        """Generate a report of detection mitigation changes.

        Args:
            original_data: Original PE file bytes
            mitigated_data: Mitigated PE file bytes

        Returns:
            Dictionary containing mitigation report
        """
        report = {
            "size_change": len(mitigated_data) - len(original_data),
            "size_percentage": (len(mitigated_data) / len(original_data)) * 100,
            "file_size_monitoring": self.config.enable_file_size_monitoring,
            "timestamp_preservation": self.config.enable_timestamp_preservation,
            "section_name_optimization": self.config.enable_section_name_optimization,
            "mitigation_techniques_applied": sum(
                [
                    self.config.enable_file_size_monitoring,
                    self.config.enable_timestamp_preservation,
                    self.config.enable_section_name_optimization,
                ]
            ),
        }

        return report
