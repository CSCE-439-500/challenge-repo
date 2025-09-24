"""PE file reader module for parsing and analyzing PE files.

This module provides comprehensive PE file parsing capabilities while respecting
ROE guardrails. It focuses on in-memory analysis without side effects.
"""

import logging
import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
import pefile
from pefile import PE

from ..core.guards import require_redteam_mode

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PESectionInfo:
    """Information about a PE section."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_address: int
    raw_size: int
    characteristics: int
    entropy: float
    is_executable: bool
    is_writable: bool


@dataclass(frozen=True)
class PEImportInfo:
    """Information about PE imports."""

    dll_name: str
    function_name: str
    ordinal: Optional[int]
    address: int


@dataclass(frozen=True)
class PEHeaderInfo:
    """Key PE header information."""

    machine: int
    timestamp: int
    entry_point: int
    image_base: int
    section_alignment: int
    file_alignment: int
    subsystem: int
    dll_characteristics: int
    size_of_image: int
    size_of_headers: int


class PEReader:
    """PE file reader with comprehensive analysis capabilities.

    This class provides safe, ROE-compliant PE file reading and analysis.
    All operations are read-only and performed in memory.
    """

    def __init__(self, pe_data: bytes):
        """Initialize PE reader with binary data.

        Args:
            pe_data: Raw PE file bytes

        Raises:
            pefile.PEFormatError: If the data is not a valid PE file
            RuntimeError: If REDTEAM_MODE is not enabled
        """
        require_redteam_mode()

        self.pe_data = pe_data
        self.pe = PE(data=pe_data)
        self._validate_pe()

        logger.info(
            "action=pe_loaded size=%d machine=0x%x",
            len(pe_data),
            self.pe.FILE_HEADER.Machine,
        )

    def _validate_pe(self) -> None:
        """Validate that the loaded data is a valid PE file."""
        # Check if PE was loaded successfully by checking for required attributes
        if not hasattr(self.pe, "DOS_HEADER") or not hasattr(self.pe, "NT_HEADERS"):
            raise pefile.PEFormatError("Invalid PE file format")

        # Additional validation for red-team safety
        if self.pe.FILE_HEADER.Machine not in [0x014C, 0x8664]:  # x86, x64
            logger.warning(
                "action=unsupported_architecture machine=0x%x",
                self.pe.FILE_HEADER.Machine,
            )

    def get_header_info(self) -> PEHeaderInfo:
        """Extract key header information.

        Returns:
            PEHeaderInfo containing key PE header fields
        """
        return PEHeaderInfo(
            machine=self.pe.FILE_HEADER.Machine,
            timestamp=self.pe.FILE_HEADER.TimeDateStamp,
            entry_point=self.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            image_base=self.pe.OPTIONAL_HEADER.ImageBase,
            section_alignment=self.pe.OPTIONAL_HEADER.SectionAlignment,
            file_alignment=self.pe.OPTIONAL_HEADER.FileAlignment,
            subsystem=self.pe.OPTIONAL_HEADER.Subsystem,
            dll_characteristics=self.pe.OPTIONAL_HEADER.DllCharacteristics,
            size_of_image=self.pe.OPTIONAL_HEADER.SizeOfImage,
            size_of_headers=self.pe.OPTIONAL_HEADER.SizeOfHeaders,
        )

    def get_sections(self) -> List[PESectionInfo]:
        """Extract section information.

        Returns:
            List of PESectionInfo for each section
        """
        sections = []

        for section in self.pe.sections:
            # Calculate entropy for the section
            section_data = section.get_data()
            entropy = self._calculate_entropy(section_data) if section_data else 0.0

            sections.append(
                PESectionInfo(
                    name=section.Name.decode("utf-8", errors="ignore").rstrip("\x00"),
                    virtual_address=section.VirtualAddress,
                    virtual_size=section.Misc_VirtualSize,
                    raw_address=section.PointerToRawData,
                    raw_size=section.SizeOfRawData,
                    characteristics=section.Characteristics,
                    entropy=entropy,
                    is_executable=bool(
                        section.Characteristics & 0x20000000
                    ),  # IMAGE_SCN_MEM_EXECUTE
                    is_writable=bool(
                        section.Characteristics & 0x80000000
                    ),  # IMAGE_SCN_MEM_WRITE
                )
            )

        return sections

    def get_imports(self) -> List[PEImportInfo]:
        """Extract import information.

        Returns:
            List of PEImportInfo for each imported function
        """
        imports = []

        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")

                for imp in entry.imports:
                    if imp.name:
                        function_name = imp.name.decode("utf-8", errors="ignore")
                    else:
                        function_name = f"ordinal_{imp.ordinal}"

                    imports.append(
                        PEImportInfo(
                            dll_name=dll_name,
                            function_name=function_name,
                            ordinal=imp.ordinal,
                            address=imp.address,
                        )
                    )

        return imports

    def get_strings(self, min_length: int = 4) -> List[str]:
        """Extract printable strings from the PE file.

        Args:
            min_length: Minimum string length to include

        Returns:
            List of printable strings found in the PE
        """
        strings = []
        current_string = ""

        for byte in self.pe_data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""

        # Add final string if it meets criteria
        if len(current_string) >= min_length:
            strings.append(current_string)

        return strings

    def get_section_data(self, section_name: str) -> Optional[bytes]:
        """Get raw data for a specific section.

        Args:
            section_name: Name of the section to retrieve

        Returns:
            Raw section data or None if section not found
        """
        for section in self.pe.sections:
            if (
                section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                == section_name
            ):
                return section.get_data()
        return None

    def get_entropy_analysis(self) -> Dict[str, float]:
        """Calculate entropy for each section.

        Returns:
            Dictionary mapping section names to their entropy values
        """
        entropy_map = {}

        for section in self.pe.sections:
            section_data = section.get_data()
            if section_data:
                name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                entropy_map[name] = self._calculate_entropy(section_data)

        return entropy_map

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy for given data.

        Args:
            data: Binary data to analyze

        Returns:
            Entropy value between 0 and 8
        """
        if not data:
            return 0.0

        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                # Use log2 for entropy calculation instead of bit_length
                entropy -= probability * math.log2(probability)

        return entropy

    def get_pe_characteristics(self) -> Dict[str, Any]:
        """Get comprehensive PE characteristics for mimicry.

        Returns:
            Dictionary containing PE characteristics for template matching
        """
        header_info = self.get_header_info()
        sections = self.get_sections()
        imports = self.get_imports()

        # Group imports by DLL
        dll_imports = {}
        for imp in imports:
            if imp.dll_name not in dll_imports:
                dll_imports[imp.dll_name] = []
            dll_imports[imp.dll_name].append(imp.function_name)

        return {
            "header": {
                "machine": header_info.machine,
                "subsystem": header_info.subsystem,
                "dll_characteristics": header_info.dll_characteristics,
                "timestamp": header_info.timestamp,
            },
            "sections": {
                section.name: {
                    "characteristics": section.characteristics,
                    "is_executable": section.is_executable,
                    "is_writable": section.is_writable,
                    "entropy": section.entropy,
                }
                for section in sections
            },
            "imports": dll_imports,
            "strings": self.get_strings(min_length=6)[:100],  # Limit for performance
        }

    def close(self) -> None:
        """Clean up PE object and free memory."""
        if hasattr(self, "pe"):
            self.pe.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.close()
