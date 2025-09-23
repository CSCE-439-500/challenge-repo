"""PE file validator module for ensuring PE format integrity.

This module provides comprehensive PE file validation capabilities to ensure
that modified PE files maintain proper format and can execute correctly.
"""

import logging
from typing import Dict, Any
import pefile
from pefile import PE

from ..core.guards import require_redteam_mode

logger = logging.getLogger(__name__)


class PEValidationError(Exception):
    """Exception raised when PE validation fails."""


class PEValidator:
    """PE file validator with comprehensive format checking.

    This class provides thorough PE file validation to ensure format integrity
    and execution compatibility after modifications.
    """

    def __init__(self):
        """Initialize PE validator."""
        require_redteam_mode()
        self.validation_results = {}

    def validate_pe(self, pe_data: bytes) -> Dict[str, Any]:
        """Perform comprehensive PE validation.

        Args:
            pe_data: Raw PE file bytes to validate

        Returns:
            Dictionary containing validation results and issues

        Raises:
            PEValidationError: If critical validation errors are found
        """
        self.validation_results = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "info": {},
        }

        try:
            pe = PE(data=pe_data)

            # Basic PE format validation
            self._validate_pe_structure(pe)

            # Header validation
            self._validate_headers(pe)

            # Section validation
            self._validate_sections(pe)

            # Import table validation
            self._validate_imports(pe)

            # Size and alignment validation
            self._validate_size_and_alignment(pe)

            # Security validation
            self._validate_security_features(pe)

            pe.close()

        except pefile.PEFormatError as e:
            self.validation_results["valid"] = False
            self.validation_results["errors"].append(f"PE format error: {e}")
        except Exception as e:
            self.validation_results["valid"] = False
            self.validation_results["errors"].append(f"Unexpected error: {e}")

        # Determine overall validity
        if self.validation_results["errors"]:
            self.validation_results["valid"] = False

        logger.info(
            "action=pe_validation_complete valid=%s errors=%d warnings=%d",
            self.validation_results["valid"],
            len(self.validation_results["errors"]),
            len(self.validation_results["warnings"]),
        )

        return self.validation_results

    def _validate_pe_structure(self, pe: PE) -> None:
        """Validate basic PE structure."""
        # Check if PE was loaded successfully by checking for required attributes
        if not hasattr(pe, "DOS_HEADER") or not hasattr(pe, "NT_HEADERS"):
            self.validation_results["errors"].append("Invalid PE file structure")
            return

        # Check DOS header
        if not hasattr(pe, "DOS_HEADER") or pe.DOS_HEADER.e_magic != 0x5A4D:
            self.validation_results["errors"].append("Invalid DOS header")

        # Check NT headers
        if not hasattr(pe, "NT_HEADERS"):
            self.validation_results["errors"].append("Missing NT headers")

        # Check file header
        if not hasattr(pe, "FILE_HEADER"):
            self.validation_results["errors"].append("Missing file header")

        # Check optional header
        if not hasattr(pe, "OPTIONAL_HEADER"):
            self.validation_results["errors"].append("Missing optional header")

    def _validate_headers(self, pe: PE) -> None:
        """Validate PE headers."""
        # File header validation
        if hasattr(pe, "FILE_HEADER"):
            if pe.FILE_HEADER.Machine not in [0x014C, 0x8664]:  # x86, x64
                self.validation_results["warnings"].append(
                    f"Unsupported architecture: 0x{pe.FILE_HEADER.Machine:x}"
                )

            if pe.FILE_HEADER.NumberOfSections == 0:
                self.validation_results["errors"].append("No sections found")

            if pe.FILE_HEADER.NumberOfSections > 100:
                self.validation_results["warnings"].append(
                    f"Unusually high section count: {pe.FILE_HEADER.NumberOfSections}"
                )

        # Optional header validation
        if hasattr(pe, "OPTIONAL_HEADER"):
            if pe.OPTIONAL_HEADER.Magic not in [0x010B, 0x020B]:  # PE32, PE32+
                self.validation_results["errors"].append(
                    f"Invalid optional header magic: 0x{pe.OPTIONAL_HEADER.Magic:x}"
                )

            if pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
                self.validation_results["warnings"].append("Entry point is zero")

            if pe.OPTIONAL_HEADER.SizeOfImage == 0:
                self.validation_results["errors"].append("Image size is zero")

            if pe.OPTIONAL_HEADER.SizeOfHeaders == 0:
                self.validation_results["errors"].append("Header size is zero")

    def _validate_sections(self, pe: PE) -> None:
        """Validate PE sections."""
        if not pe.sections:
            self.validation_results["errors"].append("No sections found")
            return

        section_names = set()
        virtual_addresses = set()
        raw_addresses = set()

        for section in pe.sections:
            # Check section name
            section_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            if section_name in section_names:
                self.validation_results["warnings"].append(
                    f"Duplicate section name: {section_name}"
                )
            section_names.add(section_name)

            # Check virtual address
            if section.VirtualAddress in virtual_addresses:
                self.validation_results["errors"].append(
                    f"Duplicate virtual address in section {section_name}: "
                    f"0x{section.VirtualAddress:x}"
                )
            virtual_addresses.add(section.VirtualAddress)

            # Check raw address
            if section.PointerToRawData in raw_addresses:
                self.validation_results["warnings"].append(
                    f"Duplicate raw address in section {section_name}: "
                    f"0x{section.PointerToRawData:x}"
                )
            raw_addresses.add(section.PointerToRawData)

            # Check section characteristics
            if section.Characteristics == 0:
                self.validation_results["warnings"].append(
                    f"Section {section_name} has no characteristics"
                )

            # Check for suspicious section names
            suspicious_names = [".malware", ".payload", ".inject", ".backdoor"]
            if any(sus in section_name.lower() for sus in suspicious_names):
                self.validation_results["warnings"].append(
                    f"Suspicious section name: {section_name}"
                )

    def _validate_imports(self, pe: PE) -> None:
        """Validate import table."""
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            self.validation_results["warnings"].append("No import table found")
            return

        import_dlls = set()
        import_functions = set()

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="ignore")
            import_dlls.add(dll_name.lower())

            for imp in entry.imports:
                if imp.name:
                    function_name = imp.name.decode("utf-8", errors="ignore")
                    import_functions.add(f"{dll_name}.{function_name}")

        # Check for suspicious imports
        suspicious_dlls = ["kernel32.dll", "ntdll.dll", "advapi32.dll"]
        suspicious_functions = [
            "CreateProcess",
            "CreateRemoteThread",
            "VirtualAlloc",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "OpenProcess",
            "TerminateProcess",
            "LoadLibrary",
            "GetProcAddress",
            "SetWindowsHookEx",
            "RegisterHotKey",
        ]

        for dll in import_dlls:
            if dll in suspicious_dlls:
                self.validation_results["warnings"].append(
                    f"Suspicious DLL import: {dll}"
                )

        for func in import_functions:
            if any(sus in func.lower() for sus in suspicious_functions):
                self.validation_results["warnings"].append(
                    f"Suspicious function import: {func}"
                )

    def _validate_size_and_alignment(self, pe: PE) -> None:
        """Validate file size and alignment."""
        if hasattr(pe, "OPTIONAL_HEADER"):
            file_alignment = pe.OPTIONAL_HEADER.FileAlignment
            section_alignment = pe.OPTIONAL_HEADER.SectionAlignment

            # Check alignment values
            if file_alignment not in [0x200, 0x1000]:  # 512, 4096
                self.validation_results["warnings"].append(
                    f"Unusual file alignment: 0x{file_alignment:x}"
                )

            if section_alignment not in [0x1000, 0x2000, 0x4000]:  # 4KB, 8KB, 16KB
                self.validation_results["warnings"].append(
                    f"Unusual section alignment: 0x{section_alignment:x}"
                )

            # Check image size
            if pe.OPTIONAL_HEADER.SizeOfImage > 100 * 1024 * 1024:  # 100MB
                self.validation_results["warnings"].append(
                    f"Large image size: {pe.OPTIONAL_HEADER.SizeOfImage} bytes"
                )

    def _validate_security_features(self, pe: PE) -> None:
        """Validate security-related features."""
        if hasattr(pe, "OPTIONAL_HEADER"):
            dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics

            # Check for security features
            if dll_characteristics & 0x0020:  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                self.validation_results["info"]["aslr_enabled"] = True
            else:
                self.validation_results["warnings"].append("ASLR not enabled")

            if dll_characteristics & 0x0100:  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                self.validation_results["info"]["nx_compat"] = True
            else:
                self.validation_results["warnings"].append(
                    "NX compatibility not enabled"
                )

            if dll_characteristics & 0x0040:  # IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
                self.validation_results["info"]["force_integrity"] = True

            if (
                dll_characteristics & 0x0080
            ):  # IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
                self.validation_results["info"]["terminal_server_aware"] = True

    def validate_execution_compatibility(self, pe_data: bytes) -> bool:
        """Validate that the PE file can execute properly.

        Args:
            pe_data: Raw PE file bytes to validate

        Returns:
            True if the file appears executable
        """
        try:
            pe = PE(data=pe_data)

            # Check if it's an executable (not a DLL)
            if hasattr(pe, "OPTIONAL_HEADER"):
                subsystem = pe.OPTIONAL_HEADER.Subsystem
                if subsystem not in [
                    1,
                    2,
                    3,
                    9,
                    10,
                    11,
                ]:  # Common executable subsystems
                    logger.warning("action=unusual_subsystem subsystem=%d", subsystem)

            # Check entry point
            if pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
                logger.warning("action=zero_entry_point")
                return False

            pe.close()
            return True

        except Exception as e:
            logger.error("action=execution_validation_failed error=%s", e)
            return False

    def get_validation_summary(self) -> str:
        """Get a human-readable validation summary.

        Returns:
            Formatted validation summary string
        """
        if not self.validation_results:
            return "No validation performed"

        valid = self.validation_results["valid"]
        errors = len(self.validation_results["errors"])
        warnings = len(self.validation_results["warnings"])

        summary = f"PE Validation: {'PASS' if valid else 'FAIL'}"
        summary += f" (Errors: {errors}, Warnings: {warnings})"

        if errors > 0:
            summary += "\nErrors:\n" + "\n".join(
                f"  - {error}" for error in self.validation_results["errors"]
            )

        if warnings > 0:
            summary += "\nWarnings:\n" + "\n".join(
                f"  - {warning}" for warning in self.validation_results["warnings"]
            )

        return summary
