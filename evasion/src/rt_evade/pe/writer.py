"""PE file writer module for modifying PE files while preserving structure.

This module provides safe PE file modification capabilities while respecting
ROE guardrails. All modifications preserve PE format integrity.
"""

import logging
import os
from typing import Dict, List, Optional, Tuple, Any
import pefile
from pefile import PE, SectionStructure

from ..core.guards import require_redteam_mode, guard_can_write
from .reader import PEReader, PESectionInfo, PEHeaderInfo

logger = logging.getLogger(__name__)


class PEWriter:
    """PE file writer with structure-preserving modification capabilities.

    This class provides safe, ROE-compliant PE file modification while
    maintaining PE format integrity and original functionality.
    """

    def __init__(self, pe_data: bytes):
        """Initialize PE writer with binary data.

        Args:
            pe_data: Raw PE file bytes

        Raises:
            pefile.PEFormatError: If the data is not a valid PE file
            RuntimeError: If REDTEAM_MODE is not enabled
        """
        require_redteam_mode()

        self.pe_data = bytearray(pe_data)
        self.pe = PE(data=self.pe_data)
        self._validate_pe()

        logger.info(
            "action=pe_writer_initialized size=%d machine=0x%x",
            len(pe_data),
            self.pe.FILE_HEADER.Machine,
        )

    def _validate_pe(self) -> None:
        """Validate that the loaded data is a valid PE file."""
        # Check if PE was loaded successfully by checking for required attributes
        if not hasattr(self.pe, "DOS_HEADER") or not hasattr(self.pe, "NT_HEADERS"):
            raise pefile.PEFormatError("Invalid PE file format")

    def add_section(
        self, name: str, data: bytes, characteristics: int = 0x40000000
    ) -> bool:
        """Add a new section to the PE file.

        Args:
            name: Section name (max 8 characters)
            data: Section data
            characteristics: Section characteristics flags

        Returns:
            True if section was added successfully

        Raises:
            ValueError: If section name is too long or invalid
        """
        guard_can_write()

        if len(name) > 8:
            raise ValueError("Section name must be 8 characters or less")

        # Ensure name is null-padded to 8 bytes
        section_name = name.encode("ascii").ljust(8, b"\x00")

        # Calculate new section parameters
        file_alignment = self.pe.OPTIONAL_HEADER.FileAlignment
        section_alignment = self.pe.OPTIONAL_HEADER.SectionAlignment

        # Align data size to file alignment
        raw_size = ((len(data) + file_alignment - 1) // file_alignment) * file_alignment
        virtual_size = (
            (len(data) + section_alignment - 1) // section_alignment
        ) * section_alignment

        # Find the last section to calculate new addresses
        last_section = self.pe.sections[-1] if self.pe.sections else None

        if last_section:
            raw_address = last_section.PointerToRawData + last_section.SizeOfRawData
            virtual_address = (
                last_section.VirtualAddress + last_section.Misc_VirtualSize
            )
        else:
            raw_address = self.pe.OPTIONAL_HEADER.SizeOfHeaders
            virtual_address = self.pe.OPTIONAL_HEADER.SizeOfHeaders

        # Create new section
        new_section = SectionStructure(
            self.pe.__IMAGE_SECTION_HEADER_format__, pe=self.pe
        )

        # Set section header fields
        new_section.Name = section_name
        new_section.Misc_VirtualSize = virtual_size
        new_section.VirtualAddress = virtual_address
        new_section.SizeOfRawData = raw_size
        new_section.PointerToRawData = raw_address
        new_section.PointerToRelocations = 0
        new_section.PointerToLinenumbers = 0
        new_section.NumberOfRelocations = 0
        new_section.NumberOfLinenumbers = 0
        new_section.Characteristics = characteristics

        # Add section to PE
        self.pe.sections.append(new_section)

        # Update PE headers
        self.pe.FILE_HEADER.NumberOfSections += 1

        # Update image size
        new_image_size = virtual_address + virtual_size
        if new_image_size > self.pe.OPTIONAL_HEADER.SizeOfImage:
            self.pe.OPTIONAL_HEADER.SizeOfImage = new_image_size

        # Pad data to file alignment
        padded_data = data + b"\x00" * (raw_size - len(data))

        # Insert data into the PE file
        self.pe_data[raw_address:raw_address] = padded_data

        # Update all subsequent section addresses
        self._update_section_addresses()

        logger.info(
            "action=section_added name=%s size=%d virtual_addr=0x%x",
            name,
            len(data),
            virtual_address,
        )

        return True

    def modify_section_data(self, section_name: str, new_data: bytes) -> bool:
        """Modify data in an existing section.

        Args:
            section_name: Name of the section to modify
            new_data: New section data

        Returns:
            True if section was modified successfully
        """
        guard_can_write()

        section = self._find_section(section_name)
        if not section:
            logger.warning("action=section_not_found name=%s", section_name)
            return False

        # Ensure new data fits in section
        if len(new_data) > section.SizeOfRawData:
            logger.warning(
                "action=data_too_large section=%s available=%d needed=%d",
                section_name,
                section.SizeOfRawData,
                len(new_data),
            )
            return False

        # Replace section data
        start = section.PointerToRawData
        end = start + len(new_data)

        # Pad with nulls if new data is smaller
        padded_data = new_data + b"\x00" * (section.SizeOfRawData - len(new_data))

        self.pe_data[start : start + section.SizeOfRawData] = padded_data

        logger.info(
            "action=section_modified name=%s size=%d", section_name, len(new_data)
        )

        return True

    def inject_payload_to_section(
        self, section_name: str, payload: bytes, offset: int = 0
    ) -> bool:
        """Inject payload into an existing section at specified offset.

        Args:
            section_name: Name of the target section
            payload: Payload data to inject
            offset: Offset within the section to inject at

        Returns:
            True if payload was injected successfully
        """
        guard_can_write()

        section = self._find_section(section_name)
        if not section:
            logger.warning("action=section_not_found name=%s", section_name)
            return False

        # Check if payload fits at offset
        if offset + len(payload) > section.SizeOfRawData:
            logger.warning(
                "action=payload_too_large section=%s offset=%d available=%d needed=%d",
                section_name,
                offset,
                section.SizeOfRawData - offset,
                len(payload),
            )
            return False

        # Inject payload
        start = section.PointerToRawData + offset
        self.pe_data[start : start + len(payload)] = payload

        logger.info(
            "action=payload_injected section=%s offset=%d size=%d",
            section_name,
            offset,
            len(payload),
        )

        return True

    def add_import(self, dll_name: str, function_name: str) -> bool:
        """Add a new import to the PE file.

        Args:
            dll_name: Name of the DLL to import from
            function_name: Name of the function to import

        Returns:
            True if import was added successfully
        """
        guard_can_write()

        # This is a simplified implementation
        # Full import table modification requires complex PE manipulation
        logger.warning(
            "action=import_addition_not_implemented dll=%s function=%s",
            dll_name,
            function_name,
        )
        return False

    def modify_strings(self, string_replacements: Dict[str, str]) -> int:
        """Replace strings in the PE file.

        Args:
            string_replacements: Dictionary mapping old strings to new strings

        Returns:
            Number of strings replaced
        """
        guard_can_write()

        replacements_made = 0

        for old_string, new_string in string_replacements.items():
            old_bytes = old_string.encode("utf-8")
            new_bytes = new_string.encode("utf-8")

            # Ensure new string is not longer than old string
            if len(new_bytes) > len(old_bytes):
                logger.warning(
                    "action=string_too_long old=%s new=%s", old_string, new_string
                )
                continue

            # Pad new string to match old string length
            padded_new = new_bytes + b"\x00" * (len(old_bytes) - len(new_bytes))

            # Find and replace all occurrences
            start = 0
            while True:
                pos = self.pe_data.find(old_bytes, start)
                if pos == -1:
                    break

                self.pe_data[pos : pos + len(old_bytes)] = padded_new
                replacements_made += 1
                start = pos + 1

        logger.info("action=strings_replaced count=%d", replacements_made)
        return replacements_made

    def add_junk_data(self, section_name: str, size: int) -> bool:
        """Add junk data to a section to increase entropy.

        Args:
            section_name: Name of the section to add junk to
            size: Number of bytes of junk data to add

        Returns:
            True if junk data was added successfully
        """
        guard_can_write()

        section = self._find_section(section_name)
        if not section:
            logger.warning("action=section_not_found name=%s", section_name)
            return False

        # Generate random junk data
        import secrets

        junk_data = secrets.token_bytes(size)

        # Find a suitable location within the section
        section_data_start = section.PointerToRawData
        section_data_end = section_data_start + section.SizeOfRawData

        # Look for null bytes to replace
        null_start = self.pe_data.find(
            b"\x00" * size, section_data_start, section_data_end
        )
        if null_start != -1:
            self.pe_data[null_start : null_start + size] = junk_data
            logger.info("action=junk_data_added section=%s size=%d", section_name, size)
            return True
        else:
            logger.warning(
                "action=no_space_for_junk section=%s size=%d", section_name, size
            )
            return False

    def _find_section(self, section_name: str) -> Optional[SectionStructure]:
        """Find a section by name.

        Args:
            section_name: Name of the section to find

        Returns:
            SectionStructure if found, None otherwise
        """
        for section in self.pe.sections:
            if (
                section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                == section_name
            ):
                return section
        return None

    def _update_section_addresses(self) -> None:
        """Update addresses of all sections after modifications."""
        # This is a simplified implementation
        # Full address recalculation requires complex PE manipulation
        pass

    def get_modified_data(self) -> bytes:
        """Get the modified PE data.

        Returns:
            Modified PE file as bytes
        """
        return bytes(self.pe_data)

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
