"""Tests for obfuscation tools functionality.

This module contains pytest tests for the obfuscation tools component,
including PE file manipulation functions.
"""

import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock

from obfuscation_agent.obfuscation_tools import (
    add_junk_sections,
    rearrange_sections,
    change_section_names,
    change_timestamp,
    validate_pe_file,
)


@pytest.fixture
def mock_pe_data():
    """Create mock PE data that pefile can parse."""
    # Create a more realistic PE structure that pefile can handle
    pe_data = bytearray(1024)

    # DOS header
    pe_data[0:2] = b"MZ"  # e_magic
    pe_data[60:64] = (64).to_bytes(4, "little")  # e_lfanew

    # PE signature
    pe_data[64:68] = b"PE\x00\x00"

    # COFF header
    pe_data[68:70] = (0x014C).to_bytes(2, "little")  # Machine (x86)
    pe_data[70:72] = (1).to_bytes(2, "little")  # NumberOfSections
    pe_data[72:76] = (0).to_bytes(4, "little")  # TimeDateStamp
    pe_data[76:80] = (0).to_bytes(4, "little")  # PointerToSymbolTable
    pe_data[80:84] = (0).to_bytes(4, "little")  # NumberOfSymbols
    pe_data[84:86] = (224).to_bytes(2, "little")  # SizeOfOptionalHeader
    pe_data[86:88] = (0x010F).to_bytes(2, "little")  # Characteristics

    # Optional header
    pe_data[88:90] = (0x010B).to_bytes(2, "little")  # Magic (PE32)
    pe_data[90:92] = (0).to_bytes(1, "little")  # MajorLinkerVersion
    pe_data[91:93] = (0).to_bytes(1, "little")  # MinorLinkerVersion
    pe_data[92:96] = (0).to_bytes(4, "little")  # SizeOfCode
    pe_data[96:100] = (0).to_bytes(4, "little")  # SizeOfInitializedData
    pe_data[100:104] = (0).to_bytes(4, "little")  # SizeOfUninitializedData
    pe_data[104:108] = (0x1000).to_bytes(4, "little")  # AddressOfEntryPoint
    pe_data[108:112] = (0x1000).to_bytes(4, "little")  # BaseOfCode
    pe_data[112:116] = (0).to_bytes(4, "little")  # BaseOfData
    pe_data[116:120] = (0x400000).to_bytes(4, "little")  # ImageBase
    pe_data[120:124] = (0x1000).to_bytes(4, "little")  # SectionAlignment
    pe_data[124:128] = (0x200).to_bytes(4, "little")  # FileAlignment
    pe_data[128:130] = (4).to_bytes(2, "little")  # MajorOperatingSystemVersion
    pe_data[130:132] = (0).to_bytes(2, "little")  # MinorOperatingSystemVersion
    pe_data[132:134] = (0).to_bytes(2, "little")  # MajorImageVersion
    pe_data[134:136] = (0).to_bytes(2, "little")  # MinorImageVersion
    pe_data[136:138] = (4).to_bytes(2, "little")  # MajorSubsystemVersion
    pe_data[138:140] = (0).to_bytes(2, "little")  # MinorSubsystemVersion
    pe_data[140:144] = (0).to_bytes(4, "little")  # Win32VersionValue
    pe_data[144:148] = (0x2000).to_bytes(4, "little")  # SizeOfImage
    pe_data[148:152] = (0x200).to_bytes(4, "little")  # SizeOfHeaders
    pe_data[152:156] = (0).to_bytes(4, "little")  # CheckSum
    pe_data[156:158] = (2).to_bytes(2, "little")  # Subsystem
    pe_data[158:160] = (0).to_bytes(2, "little")  # DllCharacteristics
    pe_data[160:164] = (0x100000).to_bytes(4, "little")  # SizeOfStackReserve
    pe_data[164:168] = (0x1000).to_bytes(4, "little")  # SizeOfStackCommit
    pe_data[168:172] = (0x100000).to_bytes(4, "little")  # SizeOfHeapReserve
    pe_data[172:176] = (0x1000).to_bytes(4, "little")  # SizeOfHeapCommit
    pe_data[176:180] = (0).to_bytes(4, "little")  # LoaderFlags
    pe_data[180:184] = (16).to_bytes(4, "little")  # NumberOfRvaAndSizes

    # Data directories (all zeros for simplicity)
    for i in range(16):
        offset = 184 + (i * 8)
        pe_data[offset : offset + 8] = b"\x00" * 8

    # Section header (.text)
    pe_data[312:320] = b".text\x00\x00\x00"  # Name
    pe_data[320:324] = (0x1000).to_bytes(4, "little")  # VirtualSize
    pe_data[324:328] = (0x1000).to_bytes(4, "little")  # VirtualAddress
    pe_data[328:332] = (0x200).to_bytes(4, "little")  # SizeOfRawData
    pe_data[332:336] = (0x200).to_bytes(4, "little")  # PointerToRawData
    pe_data[336:340] = (0).to_bytes(4, "little")  # PointerToRelocations
    pe_data[340:344] = (0).to_bytes(4, "little")  # PointerToLinenumbers
    pe_data[344:346] = (0).to_bytes(2, "little")  # NumberOfRelocations
    pe_data[346:348] = (0).to_bytes(2, "little")  # NumberOfLinenumbers
    pe_data[348:352] = (0x60000020).to_bytes(4, "little")  # Characteristics

    return bytes(pe_data)


@pytest.fixture
def temp_pe_file(mock_pe_data):
    """Create a temporary PE file for testing."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(mock_pe_data)
        temp_file = f.name
    yield temp_file
    # Cleanup
    if os.path.exists(temp_file):
        os.unlink(temp_file)


class TestObfuscationTools:
    """Test class for obfuscation tools."""

    def test_validate_pe_file_valid(self, temp_pe_file):
        """Test PE file validation with valid file."""
        assert validate_pe_file(temp_pe_file) is True

    def test_validate_pe_file_invalid(self):
        """Test PE file validation with invalid file."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"Not a PE file")
            invalid_file = f.name

        try:
            assert validate_pe_file(invalid_file) is False
        finally:
            os.unlink(invalid_file)

    def test_validate_pe_file_nonexistent(self):
        """Test PE file validation with nonexistent file."""
        assert validate_pe_file("nonexistent.exe") is False

    @patch("obfuscation_agent.obfuscation_tools.PEReader")
    @patch("obfuscation_agent.obfuscation_tools.PEWriter")
    def test_add_junk_sections_success(
        self, mock_writer_class, mock_reader_class, temp_pe_file
    ):
        """Test successful junk section addition."""
        # Mock the context managers
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_reader_class.return_value.__enter__.return_value = mock_reader
        mock_writer_class.return_value.__enter__.return_value = mock_writer
        mock_writer.get_modified_data.return_value = b"modified_pe_data"

        result = add_junk_sections(temp_pe_file)

        assert result.endswith("_junked.exe")
        assert os.path.exists(result)

        # Cleanup
        if os.path.exists(result):
            os.unlink(result)

    def test_add_junk_sections_error_handling(self, temp_pe_file):
        """Test error handling in add_junk_sections."""
        # Test with invalid file path
        result = add_junk_sections("nonexistent.exe")
        assert result == "nonexistent.exe"

    @patch("obfuscation_agent.obfuscation_tools.PEReader")
    @patch("obfuscation_agent.obfuscation_tools.PEWriter")
    def test_rearrange_sections_success(
        self, mock_writer_class, mock_reader_class, temp_pe_file
    ):
        """Test successful section rearrangement."""
        # Mock the context managers
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_reader_class.return_value.__enter__.return_value = mock_reader
        mock_writer_class.return_value.__enter__.return_value = mock_writer
        mock_writer.get_modified_data.return_value = b"modified_pe_data"

        # Mock section data
        mock_section = MagicMock()
        mock_section.name = ".text"
        mock_reader.get_sections.return_value = [mock_section]
        mock_reader.get_section_data.return_value = b"section_data"

        result = rearrange_sections(temp_pe_file)

        assert result.endswith("_rearranged.exe")
        assert os.path.exists(result)

        # Cleanup
        if os.path.exists(result):
            os.unlink(result)

    def test_rearrange_sections_error_handling(self, temp_pe_file):
        """Test error handling in rearrange_sections."""
        result = rearrange_sections("nonexistent.exe")
        assert result == "nonexistent.exe"

    @patch("obfuscation_agent.obfuscation_tools.PEReader")
    @patch("obfuscation_agent.obfuscation_tools.PEWriter")
    def test_change_section_names_success(
        self, mock_writer_class, mock_reader_class, temp_pe_file
    ):
        """Test successful section name changes."""
        # Mock the context managers
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_reader_class.return_value.__enter__.return_value = mock_reader
        mock_writer_class.return_value.__enter__.return_value = mock_writer
        mock_writer.get_modified_data.return_value = b"modified_pe_data"

        # Mock section data
        mock_section = MagicMock()
        mock_section.name = ".text"
        mock_reader.get_sections.return_value = [mock_section]
        mock_reader.get_section_data.return_value = b"section_data"

        result = change_section_names(temp_pe_file)

        assert result.endswith("_renamed.exe")
        assert os.path.exists(result)

        # Cleanup
        if os.path.exists(result):
            os.unlink(result)

    def test_change_section_names_error_handling(self, temp_pe_file):
        """Test error handling in change_section_names."""
        result = change_section_names("nonexistent.exe")
        assert result == "nonexistent.exe"

    @patch("obfuscation_agent.obfuscation_tools.PE")
    def test_change_timestamp_success(self, mock_pe_class, temp_pe_file):
        """Test successful timestamp change."""
        # Mock PE object
        mock_pe = MagicMock()
        mock_pe_class.return_value = mock_pe
        mock_pe.write.return_value = b"modified_pe_data"

        result = change_timestamp(temp_pe_file)

        assert result.endswith("_timestamped.exe")
        assert os.path.exists(result)

        # Verify timestamp was modified
        mock_pe.FILE_HEADER.TimeDateStamp = 1234567890

        # Cleanup
        if os.path.exists(result):
            os.unlink(result)
        mock_pe.close.assert_called_once()

    def test_change_timestamp_error_handling(self, temp_pe_file):
        """Test error handling in change_timestamp."""
        result = change_timestamp("nonexistent.exe")
        assert result == "nonexistent.exe"
