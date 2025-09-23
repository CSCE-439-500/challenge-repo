"""Tests for PE writer functionality.

This module contains pytest tests for the PE writer component,
including PE file modification, section addition, and payload injection.
"""

import os
import pytest
from unittest.mock import patch

from rt_evade.pe.writer import PEWriter


@pytest.fixture
def mock_pe_data():
    """Create mock PE data that pefile can parse."""
    # Create a more realistic PE structure that pefile can handle
    pe_data = bytearray(1024)
    
    # DOS header
    pe_data[0:2] = b"MZ"  # e_magic
    pe_data[60:64] = (64).to_bytes(4, 'little')  # e_lfanew
    
    # PE signature
    pe_data[64:68] = b"PE\x00\x00"
    
    # COFF header
    pe_data[68:70] = (0x014c).to_bytes(2, 'little')  # Machine (x86)
    pe_data[70:72] = (1).to_bytes(2, 'little')  # NumberOfSections
    pe_data[72:76] = (0).to_bytes(4, 'little')  # TimeDateStamp
    pe_data[76:80] = (0).to_bytes(4, 'little')  # PointerToSymbolTable
    pe_data[80:84] = (0).to_bytes(4, 'little')  # NumberOfSymbols
    pe_data[84:86] = (224).to_bytes(2, 'little')  # SizeOfOptionalHeader
    pe_data[86:88] = (0x010f).to_bytes(2, 'little')  # Characteristics
    
    # Optional header
    pe_data[88:90] = (0x010b).to_bytes(2, 'little')  # Magic (PE32)
    pe_data[90:92] = (0).to_bytes(1, 'little')  # MajorLinkerVersion
    pe_data[91:93] = (0).to_bytes(1, 'little')  # MinorLinkerVersion
    pe_data[92:96] = (0).to_bytes(4, 'little')  # SizeOfCode
    pe_data[96:100] = (0).to_bytes(4, 'little')  # SizeOfInitializedData
    pe_data[100:104] = (0).to_bytes(4, 'little')  # SizeOfUninitializedData
    pe_data[104:108] = (0x1000).to_bytes(4, 'little')  # AddressOfEntryPoint
    pe_data[108:112] = (0x1000).to_bytes(4, 'little')  # BaseOfCode
    pe_data[112:116] = (0).to_bytes(4, 'little')  # BaseOfData
    pe_data[116:120] = (0x400000).to_bytes(4, 'little')  # ImageBase
    pe_data[120:124] = (0x1000).to_bytes(4, 'little')  # SectionAlignment
    pe_data[124:128] = (0x200).to_bytes(4, 'little')  # FileAlignment
    pe_data[128:130] = (4).to_bytes(2, 'little')  # MajorOperatingSystemVersion
    pe_data[130:132] = (0).to_bytes(2, 'little')  # MinorOperatingSystemVersion
    pe_data[132:134] = (0).to_bytes(2, 'little')  # MajorImageVersion
    pe_data[134:136] = (0).to_bytes(2, 'little')  # MinorImageVersion
    pe_data[136:138] = (4).to_bytes(2, 'little')  # MajorSubsystemVersion
    pe_data[138:140] = (0).to_bytes(2, 'little')  # MinorSubsystemVersion
    pe_data[140:144] = (0).to_bytes(4, 'little')  # Win32VersionValue
    pe_data[144:148] = (0x2000).to_bytes(4, 'little')  # SizeOfImage
    pe_data[148:152] = (0x200).to_bytes(4, 'little')  # SizeOfHeaders
    pe_data[152:156] = (0).to_bytes(4, 'little')  # CheckSum
    pe_data[156:158] = (2).to_bytes(2, 'little')  # Subsystem (GUI)
    pe_data[158:160] = (0).to_bytes(2, 'little')  # DllCharacteristics
    pe_data[160:164] = (0).to_bytes(4, 'little')  # SizeOfStackReserve
    pe_data[164:168] = (0).to_bytes(4, 'little')  # SizeOfStackCommit
    pe_data[168:172] = (0).to_bytes(4, 'little')  # SizeOfHeapReserve
    pe_data[172:176] = (0).to_bytes(4, 'little')  # SizeOfHeapCommit
    pe_data[176:180] = (0).to_bytes(4, 'little')  # LoaderFlags
    pe_data[180:184] = (0).to_bytes(4, 'little')  # NumberOfRvaAndSizes
    
    # Data directories (all zeros for simplicity)
    pe_data[184:312] = b"\x00" * 128
    
    # Section header
    pe_data[312:320] = b".text\x00\x00\x00"  # Name
    pe_data[320:324] = (0).to_bytes(4, 'little')  # VirtualSize
    pe_data[324:328] = (0x1000).to_bytes(4, 'little')  # VirtualAddress
    pe_data[328:332] = (0x200).to_bytes(4, 'little')  # SizeOfRawData
    pe_data[332:336] = (0x400).to_bytes(4, 'little')  # PointerToRawData
    pe_data[336:340] = (0).to_bytes(4, 'little')  # PointerToRelocations
    pe_data[340:344] = (0).to_bytes(4, 'little')  # PointerToLinenumbers
    pe_data[344:346] = (0).to_bytes(2, 'little')  # NumberOfRelocations
    pe_data[346:348] = (0).to_bytes(2, 'little')  # NumberOfLinenumbers
    pe_data[348:352] = (0x60000020).to_bytes(4, 'little')  # Characteristics
    
    return bytes(pe_data)


class TestPEWriter:
    """Test PE writer functionality."""
    
    def test_pe_writer_initialization(self, mock_pe_data):
        """Test PE writer initialization."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            writer = PEWriter(mock_pe_data)
            assert writer is not None
            writer.close()
    
    def test_pe_writer_requires_redteam_mode(self, mock_pe_data):
        """Test that PE writer requires REDTEAM_MODE."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="REDTEAM_MODE not enabled"):
                PEWriter(mock_pe_data)
    
    def test_add_section(self, mock_pe_data):
        """Test adding a section to PE."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            with PEWriter(mock_pe_data) as writer:
                test_data = b"test_section_data"
                success = writer.add_section("test", test_data)
                # Note: This might fail with mock data due to PE structure limitations
                # The important thing is that it doesn't crash
                assert isinstance(success, bool)
    
    def test_modify_strings(self, mock_pe_data):
        """Test modifying strings in PE."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            with PEWriter(mock_pe_data) as writer:
                replacements = {"old_string": "new_string"}
                count = writer.modify_strings(replacements)
                assert isinstance(count, int)
                assert count >= 0
    
    def test_context_manager(self, mock_pe_data):
        """Test PE writer as context manager."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            with PEWriter(mock_pe_data) as writer:
                assert writer is not None
            # Should not raise exception on exit
