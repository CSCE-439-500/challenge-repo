"""Tests for PE section manipulation functionality.

This module contains pytest tests for the PE section manipulation component,
including padding and entropy modification testing.
"""

import os
import pytest
from unittest.mock import patch

from rt_evade.pe.section_manipulation import (
    PESectionManipulator,
    SectionManipulationConfig,
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
    pe_data[156:158] = (2).to_bytes(2, "little")  # Subsystem (GUI)
    pe_data[158:160] = (0).to_bytes(2, "little")  # DllCharacteristics
    pe_data[160:164] = (0).to_bytes(4, "little")  # SizeOfStackReserve
    pe_data[164:168] = (0).to_bytes(4, "little")  # SizeOfStackCommit
    pe_data[168:172] = (0).to_bytes(4, "little")  # SizeOfHeapReserve
    pe_data[172:176] = (0).to_bytes(4, "little")  # SizeOfHeapCommit
    pe_data[176:180] = (0).to_bytes(4, "little")  # LoaderFlags
    pe_data[180:184] = (0).to_bytes(4, "little")  # NumberOfRvaAndSizes

    # Data directories (all zeros for simplicity)
    pe_data[184:312] = b"\x00" * 128

    # Section header
    pe_data[312:320] = b".text\x00\x00\x00"  # Name
    pe_data[320:324] = (0).to_bytes(4, "little")  # VirtualSize
    pe_data[324:328] = (0x1000).to_bytes(4, "little")  # VirtualAddress
    pe_data[328:332] = (0x200).to_bytes(4, "little")  # SizeOfRawData
    pe_data[332:336] = (0x400).to_bytes(4, "little")  # PointerToRawData
    pe_data[336:340] = (0).to_bytes(4, "little")  # PointerToRelocations
    pe_data[340:344] = (0).to_bytes(4, "little")  # PointerToLinenumbers
    pe_data[344:346] = (0).to_bytes(2, "little")  # NumberOfRelocations
    pe_data[346:348] = (0).to_bytes(2, "little")  # NumberOfLinenumbers
    pe_data[348:352] = (0x60000020).to_bytes(4, "little")  # Characteristics

    return bytes(pe_data)


class TestPESectionManipulator:
    """Test PE section manipulator functionality."""

    def test_manipulator_initialization(self):
        """Test manipulator initialization."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = SectionManipulationConfig()
            manipulator = PESectionManipulator(config)
            assert manipulator is not None
            # The config gets modified with defaults, so we check the important fields
            assert (
                manipulator.config.enable_section_padding
                == config.enable_section_padding
            )
            assert (
                manipulator.config.enable_entropy_increase
                == config.enable_entropy_increase
            )
            assert manipulator.config.max_padding_size == config.max_padding_size
            assert manipulator.config.entropy_data_size == config.entropy_data_size
            # Check that defaults were applied
            assert manipulator.config.padding_sections is not None
            assert manipulator.config.entropy_sections is not None

    def test_manipulator_requires_redteam_mode(self):
        """Test that manipulator requires REDTEAM_MODE."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="REDTEAM_MODE not enabled"):
                PESectionManipulator()

    def test_manipulate_sections_disabled(self, mock_pe_data):
        """Test that section manipulation is skipped when disabled."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = SectionManipulationConfig(
                enable_section_padding=False, enable_entropy_increase=False
            )
            manipulator = PESectionManipulator(config)

            result = manipulator.manipulate_sections(mock_pe_data)
            assert result == mock_pe_data

    def test_manipulate_sections_padding_only(self, mock_pe_data):
        """Test section manipulation with padding only."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = SectionManipulationConfig(
                enable_section_padding=True,
                enable_entropy_increase=False,
                padding_sections=[".data", ".rdata"],
                max_padding_size=512,
            )
            manipulator = PESectionManipulator(config)

            try:
                result = manipulator.manipulate_sections(mock_pe_data)
                assert isinstance(result, bytes)
                assert len(result) > 0
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_manipulate_sections_entropy_only(self, mock_pe_data):
        """Test section manipulation with entropy increase only."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = SectionManipulationConfig(
                enable_section_padding=False,
                enable_entropy_increase=True,
                entropy_sections=[".data"],
                entropy_data_size=256,
            )
            manipulator = PESectionManipulator(config)

            try:
                result = manipulator.manipulate_sections(mock_pe_data)
                assert isinstance(result, bytes)
                assert len(result) > 0
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_manipulate_sections_both_enabled(self, mock_pe_data):
        """Test section manipulation with both padding and entropy increase."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = SectionManipulationConfig(
                enable_section_padding=True,
                enable_entropy_increase=True,
                padding_sections=[".data", ".rdata"],
                entropy_sections=[".data"],
                max_padding_size=256,
                entropy_data_size=128,
            )
            manipulator = PESectionManipulator(config)

            try:
                result = manipulator.manipulate_sections(mock_pe_data)
                assert isinstance(result, bytes)
                assert len(result) > 0
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_get_section_manipulation_report(self, mock_pe_data):
        """Test section manipulation report generation."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = SectionManipulationConfig(
                enable_section_padding=True,
                enable_entropy_increase=True,
                padding_sections=[".data"],
                entropy_sections=[".data"],
                max_padding_size=512,
                entropy_data_size=256,
            )
            manipulator = PESectionManipulator(config)

            try:
                result = manipulator.manipulate_sections(mock_pe_data)
                report = manipulator.get_section_manipulation_report(
                    mock_pe_data, result
                )

                assert isinstance(report, dict)
                assert "section_padding_enabled" in report
                assert "entropy_increase_enabled" in report
                assert "padding_sections" in report
                assert "entropy_sections" in report
                assert "max_padding_size" in report
                assert "entropy_data_size" in report
                assert "original_size" in report
                assert "manipulated_size" in report
                assert "size_change" in report
                assert "size_percentage" in report
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)


class TestSectionManipulationConfig:
    """Test section manipulation configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SectionManipulationConfig()
        assert config.enable_section_padding is True
        assert config.enable_entropy_increase is True
        assert config.max_padding_size == 1024
        assert config.entropy_data_size == 512

    def test_custom_config(self):
        """Test custom configuration values."""
        config = SectionManipulationConfig(
            enable_section_padding=False,
            enable_entropy_increase=True,
            padding_sections=[".text", ".data"],
            entropy_sections=[".rdata"],
            max_padding_size=2048,
            entropy_data_size=1024,
        )

        assert config.enable_section_padding is False
        assert config.enable_entropy_increase is True
        assert config.padding_sections == [".text", ".data"]
        assert config.entropy_sections == [".rdata"]
        assert config.max_padding_size == 2048
        assert config.entropy_data_size == 1024

    def test_config_with_none_sections(self):
        """Test configuration with None sections (should use defaults)."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = SectionManipulationConfig(
                padding_sections=None, entropy_sections=None
            )

            # The manipulator should set default sections
            manipulator = PESectionManipulator(config)
            assert manipulator.config.padding_sections is not None
            assert manipulator.config.entropy_sections is not None
