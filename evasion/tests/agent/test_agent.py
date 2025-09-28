"""Tests for agent functionality.

This module contains pytest tests for the ObfuscationAgent component,
including Agno framework integration.
"""

import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock

from obfuscation_agent.agent import ObfuscationAgent


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


class TestObfuscationAgent:
    """Test class for ObfuscationAgent."""

    def test_agent_initialization(self):
        """Test agent initialization."""
        agent = ObfuscationAgent()

        assert agent.name == "BinaryObfuscationAgent"
        assert "obfuscation techniques" in agent.description
        assert agent.current_binary_path is None
        assert agent.obfuscation_history == []
        assert agent.attempt_count == 0

    def test_agent_tool_methods_exist(self):
        """Test that agent has required tool methods."""
        agent = ObfuscationAgent()

        # Check that tool methods exist
        assert hasattr(agent, "add_junk_sections")
        assert hasattr(agent, "rearrange_sections")
        assert hasattr(agent, "change_section_names")
        assert hasattr(agent, "change_timestamp")
        assert hasattr(agent, "test_evasion")

    @patch("obfuscation_agent.agent.add_junk_sections")
    def test_add_junk_sections_tool(self, mock_add_junk_sections, temp_pe_file):
        """Test add_junk_sections tool method."""
        agent = ObfuscationAgent()
        mock_add_junk_sections.return_value = "modified_file.exe"

        result = agent.add_junk_sections(temp_pe_file)

        assert result == "modified_file.exe"
        mock_add_junk_sections.assert_called_once_with(temp_pe_file)

    @patch("obfuscation_agent.agent.rearrange_sections")
    def test_rearrange_sections_tool(self, mock_rearrange_sections, temp_pe_file):
        """Test rearrange_sections tool method."""
        agent = ObfuscationAgent()
        mock_rearrange_sections.return_value = "modified_file.exe"

        result = agent.rearrange_sections(temp_pe_file)

        assert result == "modified_file.exe"
        mock_rearrange_sections.assert_called_once_with(temp_pe_file)

    @patch("obfuscation_agent.agent.change_section_names")
    def test_change_section_names_tool(self, mock_change_section_names, temp_pe_file):
        """Test change_section_names tool method."""
        agent = ObfuscationAgent()
        mock_change_section_names.return_value = "modified_file.exe"

        result = agent.change_section_names(temp_pe_file)

        assert result == "modified_file.exe"
        mock_change_section_names.assert_called_once_with(temp_pe_file)

    @patch("obfuscation_agent.agent.change_timestamp")
    def test_change_timestamp_tool(self, mock_change_timestamp, temp_pe_file):
        """Test change_timestamp tool method."""
        agent = ObfuscationAgent()
        mock_change_timestamp.return_value = "modified_file.exe"

        result = agent.change_timestamp(temp_pe_file)

        assert result == "modified_file.exe"
        mock_change_timestamp.assert_called_once_with(temp_pe_file)

    @patch("obfuscation_agent.agent.evasion_model")
    def test_test_evasion_tool(self, mock_evasion_model, temp_pe_file):
        """Test test_evasion tool method."""
        agent = ObfuscationAgent()
        mock_evasion_model.return_value = 0  # Evaded

        result = agent.test_evasion(temp_pe_file)

        assert result == 0
        mock_evasion_model.assert_called_once_with(temp_pe_file)

    def test_get_agent_status(self):
        """Test get_agent_status method."""
        agent = ObfuscationAgent()
        agent.current_binary_path = "test.exe"
        agent.attempt_count = 5
        agent.obfuscation_history = ["add_junk_sections", "change_timestamp"]

        status = agent.get_agent_status()

        assert status["current_binary_path"] == "test.exe"
        assert status["attempt_count"] == 5
        assert status["obfuscation_history"] == [
            "add_junk_sections",
            "change_timestamp",
        ]
        assert status["agent_name"] == "BinaryObfuscationAgent"
        assert "obfuscation techniques" in status["agent_description"]

    @patch("obfuscation_agent.agent.validate_pe_file")
    @patch("obfuscation_agent.agent.save_checkpoint")
    @patch("obfuscation_agent.agent.add_junk_sections")
    @patch("obfuscation_agent.agent.rearrange_sections")
    @patch("obfuscation_agent.agent.change_section_names")
    @patch("obfuscation_agent.agent.change_timestamp")
    @patch("obfuscation_agent.agent.evasion_model")
    def test_run_obfuscation_loop_success_first_attempt(
        self,
        mock_evasion_model,
        mock_change_timestamp,
        mock_change_section_names,
        mock_rearrange_sections,
        mock_add_junk_sections,
        mock_save_checkpoint,
        mock_validate_pe_file,
        temp_pe_file,
    ):
        """Test successful obfuscation loop on first attempt."""
        agent = ObfuscationAgent()

        # Mock successful validation and evasion
        mock_validate_pe_file.return_value = True
        mock_save_checkpoint.return_value = "checkpoint.exe"
        mock_evasion_model.return_value = 0  # Evaded

        # Mock all obfuscation tools to return the same result
        mock_add_junk_sections.return_value = "obfuscated.exe"
        mock_rearrange_sections.return_value = "obfuscated.exe"
        mock_change_section_names.return_value = "obfuscated.exe"
        mock_change_timestamp.return_value = "obfuscated.exe"

        final_binary, evaded, history = agent.run_obfuscation_loop(
            temp_pe_file, max_attempts=5
        )

        assert evaded is True
        assert final_binary == "obfuscated.exe"
        assert len(history) == 1  # Should have applied one obfuscation technique
        assert agent.attempt_count == 1

    @patch("obfuscation_agent.agent.validate_pe_file")
    @patch("obfuscation_agent.agent.save_checkpoint")
    @patch("obfuscation_agent.agent.add_junk_sections")
    @patch("obfuscation_agent.agent.evasion_model")
    def test_run_obfuscation_loop_max_attempts_reached(
        self,
        mock_evasion_model,
        mock_add_junk_sections,
        mock_save_checkpoint,
        mock_validate_pe_file,
        temp_pe_file,
    ):
        """Test obfuscation loop when max attempts are reached."""
        agent = ObfuscationAgent()

        # Mock validation and evasion (always detected)
        mock_validate_pe_file.return_value = True
        mock_save_checkpoint.return_value = "checkpoint.exe"
        mock_add_junk_sections.return_value = "obfuscated.exe"
        mock_evasion_model.return_value = 1  # Always detected

        final_binary, evaded, history = agent.run_obfuscation_loop(
            temp_pe_file, max_attempts=3
        )

        assert evaded is False
        assert len(history) == 3
        assert agent.attempt_count == 3

    def test_run_obfuscation_loop_invalid_pe_file(self, temp_pe_file):
        """Test obfuscation loop with invalid PE file."""
        agent = ObfuscationAgent()

        with patch("obfuscation_agent.agent.validate_pe_file") as mock_validate:
            mock_validate.return_value = False

            final_binary, evaded, history = agent.run_obfuscation_loop(
                temp_pe_file, max_attempts=5
            )

            assert evaded is False
            assert final_binary == temp_pe_file
            assert history == []

    def test_run_obfuscation_loop_error_handling(self, temp_pe_file):
        """Test error handling in obfuscation loop."""
        agent = ObfuscationAgent()

        with patch("obfuscation_agent.agent.validate_pe_file") as mock_validate:
            mock_validate.side_effect = Exception("Validation error")

            final_binary, evaded, history = agent.run_obfuscation_loop(
                temp_pe_file, max_attempts=5
            )

            assert evaded is False
            assert final_binary == temp_pe_file
            assert history == []

    @patch("obfuscation_agent.agent.validate_pe_file")
    @patch("obfuscation_agent.agent.save_checkpoint")
    @patch("obfuscation_agent.agent.add_junk_sections")
    @patch("obfuscation_agent.agent.rearrange_sections")
    @patch("obfuscation_agent.agent.change_section_names")
    @patch("obfuscation_agent.agent.change_timestamp")
    @patch("obfuscation_agent.agent.revert_to_checkpoint")
    def test_run_obfuscation_loop_revert_on_error(
        self,
        mock_revert,
        mock_change_timestamp,
        mock_change_section_names,
        mock_rearrange_sections,
        mock_add_junk_sections,
        mock_save_checkpoint,
        mock_validate_pe_file,
        temp_pe_file,
    ):
        """Test that agent reverts to checkpoint on error."""
        agent = ObfuscationAgent()

        # Mock successful validation and checkpoint
        mock_validate_pe_file.return_value = True
        mock_save_checkpoint.return_value = "checkpoint.exe"
        mock_revert.return_value = True

        # Mock all obfuscation tools to raise error
        mock_add_junk_sections.side_effect = Exception("Obfuscation error")
        mock_rearrange_sections.side_effect = Exception("Obfuscation error")
        mock_change_section_names.side_effect = Exception("Obfuscation error")
        mock_change_timestamp.side_effect = Exception("Obfuscation error")

        final_binary, evaded, history = agent.run_obfuscation_loop(
            temp_pe_file, max_attempts=5
        )

        # Should have attempted obfuscation and reverted
        mock_revert.assert_called()
        assert evaded is False
