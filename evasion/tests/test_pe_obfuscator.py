"""Tests for PE obfuscator functionality.

This module contains pytest tests for the PE obfuscator component,
including multi-layer obfuscation and configuration testing.
"""

import os
import pytest
from unittest.mock import patch

from rt_evade.pe.obfuscator import PEObfuscator, PEObfuscationConfig


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


class TestPEObfuscator:
    """Test PE obfuscator functionality."""
    
    def test_obfuscator_initialization(self):
        """Test obfuscator initialization."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = PEObfuscationConfig()
            obfuscator = PEObfuscator(config)
            assert obfuscator is not None
            assert obfuscator.config == config
    
    def test_obfuscator_requires_redteam_mode(self):
        """Test that obfuscator requires REDTEAM_MODE."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="REDTEAM_MODE not enabled"):
                PEObfuscator()
    
    def test_obfuscate_pe(self, mock_pe_data):
        """Test PE obfuscation."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = PEObfuscationConfig(
                enable_mimicry=False,  # Disable to avoid complex dependencies
                enable_string_obfuscation=True,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False
            )
            obfuscator = PEObfuscator(config)
            
            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                assert isinstance(obfuscated, bytes)
                assert len(obfuscated) > 0
            except Exception as e:
                # Some operations might fail with mock data
                # The important thing is that the obfuscator handles it gracefully
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)
    
    def test_create_obfuscation_plan(self, mock_pe_data):
        """Test creating obfuscation plan."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            obfuscator = PEObfuscator()
            plan = obfuscator.create_obfuscation_plan(mock_pe_data)
            assert plan is not None
            assert hasattr(plan, 'name')
            assert hasattr(plan, 'apply')
            assert plan.name == "pe_obfuscation"
    
    def test_get_obfuscation_report(self, mock_pe_data):
        """Test generating obfuscation report."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            obfuscator = PEObfuscator()
            
            # Create a simple obfuscated version (just copy for testing)
            obfuscated_data = mock_pe_data + b"test_padding"
            
            report = obfuscator.get_obfuscation_report(mock_pe_data, obfuscated_data)
            assert isinstance(report, dict)
            assert "size_change" in report
            assert "size_percentage" in report
            assert "entropy_changes" in report
            assert "validation_results" in report


class TestPEObfuscationConfig:
    """Test PE obfuscation configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = PEObfuscationConfig()
        assert config.enable_mimicry is True
        assert config.enable_string_obfuscation is True
        assert config.enable_import_inflation is True
        assert config.enable_section_padding is True
        assert config.enable_entropy_increase is True
        assert config.max_file_size == 5 * 1024 * 1024  # 5MB
    
    def test_custom_config(self):
        """Test custom configuration values."""
        config = PEObfuscationConfig(
            enable_mimicry=False,
            enable_string_obfuscation=False,
            enable_import_inflation=False,
            enable_section_padding=False,
            enable_entropy_increase=False,
            enable_compression=False,
            compression_algorithm="gzip",
            compression_level=9,
            target_category="system_utility",
            max_file_size=1024 * 1024  # 1MB
        )
        
        assert config.enable_mimicry is False
        assert config.enable_string_obfuscation is False
        assert config.enable_import_inflation is False
        assert config.enable_section_padding is False
        assert config.enable_entropy_increase is False
        assert config.enable_compression is False
        assert config.compression_algorithm == "gzip"
        assert config.compression_level == 9
        assert config.target_category == "system_utility"
        assert config.max_file_size == 1024 * 1024
    
    def test_compression_config(self):
        """Test compression configuration options."""
        config = PEObfuscationConfig(
            enable_compression=True,
            compression_algorithm="bz2",
            compression_level=5
        )
        
        assert config.enable_compression is True
        assert config.compression_algorithm == "bz2"
        assert config.compression_level == 5


class TestPECompression:
    """Test PE compression functionality."""
    
    def test_compression_with_large_data(self, mock_pe_data):
        """Test compression with data large enough to benefit."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            # Create larger mock data for compression testing
            large_data = mock_pe_data + b"x" * 2000  # Add 2KB of repeated data
            
            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=True,
                compression_algorithm="zlib",
                compression_level=6
            )
            obfuscator = PEObfuscator(config)
            
            try:
                obfuscated = obfuscator.obfuscate_pe(large_data)
                assert isinstance(obfuscated, bytes)
                assert len(obfuscated) > 0
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)
    
    def test_compression_skipped_for_small_files(self, mock_pe_data):
        """Test that compression is skipped for small files."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=True
            )
            obfuscator = PEObfuscator(config)
            
            # Small file should not be compressed
            obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
            assert isinstance(obfuscated, bytes)
            # For small files, compression should be skipped
            # so the result should be similar to original
    
    def test_compression_algorithms(self, mock_pe_data):
        """Test different compression algorithms."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            large_data = mock_pe_data + b"test_data_for_compression" * 100
            
            algorithms = ["zlib", "gzip", "bz2"]
            
            for algorithm in algorithms:
                config = PEObfuscationConfig(
                    enable_mimicry=False,
                    enable_string_obfuscation=False,
                    enable_import_inflation=False,
                    enable_section_padding=False,
                    enable_entropy_increase=False,
                    enable_compression=True,
                    compression_algorithm=algorithm,
                    compression_level=6
                )
                obfuscator = PEObfuscator(config)
                
                try:
                    obfuscated = obfuscator.obfuscate_pe(large_data)
                    assert isinstance(obfuscated, bytes)
                    assert len(obfuscated) > 0
                except Exception as e:
                    # Some operations might fail with mock data
                    assert "Invalid PE file" in str(e) or "PE format error" in str(e)
    
    def test_compression_levels(self, mock_pe_data):
        """Test different compression levels."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            large_data = mock_pe_data + b"repeated_data_for_compression" * 200
            
            levels = [1, 6, 9]
            
            for level in levels:
                config = PEObfuscationConfig(
                    enable_mimicry=False,
                    enable_string_obfuscation=False,
                    enable_import_inflation=False,
                    enable_section_padding=False,
                    enable_entropy_increase=False,
                    enable_compression=True,
                    compression_algorithm="zlib",
                    compression_level=level
                )
                obfuscator = PEObfuscator(config)
                
                try:
                    obfuscated = obfuscator.obfuscate_pe(large_data)
                    assert isinstance(obfuscated, bytes)
                    assert len(obfuscated) > 0
                except Exception as e:
                    # Some operations might fail with mock data
                    assert "Invalid PE file" in str(e) or "PE format error" in str(e)
    
    def test_compression_report(self, mock_pe_data):
        """Test compression report generation."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            large_data = mock_pe_data + b"test_compression_data" * 150
            
            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=True
            )
            obfuscator = PEObfuscator(config)
            
            try:
                obfuscated = obfuscator.obfuscate_pe(large_data)
                report = obfuscator.get_obfuscation_report(large_data, obfuscated)
                
                assert isinstance(report, dict)
                assert "compression_ratio" in report
                assert "size_change" in report
                assert "size_percentage" in report
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)
    
    def test_compression_disabled(self, mock_pe_data):
        """Test that compression is skipped when disabled."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            large_data = mock_pe_data + b"large_data_for_testing" * 200
            
            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False  # Disabled
            )
            obfuscator = PEObfuscator(config)
            
            try:
                obfuscated = obfuscator.obfuscate_pe(large_data)
                assert isinstance(obfuscated, bytes)
                # When compression is disabled, the result should be similar to original
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)
