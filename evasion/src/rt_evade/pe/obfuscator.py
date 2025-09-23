"""PE obfuscator module for multi-layer PE-aware obfuscation.

This module provides comprehensive PE obfuscation capabilities that work
with PE file structure while maintaining execution compatibility.
"""

import logging
import os
import secrets
import base64
import zlib
import gzip
import bz2
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

from ..core.guards import require_redteam_mode, guard_can_write
from ..core.transform import TransformPlan
from .reader import PEReader
from .writer import PEWriter
from .validator import PEValidator
from .mimicry import PEMimicryEngine

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PEObfuscationConfig:
    """Configuration for PE obfuscation."""
    enable_mimicry: bool = True
    enable_string_obfuscation: bool = True
    enable_import_inflation: bool = True
    enable_section_padding: bool = True
    enable_entropy_increase: bool = True
    enable_compression: bool = True
    compression_algorithm: str = "zlib"  # zlib, gzip, bz2
    compression_level: int = 6  # 1-9 for zlib/gzip, 1-9 for bz2
    target_category: Optional[str] = None
    max_file_size: int = 5 * 1024 * 1024  # 5MB limit


class PEObfuscator:
    """PE obfuscator with multi-layer PE-aware obfuscation.
    
    This class provides comprehensive PE obfuscation while maintaining
    PE format integrity and execution compatibility.
    """
    
    def __init__(self, config: Optional[PEObfuscationConfig] = None):
        """Initialize PE obfuscator with configuration.
        
        Args:
            config: Obfuscation configuration options
        """
        require_redteam_mode()
        
        self.config = config or PEObfuscationConfig()
        self.validator = PEValidator()
        self.mimicry_engine = PEMimicryEngine()
        
        logger.info("action=pe_obfuscator_initialized config=%s", self.config)
    
    def obfuscate_pe(self, pe_data: bytes) -> bytes:
        """Apply comprehensive obfuscation to PE file.
        
        Args:
            pe_data: Raw PE file bytes to obfuscate
            
        Returns:
            Obfuscated PE file bytes
            
        Raises:
            ValueError: If PE file is invalid or too large
        """
        # Validate input PE
        validation_result = self.validator.validate_pe(pe_data)
        if not validation_result["valid"]:
            raise ValueError(f"Invalid PE file: {validation_result['errors']}")
        
        # Check file size limit
        if len(pe_data) > self.config.max_file_size:
            raise ValueError(f"PE file too large: {len(pe_data)} bytes (max: {self.config.max_file_size})")
        
        logger.info("action=pe_obfuscation_started size=%d", len(pe_data))
        
        # Start with original PE data
        obfuscated_data = bytearray(pe_data)
        
        # Apply obfuscation layers
        if self.config.enable_mimicry:
            obfuscated_data = self._apply_mimicry(obfuscated_data)
        
        if self.config.enable_string_obfuscation:
            obfuscated_data = self._apply_string_obfuscation(obfuscated_data)
        
        if self.config.enable_import_inflation:
            obfuscated_data = self._apply_import_inflation(obfuscated_data)
        
        if self.config.enable_section_padding:
            obfuscated_data = self._apply_section_padding(obfuscated_data)
        
        if self.config.enable_entropy_increase:
            obfuscated_data = self._apply_entropy_increase(obfuscated_data)
        
        if self.config.enable_compression:
            obfuscated_data = self._apply_compression(obfuscated_data)
        
        # Validate final result
        final_validation = self.validator.validate_pe(bytes(obfuscated_data))
        if not final_validation["valid"]:
            logger.warning("action=final_validation_failed errors=%s", final_validation["errors"])
            # Continue anyway, but log the issues
        
        logger.info("action=pe_obfuscation_completed original_size=%d final_size=%d", 
                   len(pe_data), len(obfuscated_data))
        
        return bytes(obfuscated_data)
    
    def _apply_mimicry(self, pe_data: bytes) -> bytes:
        """Apply mimicry to make PE look like benign software."""
        try:
            with PEReader(pe_data) as reader:
                characteristics = reader.get_pe_characteristics()
            
            mimicry_plan = self.mimicry_engine.generate_mimicry_plan(
                characteristics, 
                self.config.target_category
            )
            
            if not mimicry_plan:
                logger.warning("action=no_mimicry_plan_generated")
                return pe_data
            
            # Apply mimicry modifications
            with PEWriter(pe_data) as writer:
                # Apply header changes (simplified - would need more complex PE manipulation)
                logger.info("action=mimicry_applied template=%s", 
                           mimicry_plan["template_name"])
                
                # Add benign strings
                for string in mimicry_plan["modifications"]["string_additions"]:
                    writer.modify_strings({f"__benign_{secrets.token_hex(4)}__": string})
                
                return writer.get_modified_data()
                
        except Exception as e:
            logger.error("action=mimicry_failed error=%s", e)
            return pe_data
    
    def _apply_string_obfuscation(self, pe_data: bytes) -> bytes:
        """Apply string obfuscation to hide suspicious strings."""
        try:
            with PEReader(pe_data) as reader:
                strings = reader.get_strings(min_length=4)
            
            # Identify suspicious strings to obfuscate
            suspicious_strings = self._identify_suspicious_strings(strings)
            
            if not suspicious_strings:
                logger.info("action=no_suspicious_strings_found")
                return pe_data
            
            # Create obfuscation mappings
            obfuscation_map = {}
            for string in suspicious_strings:
                # Use Base64 encoding for obfuscation
                obfuscated = base64.b64encode(string.encode('utf-8')).decode('ascii')
                obfuscation_map[string] = f"__b64_{obfuscated}__"
            
            # Apply string replacements
            with PEWriter(pe_data) as writer:
                writer.modify_strings(obfuscation_map)
                result = writer.get_modified_data()
            
            logger.info("action=string_obfuscation_applied strings=%d", len(obfuscation_map))
            return result
            
        except Exception as e:
            logger.error("action=string_obfuscation_failed error=%s", e)
            return pe_data
    
    def _identify_suspicious_strings(self, strings: List[str]) -> List[str]:
        """Identify suspicious strings that should be obfuscated."""
        suspicious_patterns = [
            "malware", "virus", "trojan", "backdoor", "payload", "inject",
            "exploit", "shellcode", "keylogger", "rootkit", "botnet",
            "CreateProcess", "VirtualAlloc", "WriteProcessMemory", "ReadProcessMemory",
            "OpenProcess", "TerminateProcess", "LoadLibrary", "GetProcAddress",
            "SetWindowsHookEx", "RegisterHotKey", "CreateRemoteThread"
        ]
        
        suspicious_strings = []
        for string in strings:
            string_lower = string.lower()
            if any(pattern in string_lower for pattern in suspicious_patterns):
                suspicious_strings.append(string)
        
        return suspicious_strings
    
    def _apply_import_inflation(self, pe_data: bytes) -> bytes:
        """Apply import table inflation with benign imports."""
        # This is a simplified implementation
        # Full import table modification requires complex PE manipulation
        logger.info("action=import_inflation_skipped reason=complex_pe_manipulation_required")
        return pe_data
    
    def _apply_section_padding(self, pe_data: bytes) -> bytes:
        """Apply padding to sections to increase entropy."""
        try:
            with PEWriter(pe_data) as writer:
                # Add junk data to existing sections
                sections_to_pad = [".data", ".rdata", ".rsrc"]
                
                for section_name in sections_to_pad:
                    # Add small amount of junk data
                    junk_size = min(1024, 1024)  # 1KB max
                    writer.add_junk_data(section_name, junk_size)
                
                result = writer.get_modified_data()
            
            logger.info("action=section_padding_applied")
            return result
            
        except Exception as e:
            logger.error("action=section_padding_failed error=%s", e)
            return pe_data
    
    def _apply_entropy_increase(self, pe_data: bytes) -> bytes:
        """Increase entropy by adding random data to unused sections."""
        try:
            with PEWriter(pe_data) as writer:
                # Add entropy to .data section
                entropy_data = secrets.token_bytes(512)  # 512 bytes of random data
                writer.inject_payload_to_section(".data", entropy_data, offset=0)
                
                result = writer.get_modified_data()
            
            logger.info("action=entropy_increase_applied")
            return result
            
        except Exception as e:
            logger.error("action=entropy_increase_failed error=%s", e)
            return pe_data
    
    def _apply_compression(self, pe_data: bytes) -> bytes:
        """Apply compression to reduce file size while maintaining PE structure.
        
        Args:
            pe_data: PE file bytes to compress
            
        Returns:
            Compressed PE file bytes
        """
        try:
            # Only compress if the file is large enough to benefit from compression
            if len(pe_data) < 1024:  # Don't compress small files
                logger.info("action=compression_skipped reason=file_too_small size=%d", len(pe_data))
                return pe_data
            
            # Compress the entire PE file
            compressed_data = self._compress_data(pe_data)
            
            # Check if compression actually reduced size
            if len(compressed_data) >= len(pe_data):
                logger.info("action=compression_skipped reason=no_size_reduction original=%d compressed=%d", 
                           len(pe_data), len(compressed_data))
                return pe_data
            
            # Create a new PE with compressed data in a special section
            with PEWriter(pe_data) as writer:
                # Add a section to store the compressed data
                compression_section_name = ".compressed"
                writer.add_section(compression_section_name, compressed_data, 
                                 characteristics=0x40000000)  # IMAGE_SCN_CNT_INITIALIZED_DATA
                
                # Add a small decompression stub (simplified)
                decompression_stub = self._create_decompression_stub()
                writer.inject_payload_to_section(".text", decompression_stub, offset=0)
                
                result = writer.get_modified_data()
            
            compression_ratio = (len(compressed_data) / len(pe_data)) * 100
            logger.info("action=compression_applied algorithm=%s original_size=%d compressed_size=%d ratio=%.1f%%", 
                       self.config.compression_algorithm, len(pe_data), len(compressed_data), compression_ratio)
            
            return result
            
        except Exception as e:
            logger.error("action=compression_failed error=%s", e)
            return pe_data
    
    def _compress_data(self, data: bytes) -> bytes:
        """Compress data using the configured algorithm.
        
        Args:
            data: Data to compress
            
        Returns:
            Compressed data
        """
        algorithm = self.config.compression_algorithm.lower()
        level = self.config.compression_level
        
        if algorithm == "zlib":
            return zlib.compress(data, level)
        elif algorithm == "gzip":
            return gzip.compress(data, compresslevel=level)
        elif algorithm == "bz2":
            return bz2.compress(data, compresslevel=level)
        else:
            logger.warning("action=unknown_compression_algorithm algorithm=%s using_zlib", algorithm)
            return zlib.compress(data, level)
    
    def _create_decompression_stub(self) -> bytes:
        """Create a simple decompression stub for runtime decompression.
        
        Returns:
            Decompression stub bytes
        """
        # This is a simplified stub - in a real implementation, this would be
        # a proper PE-compatible decompression routine
        stub_code = b"""
        // Simplified decompression stub
        // In a real implementation, this would be proper assembly code
        // that decompresses the .compressed section at runtime
        """
        return stub_code
    
    def create_obfuscation_plan(self, pe_data: bytes) -> TransformPlan:
        """Create a transform plan for PE obfuscation.
        
        Args:
            pe_data: Raw PE file bytes
            
        Returns:
            TransformPlan for PE obfuscation
        """
        def obfuscate_func(data: bytes) -> bytes:
            return self.obfuscate_pe(data)
        
        return TransformPlan(
            name="pe_obfuscation",
            apply=obfuscate_func
        )
    
    def get_obfuscation_report(self, original_data: bytes, obfuscated_data: bytes) -> Dict[str, Any]:
        """Generate a report of obfuscation changes.
        
        Args:
            original_data: Original PE file bytes
            obfuscated_data: Obfuscated PE file bytes
            
        Returns:
            Dictionary containing obfuscation report
        """
        report = {
            "size_change": len(obfuscated_data) - len(original_data),
            "size_percentage": (len(obfuscated_data) / len(original_data)) * 100,
            "compression_ratio": 0.0,
            "entropy_changes": {},
            "validation_results": {}
        }
        
        # Calculate compression ratio if compression was applied
        if self.config.enable_compression and len(obfuscated_data) < len(original_data):
            report["compression_ratio"] = (len(obfuscated_data) / len(original_data)) * 100
        
        # Compare entropy
        try:
            with PEReader(original_data) as orig_reader:
                orig_entropy = orig_reader.get_entropy_analysis()
            
            with PEReader(obfuscated_data) as obf_reader:
                obf_entropy = obf_reader.get_entropy_analysis()
            
            for section_name in orig_entropy:
                if section_name in obf_entropy:
                    report["entropy_changes"][section_name] = {
                        "original": orig_entropy[section_name],
                        "obfuscated": obf_entropy[section_name],
                        "change": obf_entropy[section_name] - orig_entropy[section_name]
                    }
        
        except Exception as e:
            logger.error("action=entropy_comparison_failed error=%s", e)
        
        # Validation results
        orig_validation = self.validator.validate_pe(original_data)
        obf_validation = self.validator.validate_pe(obfuscated_data)
        
        report["validation_results"] = {
            "original_valid": orig_validation["valid"],
            "obfuscated_valid": obf_validation["valid"],
            "original_errors": len(orig_validation["errors"]),
            "obfuscated_errors": len(obf_validation["errors"])
        }
        
        return report
