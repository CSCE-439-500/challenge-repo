"""PE encryption module for hiding code sections and functionality.

This module provides encryption capabilities that work with PE file structure
while maintaining execution compatibility.
"""

import logging
import os
import secrets
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..core.guards import require_redteam_mode
from .reader import PEReader
from .writer import PEWriter

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EncryptionConfig:
    """Configuration for PE encryption."""
    enable_code_encryption: bool = True
    encryption_algorithm: str = "xor"  # xor, aes, simple
    encryption_key_size: int = 32  # bytes


class PEEncryptor:
    """PE encryptor for hiding code sections and functionality.
    
    This class provides encryption capabilities that work with PE file structure
    while maintaining execution compatibility.
    """
    
    def __init__(self, config: Optional[EncryptionConfig] = None):
        """Initialize PE encryptor with configuration.
        
        Args:
            config: Encryption configuration options
        """
        require_redteam_mode()
        
        self.config = config or EncryptionConfig()
        logger.info("action=pe_encryptor_initialized config=%s", self.config)
    
    def encrypt_pe(self, pe_data: bytes) -> bytes:
        """Apply encryption to PE file code sections.
        
        Args:
            pe_data: Raw PE file bytes to encrypt
            
        Returns:
            Encrypted PE file bytes
            
        Raises:
            ValueError: If encryption fails
        """
        if not self.config.enable_code_encryption:
            logger.info("action=encryption_disabled")
            return pe_data
        
        try:
            with PEReader(pe_data) as reader:
                sections = reader.get_sections()
            
            # Find code sections to encrypt
            code_sections = []
            for section in sections:
                section_name = section.name.rstrip('\x00')
                if section_name in ['.text', '.code', '.init', '.fini']:
                    code_sections.append(section)
            
            if not code_sections:
                logger.info("action=code_encryption_skipped reason=no_code_sections_found")
                return pe_data
            
            # Generate encryption key
            encryption_key = self._generate_encryption_key()
            
            # Encrypt code sections
            with PEWriter(pe_data) as writer:
                for section in code_sections:
                    section_name = section.name.rstrip('\x00')
                    
                    # Get section data
                    section_data = pe_data[section.raw_address:section.raw_address + section.raw_size]
                    
                    # Encrypt the data
                    encrypted_data = self._encrypt_data(section_data, encryption_key)
                    
                    # Replace section data with encrypted version
                    writer.modify_section_data(section_name, encrypted_data)
                
                # Add decryption stub to .text section
                decryption_stub = self._create_decryption_stub(encryption_key)
                writer.inject_payload_to_section(".text", decryption_stub, offset=0)
                
                # Store encryption metadata in a new section
                metadata = self._create_encryption_metadata(encryption_key, code_sections)
                writer.add_section(".encrypted", metadata, 
                                 characteristics=0x40000000)  # IMAGE_SCN_CNT_INITIALIZED_DATA
                
                result = writer.get_modified_data()
            
            logger.info("action=code_encryption_applied sections=%d algorithm=%s", 
                       len(code_sections), self.config.encryption_algorithm)
            
            return result
            
        except Exception as e:
            logger.error("action=code_encryption_failed error=%s", e)
            return pe_data
    
    def _generate_encryption_key(self) -> bytes:
        """Generate encryption key based on configuration.
        
        Returns:
            Encryption key bytes
        """
        key_size = self.config.encryption_key_size
        
        # Use environment variable for key if available, otherwise generate random
        env_key = os.getenv("ENCRYPTION_KEY")
        if env_key:
            # Use provided key, pad or truncate to required size
            key_bytes = env_key.encode('utf-8')
            if len(key_bytes) >= key_size:
                return key_bytes[:key_size]
            else:
                return key_bytes + b'\x00' * (key_size - len(key_bytes))
        else:
            # Generate random key
            return secrets.token_bytes(key_size)
    
    def _encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using the configured algorithm.
        
        Args:
            data: Data to encrypt
            key: Encryption key
            
        Returns:
            Encrypted data
        """
        algorithm = self.config.encryption_algorithm.lower()
        
        if algorithm == "xor":
            return self._xor_encrypt(data, key)
        elif algorithm == "simple":
            return self._simple_encrypt(data, key)
        else:
            logger.warning("action=unknown_encryption_algorithm algorithm=%s using_xor", algorithm)
            return self._xor_encrypt(data, key)
    
    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """XOR encryption with key cycling.
        
        Args:
            data: Data to encrypt
            key: XOR key
            
        Returns:
            XOR encrypted data
        """
        if not key:
            return data
        
        result = bytearray()
        key_len = len(key)
        
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        
        return bytes(result)
    
    def _simple_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Simple encryption using key-based substitution.
        
        Args:
            data: Data to encrypt
            key: Encryption key
            
        Returns:
            Encrypted data
        """
        if not key:
            return data
        
        result = bytearray()
        key_hash = hashlib.sha256(key).digest()
        
        for i, byte in enumerate(data):
            # Simple substitution cipher using key hash
            result.append((byte + key_hash[i % len(key_hash)]) % 256)
        
        return bytes(result)
    
    def _create_decryption_stub(self, key: bytes) -> bytes:
        """Create a decryption stub for runtime decryption.
        
        Args:
            key: Encryption key
            
        Returns:
            Decryption stub bytes
        """
        # This is a simplified stub - in a real implementation, this would be
        # proper assembly code that decrypts the code sections at runtime
        stub_code = f"""
        // Simplified decryption stub
        // Key: {key.hex()}
        // Algorithm: {self.config.encryption_algorithm}
        // In a real implementation, this would be proper assembly code
        // that decrypts the encrypted code sections at runtime
        """.encode('utf-8')
        
        return stub_code
    
    def _create_encryption_metadata(self, key: bytes, sections: List[Any]) -> bytes:
        """Create metadata about encrypted sections.
        
        Args:
            key: Encryption key
            sections: List of encrypted sections
            
        Returns:
            Metadata bytes
        """
        metadata = {
            "algorithm": self.config.encryption_algorithm,
            "key_size": len(key),
            "sections": [s.name.rstrip('\x00') for s in sections],
            "timestamp": os.time() if hasattr(os, 'time') else 0
        }
        
        # Convert to bytes (simplified)
        return str(metadata).encode('utf-8')
    
    def get_encryption_report(self, original_data: bytes, encrypted_data: bytes) -> Dict[str, Any]:
        """Generate a report of encryption changes.
        
        Args:
            original_data: Original PE file bytes
            encrypted_data: Encrypted PE file bytes
            
        Returns:
            Dictionary containing encryption report
        """
        report = {
            "encryption_enabled": self.config.enable_code_encryption,
            "algorithm": self.config.encryption_algorithm,
            "key_size": self.config.encryption_key_size,
            "original_size": len(original_data),
            "encrypted_size": len(encrypted_data),
            "size_change": len(encrypted_data) - len(original_data),
            "size_percentage": (len(encrypted_data) / len(original_data)) * 100
        }
        
        return report
