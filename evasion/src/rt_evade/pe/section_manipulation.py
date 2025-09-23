"""PE section manipulation module for padding and entropy modification.

This module provides section manipulation capabilities that work with PE file structure
while maintaining execution compatibility.
"""

import logging
import secrets
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..core.guards import require_redteam_mode
from .writer import PEWriter

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SectionManipulationConfig:
    """Configuration for PE section manipulation."""
    enable_section_padding: bool = True
    enable_entropy_increase: bool = True
    padding_sections: List[str] = None  # Sections to pad
    entropy_sections: List[str] = None  # Sections to add entropy to
    max_padding_size: int = 1024  # Maximum padding per section
    entropy_data_size: int = 512  # Size of entropy data to add


class PESectionManipulator:
    """PE section manipulator for padding and entropy modification.
    
    This class provides section manipulation capabilities that work with PE file structure
    while maintaining execution compatibility.
    """
    
    def __init__(self, config: Optional[SectionManipulationConfig] = None):
        """Initialize PE section manipulator with configuration.
        
        Args:
            config: Section manipulation configuration options
        """
        require_redteam_mode()
        
        self.config = config or SectionManipulationConfig()
        
        # Set default sections if not provided
        if self.config.padding_sections is None or self.config.entropy_sections is None:
            # Create a new config with defaults
            self.config = SectionManipulationConfig(
                enable_section_padding=self.config.enable_section_padding,
                enable_entropy_increase=self.config.enable_entropy_increase,
                padding_sections=self.config.padding_sections or [".data", ".rdata", ".rsrc"],
                entropy_sections=self.config.entropy_sections or [".data"],
                max_padding_size=self.config.max_padding_size,
                entropy_data_size=self.config.entropy_data_size
            )
        
        logger.info("action=pe_section_manipulator_initialized config=%s", self.config)
    
    def manipulate_sections(self, pe_data: bytes) -> bytes:
        """Apply section manipulation to PE file.
        
        Args:
            pe_data: Raw PE file bytes to manipulate
            
        Returns:
            Section manipulated PE file bytes
            
        Raises:
            ValueError: If section manipulation fails
        """
        try:
            with PEWriter(pe_data) as writer:
                # Apply section padding
                if self.config.enable_section_padding:
                    self._apply_section_padding(writer)
                
                # Apply entropy increase
                if self.config.enable_entropy_increase:
                    self._apply_entropy_increase(writer)
                
                result = writer.get_modified_data()
            
            logger.info("action=section_manipulation_applied padding=%s entropy=%s", 
                       self.config.enable_section_padding, self.config.enable_entropy_increase)
            
            return result
            
        except Exception as e:
            logger.error("action=section_manipulation_failed error=%s", e)
            return pe_data
    
    def _apply_section_padding(self, writer: PEWriter) -> None:
        """Apply padding to sections to increase entropy.
        
        Args:
            writer: PEWriter instance for modifications
        """
        for section_name in self.config.padding_sections:
            try:
                # Add small amount of junk data
                junk_size = min(self.config.max_padding_size, 1024)  # 1KB max
                writer.add_junk_data(section_name, junk_size)
                logger.debug("action=section_padding_applied section=%s size=%d", 
                           section_name, junk_size)
            except Exception as e:
                logger.warning("action=section_padding_failed section=%s error=%s", 
                             section_name, e)
    
    def _apply_entropy_increase(self, writer: PEWriter) -> None:
        """Increase entropy by adding random data to sections.
        
        Args:
            writer: PEWriter instance for modifications
        """
        for section_name in self.config.entropy_sections:
            try:
                # Add entropy data
                entropy_data = secrets.token_bytes(self.config.entropy_data_size)
                writer.inject_payload_to_section(section_name, entropy_data, offset=0)
                logger.debug("action=entropy_increase_applied section=%s size=%d", 
                           section_name, len(entropy_data))
            except Exception as e:
                logger.warning("action=entropy_increase_failed section=%s error=%s", 
                             section_name, e)
    
    def get_section_manipulation_report(self, original_data: bytes, manipulated_data: bytes) -> Dict[str, Any]:
        """Generate a report of section manipulation changes.
        
        Args:
            original_data: Original PE file bytes
            manipulated_data: Section manipulated PE file bytes
            
        Returns:
            Dictionary containing section manipulation report
        """
        report = {
            "section_padding_enabled": self.config.enable_section_padding,
            "entropy_increase_enabled": self.config.enable_entropy_increase,
            "padding_sections": self.config.padding_sections,
            "entropy_sections": self.config.entropy_sections,
            "max_padding_size": self.config.max_padding_size,
            "entropy_data_size": self.config.entropy_data_size,
            "original_size": len(original_data),
            "manipulated_size": len(manipulated_data),
            "size_change": len(manipulated_data) - len(original_data),
            "size_percentage": (len(manipulated_data) / len(original_data)) * 100
        }
        
        return report
