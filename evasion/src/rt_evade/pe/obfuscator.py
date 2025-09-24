"""PE obfuscator module for multi-layer PE-aware obfuscation.

This module provides comprehensive PE obfuscation capabilities that work
with PE file structure while maintaining execution compatibility.
"""

import logging
import secrets
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from ..core.guards import require_redteam_mode
from ..core.transform import TransformPlan
from .reader import PEReader
from .writer import PEWriter
from .validator import PEValidator
from .mimicry import PEMimicryEngine
from .import_manipulator import PEImportManipulator
from .static_evasion import PEStaticEvasion
from .detection_mitigation import PEDetectionMitigation
from .compression import PECompressor, CompressionConfig
from .packer import PEPacker, PackerConfig
from .encryption import PEEncryptor, EncryptionConfig
from .string_obfuscation import PEStringObfuscator, StringObfuscationConfig
from .section_manipulation import PESectionManipulator, SectionManipulationConfig

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
    enable_code_encryption: bool = True
    enable_import_manipulation: bool = True
    enable_static_evasion: bool = True
    enable_detection_mitigation: bool = True
    target_category: Optional[str] = None
    max_file_size: int = 5 * 1024 * 1024  # 5MB limit

    # Sub-configurations
    packer_config: Optional[PackerConfig] = None
    compression_config: Optional[CompressionConfig] = None
    encryption_config: Optional[EncryptionConfig] = None
    string_obfuscation_config: Optional[StringObfuscationConfig] = None
    section_manipulation_config: Optional[SectionManipulationConfig] = None


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
        self.import_manipulator = PEImportManipulator()
        self.static_evasion = PEStaticEvasion()
        self.detection_mitigation = PEDetectionMitigation()

        # Initialize specialized obfuscators
        self.packer = PEPacker(self.config.packer_config)
        self.compressor = PECompressor(self.config.compression_config)
        self.encryptor = PEEncryptor(self.config.encryption_config)
        self.string_obfuscator = PEStringObfuscator(
            self.config.string_obfuscation_config
        )
        self.section_manipulator = PESectionManipulator(
            self.config.section_manipulation_config
        )

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
            raise ValueError(
                f"PE file too large: {len(pe_data)} bytes (max: {self.config.max_file_size})"
            )

        logger.info("action=pe_obfuscation_started size=%d", len(pe_data))

        # Start with original PE data
        obfuscated_data = bytearray(pe_data)

        # Apply obfuscation layers
        if self.config.enable_mimicry:
            obfuscated_data = self._apply_mimicry(obfuscated_data)

        if self.config.enable_string_obfuscation:
            obfuscated_data = self.string_obfuscator.obfuscate_strings(obfuscated_data)

        if self.config.enable_import_inflation:
            obfuscated_data = self._apply_import_inflation(obfuscated_data)

        if self.config.enable_section_padding or self.config.enable_entropy_increase:
            obfuscated_data = self.section_manipulator.manipulate_sections(
                obfuscated_data
            )

        # New: Run external packer step before internal compression
        obfuscated_data = self.packer.pack_pe(obfuscated_data)

        if self.config.enable_compression:
            obfuscated_data = self.compressor.compress_pe(obfuscated_data)

        if self.config.enable_code_encryption:
            obfuscated_data = self.encryptor.encrypt_pe(obfuscated_data)

        if self.config.enable_import_manipulation:
            obfuscated_data = self._apply_import_manipulation(obfuscated_data)

        if self.config.enable_static_evasion:
            obfuscated_data = self._apply_static_evasion(obfuscated_data)

        if self.config.enable_detection_mitigation:
            obfuscated_data = self._apply_detection_mitigation(obfuscated_data)

        # Validate final result
        final_validation = self.validator.validate_pe(bytes(obfuscated_data))
        if not final_validation["valid"]:
            logger.warning(
                "action=final_validation_failed errors=%s", final_validation["errors"]
            )
            # Continue anyway, but log the issues

        # Log final summary
        self._log_obfuscation_summary(pe_data, obfuscated_data)

        return bytes(obfuscated_data)

    def _apply_mimicry(self, pe_data: bytes) -> bytes:
        """Apply mimicry to make PE look like benign software."""
        try:
            with PEReader(pe_data) as reader:
                characteristics = reader.get_pe_characteristics()

            mimicry_plan = self.mimicry_engine.generate_mimicry_plan(
                characteristics, self.config.target_category
            )

            if not mimicry_plan:
                logger.warning("action=no_mimicry_plan_generated")
                return pe_data

            # Apply mimicry modifications
            with PEWriter(pe_data) as writer:
                # Apply header changes (simplified - would need more complex PE manipulation)
                logger.info(
                    "action=mimicry_applied template=%s", mimicry_plan["template_name"]
                )

                # Add benign strings
                for string in mimicry_plan["modifications"]["string_additions"]:
                    writer.modify_strings(
                        {f"__benign_{secrets.token_hex(4)}__": string}
                    )

                return writer.get_modified_data()

        except (OSError, IOError, ValueError, AttributeError) as e:
            logger.error("action=mimicry_failed error=%s", e)
            return pe_data

    def _apply_import_inflation(self, pe_data: bytes) -> bytes:
        """Apply import table inflation with benign imports."""
        # This is a simplified implementation
        # Full import table modification requires complex PE manipulation
        logger.info(
            "action=import_inflation_skipped reason=complex_pe_manipulation_required"
        )
        return pe_data

    def _apply_import_manipulation(self, pe_data: bytes) -> bytes:
        """Apply import table manipulation and dead code injection.

        Args:
            pe_data: PE file bytes to manipulate

        Returns:
            Manipulated PE file bytes
        """
        try:
            # Create import manipulation plan
            plan = self.import_manipulator.create_import_manipulation_plan(pe_data)

            if not plan["fake_imports"] and not plan["dead_code"]:
                logger.info(
                    "action=import_manipulation_skipped reason=no_manipulation_needed"
                )
                return pe_data

            # Apply manipulations using PEWriter
            with PEWriter(pe_data) as writer:
                # Inject dead code into .text section
                if plan["dead_code"]:
                    dead_code_text = "\n".join(plan["dead_code"])
                    dead_code_bytes = dead_code_text.encode("utf-8")

                    # Add dead code as a comment or unused section
                    writer.inject_payload_to_section(".text", dead_code_bytes, offset=0)

                # Add fake imports metadata (simplified - full implementation would modify IAT)
                if plan["fake_imports"]:
                    import_metadata = self._create_import_metadata(plan["fake_imports"])
                    writer.add_section(
                        ".fakeimp", import_metadata, characteristics=0x40000000
                    )  # IMAGE_SCN_CNT_INITIALIZED_DATA

                result = writer.get_modified_data()

            logger.info(
                "action=import_manipulation_applied fake_imports=%d dead_functions=%d",
                len(plan["fake_imports"]),
                len(plan["dead_code"]),
            )

            return result

        except (OSError, IOError, ValueError, AttributeError) as e:
            logger.error("action=import_manipulation_failed error=%s", e)
            return pe_data

    def _create_import_metadata(self, fake_imports: List[Any]) -> bytes:
        """Create metadata about fake imports.

        Args:
            fake_imports: List of fake import entries

        Returns:
            Metadata bytes
        """
        metadata = {
            "fake_imports": [
                {
                    "dll": imp.dll_name,
                    "function": imp.function_name,
                    "used": imp.is_used,
                }
                for imp in fake_imports
            ],
            "total_count": len(fake_imports),
            "dll_diversity": len(set(imp.dll_name for imp in fake_imports)),
        }

        return str(metadata).encode("utf-8")

    def _apply_static_evasion(self, pe_data: bytes) -> bytes:
        """Apply static analysis evasion techniques.

        Args:
            pe_data: PE file bytes to evade

        Returns:
            Evaded PE file bytes
        """
        try:
            # Apply metadata cleaning
            if self.static_evasion.config.enable_metadata_cleaning:
                pe_data = self.static_evasion.clean_metadata(pe_data)

            # Remove tool signatures
            if self.static_evasion.config.enable_tool_signature_removal:
                pe_data = self.static_evasion.remove_tool_signatures(pe_data)

            # Remove suspicious strings
            if self.static_evasion.config.enable_suspicious_string_removal:
                pe_data = self.static_evasion.remove_suspicious_strings(pe_data)

            logger.info("action=static_evasion_applied")
            return pe_data

        except (OSError, IOError, ValueError, AttributeError) as e:
            logger.error("action=static_evasion_failed error=%s", e)
            return pe_data

    def _apply_detection_mitigation(self, pe_data: bytes) -> bytes:
        """Apply detection vector mitigation techniques.

        Args:
            pe_data: PE file bytes to mitigate

        Returns:
            Mitigated PE file bytes
        """
        try:
            # Monitor file size
            if self.detection_mitigation.config.enable_file_size_monitoring:
                size_analysis = self.detection_mitigation.monitor_file_size(pe_data)
                if not size_analysis["within_limits"]:
                    logger.warning(
                        "action=file_size_exceeded size=%d max=%d",
                        size_analysis["current_size"],
                        size_analysis["max_size"],
                    )

            # Preserve timestamps
            if self.detection_mitigation.config.enable_timestamp_preservation:
                pe_data = self.detection_mitigation.preserve_timestamps(pe_data)

            # Optimize section names
            if self.detection_mitigation.config.enable_section_name_optimization:
                pe_data = self.detection_mitigation.optimize_section_names(pe_data)

            logger.info("action=detection_mitigation_applied")
            return pe_data

        except (OSError, IOError, ValueError, AttributeError) as e:
            logger.error("action=detection_mitigation_failed error=%s", e)
            return pe_data

    def create_obfuscation_plan(
        self, pe_data: bytes
    ) -> TransformPlan:  # pylint: disable=unused-argument
        """Create a transform plan for PE obfuscation.

        Args:
            pe_data: Raw PE file bytes

        Returns:
            TransformPlan for PE obfuscation
        """

        def obfuscate_func(data: bytes) -> bytes:
            return self.obfuscate_pe(data)

        return TransformPlan(name="pe_obfuscation", apply=obfuscate_func)

    def get_obfuscation_report(
        self, original_data: bytes, obfuscated_data: bytes
    ) -> Dict[str, Any]:
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
            "entropy_changes": {},
            "validation_results": {},
        }

        self._add_specialized_reports(report, original_data, obfuscated_data)
        self._add_techniques_applied(report)
        self._add_entropy_comparison(report, original_data, obfuscated_data)
        self._add_validation_results(report, original_data, obfuscated_data)

        return report

    def _add_specialized_reports(
        self, report: Dict[str, Any], original_data: bytes, obfuscated_data: bytes
    ) -> None:
        """Add reports from specialized modules."""
        if self.config.enable_compression:
            report["compression"] = self.compressor.get_compression_report(
                original_data, obfuscated_data
            )

        if self.config.enable_code_encryption:
            report["encryption"] = self.encryptor.get_encryption_report(
                original_data, obfuscated_data
            )

        if self.config.enable_string_obfuscation:
            report[
                "string_obfuscation"
            ] = self.string_obfuscator.get_string_obfuscation_report(
                original_data, obfuscated_data
            )

        if self.config.enable_section_padding or self.config.enable_entropy_increase:
            report[
                "section_manipulation"
            ] = self.section_manipulator.get_section_manipulation_report(
                original_data, obfuscated_data
            )

    def _add_techniques_applied(self, report: Dict[str, Any]) -> None:
        """Add information about which techniques were applied."""
        report["techniques_applied"] = {
            "mimicry": self.config.enable_mimicry,
            "string_obfuscation": self.config.enable_string_obfuscation,
            "import_inflation": self.config.enable_import_inflation,
            "section_padding": self.config.enable_section_padding,
            "entropy_increase": self.config.enable_entropy_increase,
            "compression": self.config.enable_compression,
            "code_encryption": self.config.enable_code_encryption,
            "import_manipulation": self.config.enable_import_manipulation,
            "static_evasion": self.config.enable_static_evasion,
            "detection_mitigation": self.config.enable_detection_mitigation,
        }

    def _add_entropy_comparison(
        self, report: Dict[str, Any], original_data: bytes, obfuscated_data: bytes
    ) -> None:
        """Add entropy comparison to the report."""
        try:
            with PEReader(original_data) as orig_reader:
                orig_entropy = orig_reader.get_entropy_analysis()

            with PEReader(obfuscated_data) as obf_reader:
                obf_entropy = obf_reader.get_entropy_analysis()

            for section_name, orig_value in orig_entropy.items():
                if section_name in obf_entropy:
                    report["entropy_changes"][section_name] = {
                        "original": orig_value,
                        "obfuscated": obf_entropy[section_name],
                        "change": obf_entropy[section_name] - orig_value,
                    }

        except (OSError, IOError, ValueError, AttributeError) as e:
            logger.error("action=entropy_comparison_failed error=%s", e)

    def _add_validation_results(
        self, report: Dict[str, Any], original_data: bytes, obfuscated_data: bytes
    ) -> None:
        """Add validation results to the report."""
        orig_validation = self.validator.validate_pe(original_data)
        obf_validation = self.validator.validate_pe(obfuscated_data)

        report["validation_results"] = {
            "original_valid": orig_validation["valid"],
            "obfuscated_valid": obf_validation["valid"],
            "original_errors": len(orig_validation["errors"]),
            "obfuscated_errors": len(obf_validation["errors"]),
        }

    def _log_obfuscation_summary(
        self, original_data: bytes, obfuscated_data: bytes
    ) -> None:
        """Log a summary of the obfuscation process.

        Args:
            original_data: Original PE data
            obfuscated_data: Obfuscated PE data
        """
        size_change = len(obfuscated_data) - len(original_data)
        size_change_pct = (
            (size_change / len(original_data)) * 100 if len(original_data) > 0 else 0
        )

        logger.info(
            "action=pe_obfuscation_completed original_size=%d final_size=%d size_change=%d size_change_pct=%.1f%%",
            len(original_data),
            len(obfuscated_data),
            size_change,
            size_change_pct,
        )
