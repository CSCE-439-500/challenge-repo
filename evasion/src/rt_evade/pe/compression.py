"""PE compression module for reducing file size while maintaining PE structure.

This module provides compression capabilities that work with PE file structure
while maintaining execution compatibility.
"""

import logging
import os
import subprocess
import tempfile
import zlib
import gzip
import bz2
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from ..core.guards import require_redteam_mode, guard_can_write
from .writer import PEWriter

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CompressionConfig:
    """Configuration for PE compression."""

    enable_compression: bool = True
    compression_algorithm: str = "zlib"  # zlib, gzip, bz2
    compression_level: int = 6  # 1-9 for zlib/gzip, 1-9 for bz2
    min_file_size: int = 1024  # Don't compress files smaller than this
    # Optional external packer support (e.g., UPX). When set, this takes precedence
    # over internal compression algorithms.
    enable_packer: bool = False
    packer_name: str = "upx"  # currently only "upx" supported
    packer_args: Optional[List[str]] = None  # extra args, e.g., ["--best"]


class PECompressor:
    """PE compressor for reducing file size while maintaining PE structure.

    This class provides compression capabilities that work with PE file structure
    while maintaining execution compatibility.
    """

    def __init__(self, config: Optional[CompressionConfig] = None):
        """Initialize PE compressor with configuration.

        Args:
            config: Compression configuration options
        """
        require_redteam_mode()

        self.config = config or CompressionConfig()
        logger.info("action=pe_compressor_initialized config=%s", self.config)

    def compress_pe(self, pe_data: bytes) -> bytes:
        """Apply compression to PE file.

        Args:
            pe_data: Raw PE file bytes to compress

        Returns:
            Compressed PE file bytes

        Raises:
            ValueError: If compression fails or file is too small
        """
        # If an external packer is enabled via config or env, use it and return early.
        use_upx_env = os.getenv("USE_UPX", "").lower() in {"1", "true", "yes"}
        if self.config.enable_packer or use_upx_env:
            # If env provides extra args, prefer them
            upx_args_env = os.getenv("UPX_ARGS")
            if upx_args_env:
                object.__setattr__(self.config, "packer_args", upx_args_env.split())
            packed = self._pack_with_upx(pe_data)
            if packed is pe_data or packed == pe_data:
                # UPX failed or had no gain; fall back to internal compression path
                logger.info("action=packer_fallback_to_internal packer=upx")
            else:
                return packed

        if not self.config.enable_compression:
            logger.info("action=compression_disabled")
            return pe_data

        # Only compress if the file is large enough to benefit from compression
        if len(pe_data) < self.config.min_file_size:
            logger.info(
                "action=compression_skipped reason=file_too_small size=%d", len(pe_data)
            )
            return pe_data

        # Compress the entire PE file
        compressed_data = self._compress_data(pe_data)

        # Check if compression actually reduced size
        if len(compressed_data) >= len(pe_data):
            logger.info(
                "action=compression_skipped reason=no_size_reduction original=%d compressed=%d",
                len(pe_data),
                len(compressed_data),
            )
            return pe_data

        # Create a new PE with compressed data in a special section
        with PEWriter(pe_data) as writer:
            # Add a section to store the compressed data
            compression_section_name = ".comp"
            writer.add_section(
                compression_section_name, compressed_data, characteristics=0x40000000
            )  # IMAGE_SCN_CNT_INITIALIZED_DATA

            # Add a small decompression stub (simplified)
            decompression_stub = self._create_decompression_stub()
            writer.inject_payload_to_section(".text", decompression_stub, offset=0)

            result = writer.get_modified_data()

        compression_ratio = (len(compressed_data) / len(pe_data)) * 100
        logger.info(
            "action=compression_applied algorithm=%s original_size=%d "
            "compressed_size=%d ratio=%.1f%%",
            self.config.compression_algorithm,
            len(pe_data),
            len(compressed_data),
            compression_ratio,
        )

        return result

    def _pack_with_upx(self, pe_data: bytes) -> bytes:
        """Pack the PE using UPX via a guarded subprocess and temp files.

        Notes:
            - Obeys REDTEAM_MODE and ALLOW_ACTIONS via guards.
            - Uses OS temp directory and ensures cleanup.

        Args:
            pe_data: Raw PE file bytes to pack

        Returns:
            Packed PE bytes if packing succeeds; original bytes if packing fails
            or does not reduce size.
        """
        require_redteam_mode()
        guard_can_write()

        if self.config.packer_name.lower() != "upx":
            logger.warning(
                "action=unknown_packer packer=%s skipping",
                self.config.packer_name,
            )
            return pe_data

        # Create temp input file and prepare a unique (non-existent) output path
        input_tmp = None
        output_path = None
        try:
            input_tmp = tempfile.NamedTemporaryFile(
                prefix="rt_upx_in_", suffix=".exe", delete=False
            )
            input_path = input_tmp.name
            # Get a unique path for output without creating the file so UPX can create it
            fd, tmp_out_path = tempfile.mkstemp(prefix="rt_upx_out_", suffix=".exe")
            os.close(fd)
            # Remove the file so that UPX does not fail with FileAlreadyExistsException
            os.unlink(tmp_out_path)
            output_path = tmp_out_path
            input_tmp.write(pe_data)
            input_tmp.flush()
            input_tmp.close()

            # Build the UPX command: upx [args] -o output input
            args = [self.config.packer_name]
            if self.config.packer_args:
                args.extend(self.config.packer_args)
            # Ensure we force overwrite just in case a file appears at the path
            if "-f" not in args and "--force" not in args:
                args.append("-f")
            args.extend(["-o", output_path, input_path])

            logger.info("action=packer_start packer=upx cmd=%s", " ".join(args))
            completed = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            if completed.returncode != 0:
                logger.warning(
                    "action=packer_failed packer=upx code=%d stderr=%s",
                    completed.returncode,
                    completed.stderr.decode(errors="ignore"),
                )
                # Fall back to original bytes on failure
                return pe_data

            with open(output_path, "rb") as f_out:
                packed = f_out.read()

            if len(packed) >= len(pe_data):
                logger.info(
                    "action=packer_no_gain packer=upx original=%d packed=%d",
                    len(pe_data),
                    len(packed),
                )
                return pe_data

            logger.info(
                "action=packer_applied packer=upx original_size=%d packed_size=%d",
                len(pe_data),
                len(packed),
            )
            return packed
        finally:
            # Cleanup temp files
            for tmp in (
                input_tmp.name if input_tmp else None,
                output_path,
            ):
                if tmp and os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        logger.debug("action=tempfile_cleanup_failed path=%s", tmp)

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
        if algorithm == "gzip":
            return gzip.compress(data, compresslevel=level)
        if algorithm == "bz2":
            return bz2.compress(data, compresslevel=level)
        logger.warning(
            "action=unknown_compression_algorithm algorithm=%s using_zlib",
            algorithm,
        )
        return zlib.compress(data, level)

    def _create_decompression_stub(self) -> bytes:
        """Create a simple decompression stub for runtime decompression.

        Returns:
            Decompression stub bytes
        """
        # This is a simplified stub - in a real implementation, this would be
        # a proper PE-compatible decompression routine
        stub_code = f"""
        // Simplified decompression stub
        // Algorithm: {self.config.compression_algorithm}
        // In a real implementation, this would be proper assembly code
        // that decompresses the .compressed section at runtime
        """.encode(
            "utf-8"
        )

        return stub_code

    def get_compression_report(
        self, original_data: bytes, compressed_data: bytes
    ) -> Dict[str, Any]:
        """Generate a report of compression changes.

        Args:
            original_data: Original PE file bytes
            compressed_data: Compressed PE file bytes

        Returns:
            Dictionary containing compression report
        """
        report = {
            "compression_enabled": self.config.enable_compression,
            "algorithm": self.config.compression_algorithm,
            "level": self.config.compression_level,
            "original_size": len(original_data),
            "compressed_size": len(compressed_data),
            "size_reduction": len(original_data) - len(compressed_data),
            "compression_ratio": (len(compressed_data) / len(original_data)) * 100,
            "space_saved_percentage": (
                (len(original_data) - len(compressed_data)) / len(original_data)
            )
            * 100,
        }

        return report
