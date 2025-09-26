#!/usr/bin/env python3
"""Setup script for Rust-Crypter integration.

This script helps set up the Rust-Crypter tool for use with the rt_evade toolkit.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def check_rust_installation():
    """Check if Rust is installed and available."""
    try:
        result = subprocess.run(
            ["cargo", "--version"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        logger.info("Rust found: %s", result.stdout.strip())
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("Rust not found. Please install Rust from https://rustup.rs/")
        return False


def check_rust_target(target):
    """Check if a specific Rust target is installed."""
    try:
        result = subprocess.run(
            ["rustup", "target", "list", "--installed"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        installed_targets = result.stdout.strip().split('\n')
        return target in installed_targets
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def install_rust_target(target):
    """Install a specific Rust target."""
    logger.info("Installing Rust target: %s", target)
    try:
        subprocess.run(
            ["rustup", "target", "add", target], 
            check=True, 
            capture_output=True, 
            text=True
        )
        logger.info("Successfully installed target: %s", target)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Failed to install target %s: %s", target, e.stderr)
        return False


def clone_rust_crypter(destination):
    """Clone the Rust-Crypter repository."""
    logger.info("Cloning Rust-Crypter repository...")
    try:
        subprocess.run(
            [
                "git", "clone", 
                "https://github.com/Amaop/Rust-Crypter.git", 
                str(destination)
            ],
            check=True,
            capture_output=True,
            text=True
        )
        logger.info("Successfully cloned Rust-Crypter to: %s", destination)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Failed to clone Rust-Crypter: %s", e.stderr)
        return False


def test_rust_crypter_build(rust_crypter_path):
    """Test that Rust-Crypter can be built successfully."""
    logger.info("Testing Rust-Crypter build...")
    
    # Test crypt build
    try:
        subprocess.run(
            ["cargo", "build"],
            cwd=rust_crypter_path / "crypt",
            check=True,
            capture_output=True,
            text=True
        )
        logger.info("Crypt component builds successfully")
    except subprocess.CalledProcessError as e:
        logger.error("Crypt component build failed: %s", e.stderr)
        return False
    
    # Test stub build with dummy files (stub requires encrypted files to exist)
    stub_src = rust_crypter_path / "stub" / "src"
    
    # Create dummy encrypted files for testing
    dummy_encrypted = stub_src / "encrypted_Input.bin"
    dummy_key = stub_src / "key.txt"
    
    try:
        # Create dummy files
        dummy_encrypted.write_bytes(b"dummy_encrypted_data")
        dummy_key.write_text("dummy_key_data")
        
        # Test stub build
        subprocess.run(
            ["cargo", "build", "--target=x86_64-pc-windows-gnu"],
            cwd=rust_crypter_path / "stub",
            check=True,
            capture_output=True,
            text=True
        )
        logger.info("Stub component builds successfully")
        
        # Clean up dummy files
        dummy_encrypted.unlink(missing_ok=True)
        dummy_key.unlink(missing_ok=True)
        
    except subprocess.CalledProcessError as e:
        logger.error("Stub component build failed: %s", e.stderr)
        # Clean up dummy files even on failure
        dummy_encrypted.unlink(missing_ok=True)
        dummy_key.unlink(missing_ok=True)
        return False
    
    return True


def main():
    """Main setup function."""
    logger.info("Setting up Rust-Crypter integration for rt_evade...")
    
    # Check Rust installation
    if not check_rust_installation():
        logger.error("Please install Rust first: https://rustup.rs/")
        return 1
    
    # Check and install required targets
    targets = ["x86_64-pc-windows-gnu", "i686-pc-windows-gnu"]
    for target in targets:
        if not check_rust_target(target):
            logger.info("Installing target: %s", target)
            if not install_rust_target(target):
                logger.error("Failed to install target: %s", target)
                return 1
    
    # Determine where to install Rust-Crypter
    install_dir = Path.cwd() / "rust-crypter"
    
    if install_dir.exists():
        logger.info("Rust-Crypter already exists at: %s", install_dir)
        response = input("Do you want to reinstall? (y/N): ").strip().lower()
        if response == 'y':
            import shutil
            shutil.rmtree(install_dir)
        else:
            logger.info("Using existing Rust-Crypter installation")
    else:
        # Clone Rust-Crypter
        if not clone_rust_crypter(install_dir):
            return 1
    
    # Test the build
    if not test_rust_crypter_build(install_dir):
        logger.error("Rust-Crypter build test failed")
        return 1
    
    # Set environment variable
    env_file = Path.cwd() / ".env"
    env_content = f"RUST_CRYPTER_PATH={install_dir.absolute()}\n"
    
    if env_file.exists():
        # Read existing content
        existing_content = env_file.read_text()
        if "RUST_CRYPTER_PATH" not in existing_content:
            env_file.write_text(existing_content + "\n" + env_content)
        else:
            # Update existing line
            lines = existing_content.split('\n')
            updated_lines = []
            for line in lines:
                if line.startswith("RUST_CRYPTER_PATH="):
                    updated_lines.append(env_content.strip())
                else:
                    updated_lines.append(line)
            env_file.write_text('\n'.join(updated_lines))
    else:
        env_file.write_text(env_content)
    
    logger.info("Rust-Crypter setup completed successfully!")
    logger.info("Installation directory: %s", install_dir.absolute())
    logger.info("Environment variable set in: %s", env_file.absolute())
    logger.info("")
    logger.info("You can now use the rust-crypter command:")
    logger.info("  python -m rt_evade rust-crypter samples/out.bin --output encrypted.exe")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
