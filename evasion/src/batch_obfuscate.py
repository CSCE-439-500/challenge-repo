#!/usr/bin/env python3
"""Batch obfuscation script for processing multiple binaries in a folder.

This script takes a folder as input and obfuscates all binary files in that folder,
outputting them to an 'out/' directory with the same filenames.
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import List

from .rt_evade.core.guards import require_redteam_mode, guard_can_write
from .rt_evade.core.pipeline import TransformPipeline
from .rt_evade.pe.obfuscator import PEObfuscator, PEObfuscationConfig


def _setup_logging() -> None:
    """Set up logging configuration based on environment variables."""
    level = logging.getLevelName(os.getenv("LOG_LEVEL", "INFO").upper())
    logging.basicConfig(
        level=level, format="time=%(asctime)s level=%(levelname)s msg=%(message)s"
    )


def load_bytes_from_file(path: str) -> bytes:
    """Load binary data from a file.

    Args:
        path: Path to the file to read

    Returns:
        The binary content of the file
    """
    with open(path, "rb") as f:
        return f.read()


def write_bytes_to_file(path: str, data: bytes) -> None:
    """Write binary data to a file.

    Args:
        path: Path where to write the data
        data: Binary data to write
    """
    guard_can_write()
    with open(path, "wb") as f:
        f.write(data)


def is_binary_file(file_path: Path) -> bool:
    """Check if a file is likely a binary file.

    Args:
        file_path: Path to the file to check

    Returns:
        True if the file appears to be binary
    """
    # Common binary file extensions
    binary_extensions = {
        ".exe",
        ".dll",
        ".sys",
        ".bin",
        ".dat",
        ".raw",
        ".img",
        ".iso",
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz",
        ".bz2",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".mp3",
        ".mp4",
        ".avi",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".bmp",
        ".ico",
        ".cur",
    }

    # Check by extension first
    if file_path.suffix.lower() in binary_extensions:
        return True

    # Check by content - read first 1024 bytes and look for null bytes
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except (IOError, OSError):
        return False


def find_binary_files(input_dir: Path) -> List[Path]:
    """Find all binary files in the input directory.

    Args:
        input_dir: Directory to search for binary files

    Returns:
        List of paths to binary files found
    """
    binary_files = []

    if not input_dir.exists():
        raise FileNotFoundError(f"Input directory does not exist: {input_dir}")

    if not input_dir.is_dir():
        raise NotADirectoryError(f"Input path is not a directory: {input_dir}")

    for file_path in input_dir.iterdir():
        if file_path.is_file() and is_binary_file(file_path):
            binary_files.append(file_path)

    return binary_files


def obfuscate_file(
    input_file: Path, output_file: Path, config: PEObfuscationConfig
) -> bool:
    """Obfuscate a single file.

    Args:
        input_file: Path to input file
        output_file: Path to output file
        config: Obfuscation configuration

    Returns:
        True if obfuscation was successful, False otherwise
    """
    try:
        # Load the original file
        original = load_bytes_from_file(str(input_file))

        # Create obfuscation pipeline
        pipeline = TransformPipeline()
        obfuscator = PEObfuscator(config)
        pipeline.add(obfuscator.create_obfuscation_plan(original))

        # Apply obfuscation
        obfuscated = pipeline.apply_all(original)

        # Write obfuscated file
        write_bytes_to_file(str(output_file), obfuscated)

        logging.info(
            "action=obfuscate_success input=%s output=%s original_size=%d obfuscated_size=%d",
            input_file.name,
            output_file.name,
            len(original),
            len(obfuscated),
        )
        return True

    except Exception as e:
        logging.error(
            "action=obfuscate_failed input=%s error=%s", input_file.name, str(e)
        )
        return False


def main() -> int:
    """Main entry point for batch obfuscation."""
    parser = argparse.ArgumentParser(
        description="Batch obfuscate all binary files in a directory"
    )
    parser.add_argument(
        "input_dir", help="Directory containing binary files to obfuscate"
    )
    parser.add_argument(
        "--output-dir",
        default="out",
        help="Output directory for obfuscated files (default: out)",
    )
    parser.add_argument(
        "--pe-mimicry",
        action="store_true",
        default=True,
        help="Enable PE mimicry (default: True)",
    )
    parser.add_argument(
        "--pe-strings",
        action="store_true",
        default=True,
        help="Enable PE string obfuscation (default: True)",
    )
    parser.add_argument(
        "--pe-imports",
        action="store_true",
        default=True,
        help="Enable PE import inflation (default: True)",
    )
    parser.add_argument(
        "--pe-padding",
        action="store_true",
        default=True,
        help="Enable PE section padding (default: True)",
    )
    parser.add_argument(
        "--pe-compression",
        action="store_true",
        default=True,
        help="Enable PE compression (default: True)",
    )
    parser.add_argument(
        "--pe-encryption",
        action="store_true",
        default=True,
        help="Enable PE encryption (default: True)",
    )
    parser.add_argument(
        "--pe-category",
        choices=["system_utility", "web_browser", "office_app"],
        help="Target software category for mimicry",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be obfuscated without actually doing it",
    )

    args = parser.parse_args()

    _setup_logging()
    require_redteam_mode()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)

    # Create output directory
    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    # Find binary files
    try:
        binary_files = find_binary_files(input_dir)
    except (FileNotFoundError, NotADirectoryError) as e:
        logging.error("action=find_files_failed error=%s", str(e))
        return 1

    if not binary_files:
        logging.warning("action=no_binary_files input_dir=%s", input_dir)
        return 0

    logging.info(
        "action=found_files count=%d input_dir=%s output_dir=%s",
        len(binary_files),
        input_dir,
        output_dir,
    )

    if args.dry_run:
        logging.info("action=dry_run files_to_process:")
        for file_path in binary_files:
            output_file = output_dir / file_path.name
            logging.info("  %s -> %s", file_path, output_file)
        return 0

    # Create obfuscation configuration
    config = PEObfuscationConfig(
        enable_mimicry=args.pe_mimicry,
        enable_string_obfuscation=args.pe_strings,
        enable_import_inflation=args.pe_imports,
        enable_section_padding=args.pe_padding,
        enable_compression=args.pe_compression,
        enable_code_encryption=args.pe_encryption,
        target_category=args.pe_category,
    )

    # Process each file
    success_count = 0
    for input_file in binary_files:
        output_file = output_dir / input_file.name
        if obfuscate_file(input_file, output_file, config):
            success_count += 1

    logging.info(
        "action=batch_complete processed=%d successful=%d failed=%d",
        len(binary_files),
        success_count,
        len(binary_files) - success_count,
    )

    return 0 if success_count == len(binary_files) else 1


if __name__ == "__main__":
    sys.exit(main())
