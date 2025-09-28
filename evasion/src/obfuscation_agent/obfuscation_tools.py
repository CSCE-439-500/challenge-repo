"""Obfuscation tools module for PE file manipulation.

This module provides independent obfuscation functions that can be called
repeatedly by the agent without causing cascading errors.
"""

import os
import random
import logging
from typing import Optional
import pefile
from pefile import PE

from rt_evade.pe.reader import PEReader
from rt_evade.pe.writer import PEWriter

# Removed REDTEAM_MODE requirement

logger = logging.getLogger(__name__)


def add_junk_sections(filepath: str, output_dir: str = None) -> str:
    """Adds a new, empty section to the PE header.

    Args:
        filepath: Path to the input PE file

    Returns:
        Path to the modified binary file

    Raises:
        Exception: If obfuscation fails
    """
    try:

        # Read the PE file
        with open(filepath, "rb") as f:
            pe_data = f.read()

        with PEReader(pe_data) as reader:
            # Create a new PE writer
            with PEWriter(pe_data) as writer:
                # Add a junk section with random name (max 8 chars for PE)
                junk_section_name = f".j{random.randint(100, 999)}"
                junk_data = os.urandom(1024)  # 1KB of random data

                # Add the junk section
                writer.add_section(junk_section_name, junk_data)

                # Get modified data
                modified_data = writer.get_modified_data()

        # Save to new file
        if output_dir:
            # Create intermediate files directory within the specific output directory
            intermediate_dir = os.path.join(output_dir, "intermediate-files")
            os.makedirs(intermediate_dir, exist_ok=True)
            filename = os.path.basename(filepath)
            name, ext = os.path.splitext(filename)
            new_path = os.path.join(intermediate_dir, f"{name}_junked{ext}")
        else:
            new_path = filepath.replace(".exe", "_junked.exe")
        with open(new_path, "wb") as f:
            f.write(modified_data)

        logger.info(f"Added junk section {junk_section_name} to {filepath}")
        return new_path

    except Exception as e:
        logger.error(f"Error in add_junk_sections: {e}")
        return filepath


def rearrange_sections(filepath: str, output_dir: str = None) -> str:
    """Changes the order of existing sections in the PE file.

    Args:
        filepath: Path to the input PE file

    Returns:
        Path to the modified binary file

    Raises:
        Exception: If obfuscation fails
    """
    try:

        # Read the PE file
        with open(filepath, "rb") as f:
            pe_data = f.read()

        with PEReader(pe_data) as reader:
            sections = reader.get_sections()

            if len(sections) < 2:
                logger.warning("Not enough sections to rearrange")
                # Still create a modified file for consistency
                new_path = filepath.replace(".exe", "_rearranged.exe")
                with open(new_path, "wb") as f:
                    f.write(pe_data)
                return new_path

            # Create a new PE writer
            with PEWriter(pe_data) as writer:
                # Get section data
                section_data = {}
                for section in sections:
                    section_data[section.name] = reader.get_section_data(section.name)

                # Randomly shuffle section order (keep .text first for execution)
                section_names = [s.name for s in sections if s.name != ".text"]
                random.shuffle(section_names)

                # Rebuild sections in new order
                if ".text" in [s.name for s in sections]:
                    section_names.insert(0, ".text")  # Keep .text first

                # Clear existing sections and add in new order
                for section_name in section_names:
                    if section_name in section_data and section_data[section_name]:
                        writer.add_section(section_name, section_data[section_name])

                # Get modified data
                modified_data = writer.get_modified_data()

        # Save to new file
        if output_dir:
            # Create intermediate files directory
            intermediate_dir = os.path.join(output_dir, "intermediate-files")
            os.makedirs(intermediate_dir, exist_ok=True)
            filename = os.path.basename(filepath)
            name, ext = os.path.splitext(filename)
            new_path = os.path.join(intermediate_dir, f"{name}_rearranged{ext}")
        else:
            new_path = filepath.replace(".exe", "_rearranged.exe")
        with open(new_path, "wb") as f:
            f.write(modified_data)

        logger.info(f"Rearranged sections in {filepath}")
        return new_path

    except Exception as e:
        logger.error(f"Error in rearrange_sections: {e}")
        return filepath


def change_section_names(filepath: str, output_dir: str = None) -> str:
    """Renames sections (e.g., from .text to .code).

    Args:
        filepath: Path to the input PE file

    Returns:
        Path to the modified binary file

    Raises:
        Exception: If obfuscation fails
    """
    try:

        # Read the PE file
        with open(filepath, "rb") as f:
            pe_data = f.read()

        with PEReader(pe_data) as reader:
            sections = reader.get_sections()

            # Create a new PE writer
            with PEWriter(pe_data) as writer:
                # Mapping of common section names to alternatives
                name_mappings = {
                    ".text": ".code",
                    ".data": ".info",
                    ".rdata": ".read",
                    ".rsrc": ".resources",
                    ".reloc": ".relocations",
                }

                # Rename sections
                for section in sections:
                    original_name = section.name
                    new_name = name_mappings.get(
                        original_name, f".{original_name[1:]}{random.randint(100, 999)}"
                    )

                    section_data = reader.get_section_data(original_name)
                    if section_data:
                        writer.add_section(new_name, section_data)

                # Get modified data
                modified_data = writer.get_modified_data()

        # Save to new file
        if output_dir:
            # Create intermediate files directory
            intermediate_dir = os.path.join(output_dir, "intermediate-files")
            os.makedirs(intermediate_dir, exist_ok=True)
            filename = os.path.basename(filepath)
            name, ext = os.path.splitext(filename)
            new_path = os.path.join(intermediate_dir, f"{name}_renamed{ext}")
        else:
            new_path = filepath.replace(".exe", "_renamed.exe")
        with open(new_path, "wb") as f:
            f.write(modified_data)

        logger.info(f"Renamed sections in {filepath}")
        return new_path

    except Exception as e:
        logger.error(f"Error in change_section_names: {e}")
        return filepath


def change_timestamp(filepath: str, output_dir: str = None) -> str:
    """Modifies the PE file's timestamp.

    Args:
        filepath: Path to the input PE file

    Returns:
        Path to the modified binary file

    Raises:
        Exception: If obfuscation fails
    """
    try:

        # Read the PE file
        with open(filepath, "rb") as f:
            pe_data = f.read()

        # Load with pefile for direct manipulation
        pe = PE(data=pe_data)

        # Generate a random timestamp (within reasonable range)
        # Unix timestamp range: 2020-2030
        min_timestamp = 1577836800  # 2020-01-01
        max_timestamp = 1893456000  # 2030-01-01
        new_timestamp = random.randint(min_timestamp, max_timestamp)

        # Modify the timestamp
        pe.FILE_HEADER.TimeDateStamp = new_timestamp

        # Get modified data
        modified_data = pe.write()
        pe.close()

        # Save to new file
        if output_dir:
            # Create intermediate files directory
            intermediate_dir = os.path.join(output_dir, "intermediate-files")
            os.makedirs(intermediate_dir, exist_ok=True)
            filename = os.path.basename(filepath)
            name, ext = os.path.splitext(filename)
            new_path = os.path.join(intermediate_dir, f"{name}_timestamped{ext}")
        else:
            new_path = filepath.replace(".exe", "_timestamped.exe")
        with open(new_path, "wb") as f:
            f.write(modified_data)

        logger.info(f"Changed timestamp to {new_timestamp} in {filepath}")
        return new_path

    except Exception as e:
        logger.error(f"Error in change_timestamp: {e}")
        return filepath


def validate_pe_file(filepath: str) -> bool:
    """Validate that a file is a valid PE file.

    Args:
        filepath: Path to the file to validate

    Returns:
        True if valid PE file, False otherwise
    """
    try:
        with open(filepath, "rb") as f:
            pe_data = f.read()

        # Try to load with pefile
        pe = PE(data=pe_data)
        pe.close()
        return True

    except Exception:
        return False
