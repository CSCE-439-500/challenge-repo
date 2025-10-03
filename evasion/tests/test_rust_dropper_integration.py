"""Integration test for rust-dropper functionality.

This test verifies that the rust-dropper pipeline works correctly
when given input files and produces proper dropper executables.
"""

import os
import tempfile
import subprocess
import shutil
from pathlib import Path
import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def sample_pe_file(temp_dir):
    """Create a sample PE file for testing."""
    # Create a simple executable file (not a real PE, but good enough for testing)
    sample_file = os.path.join(temp_dir, "test_sample.exe")
    with open(sample_file, "wb") as f:
        # Write some dummy content that looks like a PE file
        f.write(b"MZ" + b"\x00" * 58 + b"PE\x00\x00" + b"\x00" * 1000)
    return sample_file


def test_rust_dropper_single_file(sample_pe_file, temp_dir):
    """Test rust-dropper with a single input file."""
    # Get the rust-dropper directory
    project_root = Path(__file__).parent.parent
    rust_dropper_dir = project_root / "rust-dropper"

    if not rust_dropper_dir.exists():
        pytest.skip("rust-dropper directory not found")

    # Create output directory
    output_dir = os.path.join(temp_dir, "output")
    os.makedirs(output_dir, exist_ok=True)

    # Run rust-dropper with single file
    cmd = [
        "cargo",
        "run",
        "--bin",
        "build-droppers",
        "stealth",
        sample_pe_file,
        output_dir,
    ]

    result = subprocess.run(
        cmd, cwd=rust_dropper_dir, capture_output=True, text=True, timeout=60
    )

    # Check if command succeeded
    assert result.returncode == 0, f"rust-dropper failed: {result.stderr}"

    # Check if dropper was created (with same filename as input)
    input_filename = os.path.basename(sample_pe_file)
    dropper_file = os.path.join(output_dir, input_filename)
    assert os.path.exists(dropper_file), f"Dropper file not created at {dropper_file}"

    # Check if dropper is different from input (should be larger due to embedding)
    input_size = os.path.getsize(sample_pe_file)
    dropper_size = os.path.getsize(dropper_file)

    print(f"Input file size: {input_size} bytes")
    print(f"Dropper file size: {dropper_size} bytes")

    # The dropper should be significantly larger due to the embedded payload and Rust runtime
    assert dropper_size > input_size, "Dropper should be larger than input file"
    assert (
        dropper_size > 100000
    ), "Dropper should be substantial size (Rust runtime + embedded payload)"


# Multiple files test removed - rust-dropper now only accepts single files


def test_rust_dropper_presets(temp_dir):
    """Test different rust-dropper presets."""
    # Get the rust-dropper directory
    project_root = Path(__file__).parent.parent
    rust_dropper_dir = project_root / "rust-dropper"

    if not rust_dropper_dir.exists():
        pytest.skip("rust-dropper directory not found")

    # Create a sample file
    sample_file = os.path.join(temp_dir, "test.exe")
    with open(sample_file, "wb") as f:
        f.write(b"MZ" + b"\x00" * 58 + b"PE\x00\x00" + b"\x00" * 1000)

    # Test different presets
    presets = ["minimal", "stealth", "maximum"]

    for preset in presets:
        output_dir = os.path.join(temp_dir, f"output_{preset}")
        os.makedirs(output_dir, exist_ok=True)

        cmd = [
            "cargo",
            "run",
            "--bin",
            "build-droppers",
            preset,
            sample_file,
            output_dir,
        ]

        result = subprocess.run(
            cmd, cwd=rust_dropper_dir, capture_output=True, text=True, timeout=60
        )

        # Check if command succeeded
        assert (
            result.returncode == 0
        ), f"rust-dropper failed with preset {preset}: {result.stderr}"

        # Check if dropper was created
        dropper_file = os.path.join(output_dir, "test.exe")
        assert os.path.exists(
            dropper_file
        ), f"Dropper file not created for preset {preset}"

        # Check dropper size
        dropper_size = os.path.getsize(dropper_file)
        assert (
            dropper_size > 100000
        ), f"Dropper for preset {preset} should be substantial size"


def test_rust_dropper_error_handling(temp_dir):
    """Test rust-dropper error handling with invalid input."""
    # Get the rust-dropper directory
    project_root = Path(__file__).parent.parent
    rust_dropper_dir = project_root / "rust-dropper"

    if not rust_dropper_dir.exists():
        pytest.skip("rust-dropper directory not found")

    # Create input and output directories
    input_dir = os.path.join(temp_dir, "input")
    output_dir = os.path.join(temp_dir, "output")
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    # Create an invalid file (not a PE)
    invalid_file = os.path.join(input_dir, "invalid.txt")
    with open(invalid_file, "w") as f:
        f.write("This is not a PE file")

    # Run rust-dropper
    cmd = ["cargo", "run", "--bin", "build-droppers", "stealth", input_dir, output_dir]

    result = subprocess.run(
        cmd, cwd=rust_dropper_dir, capture_output=True, text=True, timeout=60
    )

    # The command might succeed but not create a dropper for invalid files
    # This tests that the system handles invalid input gracefully
    print(f"Return code: {result.returncode}")
    print(f"STDOUT: {result.stdout}")
    print(f"STDERR: {result.stderr}")

    # Check that no dropper was created for the invalid file
    dropper_file = os.path.join(output_dir, "invalid.txt")
    assert not os.path.exists(
        dropper_file
    ), "No dropper should be created for invalid input"
