"""Tests for state manager functionality.

This module contains pytest tests for the state manager component,
including checkpoint and revert functionality.
"""

import os
import tempfile
import pytest
from unittest.mock import patch

from obfuscation_agent.state_manager import (
    save_checkpoint,
    revert_to_checkpoint,
    cleanup_checkpoint,
    list_checkpoints,
    cleanup_old_checkpoints,
)


@pytest.fixture
def temp_file():
    """Create a temporary file for testing."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(b"test binary data")
        temp_file = f.name
    yield temp_file
    # Cleanup
    if os.path.exists(temp_file):
        os.unlink(temp_file)


class TestStateManager:
    """Test class for state manager."""

    def test_save_checkpoint_success(self, temp_file):
        """Test successful checkpoint creation."""
        checkpoint_path = save_checkpoint(temp_file)

        assert checkpoint_path != temp_file
        assert os.path.exists(checkpoint_path)
        assert "_checkpoint_" in checkpoint_path

        # Verify content is the same
        with open(temp_file, "rb") as f:
            original_data = f.read()
        with open(checkpoint_path, "rb") as f:
            checkpoint_data = f.read()
        assert original_data == checkpoint_data

        # Cleanup
        if os.path.exists(checkpoint_path):
            os.unlink(checkpoint_path)

    def test_save_checkpoint_nonexistent_file(self):
        """Test checkpoint creation with nonexistent file."""
        with pytest.raises(FileNotFoundError):
            save_checkpoint("nonexistent.exe")

    def test_revert_to_checkpoint_success(self, temp_file):
        """Test successful checkpoint revert."""
        # Create checkpoint
        checkpoint_path = save_checkpoint(temp_file)

        # Modify original file
        with open(temp_file, "wb") as f:
            f.write(b"modified data")

        # Revert to checkpoint
        success = revert_to_checkpoint(temp_file, checkpoint_path)

        assert success is True

        # Verify file was reverted
        with open(temp_file, "rb") as f:
            data = f.read()
        assert data == b"test binary data"

        # Cleanup
        if os.path.exists(checkpoint_path):
            os.unlink(checkpoint_path)

    def test_revert_to_checkpoint_nonexistent_checkpoint(self, temp_file):
        """Test revert with nonexistent checkpoint."""
        success = revert_to_checkpoint(temp_file, "nonexistent_checkpoint.exe")
        assert success is False

    def test_cleanup_checkpoint_success(self, temp_file):
        """Test successful checkpoint cleanup."""
        # Create checkpoint
        checkpoint_path = save_checkpoint(temp_file)
        assert os.path.exists(checkpoint_path)

        # Cleanup checkpoint
        success = cleanup_checkpoint(checkpoint_path)

        assert success is True
        assert not os.path.exists(checkpoint_path)

    def test_cleanup_checkpoint_nonexistent(self):
        """Test cleanup of nonexistent checkpoint."""
        success = cleanup_checkpoint("nonexistent_checkpoint.exe")
        assert success is True  # Should return True even if file doesn't exist

    def test_list_checkpoints(self, temp_file):
        """Test listing checkpoints."""
        # Create multiple checkpoints
        checkpoint1 = save_checkpoint(temp_file)
        checkpoint2 = save_checkpoint(temp_file)

        checkpoints = list_checkpoints(temp_file)

        assert len(checkpoints) >= 2
        assert checkpoint1 in checkpoints
        assert checkpoint2 in checkpoints

        # Cleanup
        for checkpoint in checkpoints:
            if os.path.exists(checkpoint):
                os.unlink(checkpoint)

    def test_cleanup_old_checkpoints(self, temp_file):
        """Test cleanup of old checkpoints."""
        # Create multiple checkpoints
        checkpoints = []
        for i in range(7):  # Create 7 checkpoints
            checkpoint = save_checkpoint(temp_file)
            checkpoints.append(checkpoint)

        # Cleanup old checkpoints, keeping only 3
        removed_count = cleanup_old_checkpoints(temp_file, keep_count=3)

        assert removed_count >= 4  # Should remove at least 4 checkpoints

        # Verify remaining checkpoints
        remaining = list_checkpoints(temp_file)
        assert len(remaining) <= 3

        # Cleanup remaining
        for checkpoint in remaining:
            if os.path.exists(checkpoint):
                os.unlink(checkpoint)

    def test_cleanup_old_checkpoints_insufficient(self, temp_file):
        """Test cleanup when there aren't enough checkpoints to clean."""
        # Create only 2 checkpoints
        checkpoint1 = save_checkpoint(temp_file)
        checkpoint2 = save_checkpoint(temp_file)

        # Try to clean up, keeping 3 (more than we have)
        removed_count = cleanup_old_checkpoints(temp_file, keep_count=3)

        assert removed_count == 0  # Should remove 0 checkpoints

        # Cleanup
        for checkpoint in [checkpoint1, checkpoint2]:
            if os.path.exists(checkpoint):
                os.unlink(checkpoint)

    def test_error_handling_in_save_checkpoint(self, temp_file):
        """Test error handling in save_checkpoint."""
        with patch("obfuscation_agent.state_manager.shutil.copy2") as mock_copy:
            mock_copy.side_effect = OSError("Permission denied")

            with pytest.raises(OSError):
                save_checkpoint(temp_file)

    def test_error_handling_in_revert_to_checkpoint(self, temp_file):
        """Test error handling in revert_to_checkpoint."""
        with patch("obfuscation_agent.state_manager.shutil.copy2") as mock_copy:
            mock_copy.side_effect = OSError("Permission denied")

            success = revert_to_checkpoint(temp_file, "checkpoint.exe")
            assert success is False
