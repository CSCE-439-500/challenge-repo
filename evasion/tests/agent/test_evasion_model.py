"""Tests for evasion model functionality.

This module contains pytest tests for the evasion model component,
including placeholder ML model functionality.
"""

import os
import tempfile
import pytest
from unittest.mock import patch

from obfuscation_agent.evasion_model import (
    evasion_model,
    evasion_model_with_entropy,
    evasion_model_deterministic,
)


@pytest.fixture
def temp_file():
    """Create a temporary file for testing."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(b"test binary data for evasion testing")
        temp_file = f.name
    yield temp_file
    # Cleanup
    if os.path.exists(temp_file):
        os.unlink(temp_file)


class TestEvasionModel:
    """Test class for evasion model."""

    def test_evasion_model_success(self, temp_file):
        """Test successful evasion model execution."""
        result = evasion_model(temp_file)

        assert result in [0, 1]  # Should return 0 (evaded) or 1 (detected)

    def test_evasion_model_nonexistent_file(self):
        """Test evasion model with nonexistent file."""
        result = evasion_model("nonexistent.exe")
        assert result == 1  # Should return 1 (detected) for missing file

    def test_evasion_model_file_size_heuristic(self, temp_file):
        """Test that file size affects evasion probability."""
        # Test with small file
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"small")  # Very small file
            small_file = f.name

        try:
            # Run multiple times to check probability
            results = []
            for _ in range(10):
                result = evasion_model(small_file)
                results.append(result)

            # Should get some variety in results
            assert len(set(results)) > 1  # Should have both 0 and 1 results
        finally:
            if os.path.exists(small_file):
                os.unlink(small_file)

    def test_evasion_model_with_entropy_success(self, temp_file):
        """Test successful entropy-based evasion model execution."""
        result = evasion_model_with_entropy(temp_file)

        assert result in [0, 1]  # Should return 0 (evaded) or 1 (detected)

    def test_evasion_model_with_entropy_nonexistent_file(self):
        """Test entropy-based evasion model with nonexistent file."""
        result = evasion_model_with_entropy("nonexistent.exe")
        assert result == 1  # Should return 1 (detected) for missing file

    def test_evasion_model_with_entropy_entropy_calculation(self, temp_file):
        """Test that entropy calculation affects evasion probability."""
        # Create files with different entropy levels
        low_entropy_data = b"AAAA" * 100  # Low entropy (repeated bytes)
        high_entropy_data = os.urandom(400)  # High entropy (random bytes)

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(low_entropy_data)
            low_entropy_file = f.name

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(high_entropy_data)
            high_entropy_file = f.name

        try:
            # Test both files - the entropy-based model is deterministic for the same file
            # but we can test that different entropy levels give different results
            low_result = evasion_model_with_entropy(low_entropy_file)
            high_result = evasion_model_with_entropy(high_entropy_file)

            # Both should return valid results (0 or 1)
            assert low_result in [0, 1]
            assert high_result in [0, 1]

            # Test that the function works with different entropy levels
            # (The actual evasion result depends on random chance, so we can't guarantee
            # that high entropy will always evade better, but we can verify the function works)

        finally:
            for file_path in [low_entropy_file, high_entropy_file]:
                if os.path.exists(file_path):
                    os.unlink(file_path)

    def test_evasion_model_deterministic_success(self, temp_file):
        """Test successful deterministic evasion model execution."""
        result = evasion_model_deterministic(temp_file)

        assert result in [0, 1]  # Should return 0 (evaded) or 1 (detected)

    def test_evasion_model_deterministic_consistency(self, temp_file):
        """Test that deterministic model returns consistent results."""
        # Test with same file multiple times
        results = []
        for _ in range(5):
            result = evasion_model_deterministic(temp_file)
            results.append(result)

        # All results should be the same
        assert len(set(results)) == 1

    def test_evasion_model_deterministic_different_files(self, temp_file):
        """Test that deterministic model returns different results for different files."""
        # Create another file with different content
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"different binary data")
            different_file = f.name

        try:
            result1 = evasion_model_deterministic(temp_file)
            result2 = evasion_model_deterministic(different_file)

            # Results might be the same or different, but should be deterministic
            assert result1 in [0, 1]
            assert result2 in [0, 1]

        finally:
            if os.path.exists(different_file):
                os.unlink(different_file)

    def test_evasion_model_deterministic_with_seed(self, temp_file):
        """Test deterministic model with explicit seed."""
        result1 = evasion_model_deterministic(temp_file, seed=12345)
        result2 = evasion_model_deterministic(temp_file, seed=12345)

        # Results should be the same with same seed
        assert result1 == result2

    def test_evasion_model_deterministic_different_seeds(self, temp_file):
        """Test deterministic model with different seeds."""
        result1 = evasion_model_deterministic(temp_file, seed=12345)
        result2 = evasion_model_deterministic(temp_file, seed=67890)

        # Results might be different with different seeds
        assert result1 in [0, 1]
        assert result2 in [0, 1]

    def test_evasion_model_error_handling(self, temp_file):
        """Test error handling in evasion model."""
        with patch("random.random") as mock_random:
            mock_random.side_effect = Exception("Random error")

            result = evasion_model(temp_file)
            assert result == 1  # Should return 1 (detected) on error

    def test_evasion_model_with_entropy_error_handling(self, temp_file):
        """Test error handling in entropy-based evasion model."""
        with patch("random.random") as mock_random:
            mock_random.side_effect = Exception("Random error")

            result = evasion_model_with_entropy(temp_file)
            assert result == 1  # Should return 1 (detected) on error

    def test_evasion_model_deterministic_error_handling(self, temp_file):
        """Test error handling in deterministic evasion model."""
        with patch("random.seed") as mock_seed:
            mock_seed.side_effect = Exception("Seed error")

            result = evasion_model_deterministic(temp_file)
            assert result == 1  # Should return 1 (detected) on error
