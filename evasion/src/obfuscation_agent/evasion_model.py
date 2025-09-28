"""Placeholder evasion model for testing obfuscation techniques.

This module provides a simple random evasion model that simulates
interaction with a real machine learning classification model.
"""

import os
import random
import math
import logging
from typing import Optional

# Removed REDTEAM_MODE requirement

logger = logging.getLogger(__name__)


def evasion_model(filepath: str) -> int:
    """Placeholder evasion model that randomly returns evasion results.

    Args:
        filepath: Path to the binary file to test

    Returns:
        0 if evaded (not detected), 1 if detected

    Raises:
        Exception: If file validation fails
    """
    try:
        # Check if file exists
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return 1  # Treat missing file as detected

        # Get file size for some basic "analysis"
        file_size = os.path.getsize(filepath)

        # Simple heuristic: smaller files have slightly better chance of evasion
        # This adds some realism to the random model
        if file_size < 100000:  # Less than 100KB
            evasion_chance = 0.4  # 40% chance of evasion
        elif file_size < 1000000:  # Less than 1MB
            evasion_chance = 0.3  # 30% chance of evasion
        else:
            evasion_chance = 0.2  # 20% chance of evasion

        # Random decision based on evasion chance
        result = 0 if random.random() < evasion_chance else 1

        logger.info(
            f"Evasion model result for {filepath}: {'EVADED' if result == 0 else 'DETECTED'}"
        )
        return result

    except Exception as e:
        logger.error(f"Error in evasion model: {e}")
        return 1  # Treat errors as detected


def evasion_model_with_entropy(filepath: str) -> int:
    """Enhanced evasion model that considers file entropy.

    Args:
        filepath: Path to the binary file to test

    Returns:
        0 if evaded (not detected), 1 if detected
    """
    try:

        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return 1

        # Read file and calculate basic entropy
        with open(filepath, "rb") as f:
            data = f.read()

        # Calculate simple entropy measure
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= (
                    probability * math.log2(probability) if probability > 0 else 0
                )

        # Normalize entropy (0-8 range)
        normalized_entropy = min(entropy / 8.0, 1.0)

        # Higher entropy = slightly better evasion chance
        base_chance = 0.3
        entropy_bonus = normalized_entropy * 0.2
        evasion_chance = min(base_chance + entropy_bonus, 0.8)

        result = 0 if random.random() < evasion_chance else 1

        logger.info(
            f"Entropy-based evasion model result for {filepath}: {'EVADED' if result == 0 else 'DETECTED'} (entropy: {normalized_entropy:.3f})"
        )
        return result

    except Exception as e:
        logger.error(f"Error in entropy-based evasion model: {e}")
        return 1


def evasion_model_deterministic(filepath: str, seed: Optional[int] = None) -> int:
    """Deterministic evasion model for testing consistency.

    Args:
        filepath: Path to the binary file to test
        seed: Random seed for deterministic results

    Returns:
        0 if evaded (not detected), 1 if detected
    """
    try:

        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return 1

        # Use file hash as seed for deterministic results
        if seed is None:
            with open(filepath, "rb") as f:
                data = f.read()
            seed = hash(data) % 1000000

        # Set random seed
        random.seed(seed)

        # Simple deterministic logic
        file_size = os.path.getsize(filepath)
        evasion_chance = 0.3 + (file_size % 1000) / 10000  # Vary based on file size

        result = 0 if random.random() < evasion_chance else 1

        logger.info(
            f"Deterministic evasion model result for {filepath}: {'EVADED' if result == 0 else 'DETECTED'} (seed: {seed})"
        )
        return result

    except Exception as e:
        logger.error(f"Error in deterministic evasion model: {e}")
        return 1
