"""Evasion model client for querying the local model API.

This module implements the actual model interaction logic by sending the
binary bytes to a locally running model API (default: http://127.0.0.1:8080)
and returning the classification result.

Contract:
- Request: POST binary bytes with header Content-Type: application/octet-stream
- Response: JSON with field "result" where 0 = evaded (not detected), 1 = detected

Environment variables:
- MODEL_API_URL: Base URL of the model API (default: http://127.0.0.1:8080)
- MODEL_API_TIMEOUT: Request timeout in seconds (default: 30)
"""

import os
import random
import math
import logging
from typing import Optional
import json

import requests

# Removed REDTEAM_MODE requirement

logger = logging.getLogger(__name__)


def evasion_model(filepath: str) -> int:
    """Query the local model API and return the evasion result.

    Args:
        filepath: Path to the binary file to test

    Returns:
        0 if evaded (not detected), 1 if detected
    """
    try:
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return 1

        api_url = os.getenv("MODEL_API_URL", "http://127.0.0.1:8080")
        try:
            timeout = float(os.getenv("MODEL_API_TIMEOUT", "30"))
        except ValueError:
            timeout = 30.0

        with open(filepath, "rb") as f:
            data = f.read()

        headers = {"Content-Type": "application/octet-stream"}

        response = requests.post(api_url, data=data, headers=headers, timeout=timeout)
        response.raise_for_status()

        # Parse JSON safely
        try:
            payload = response.json()
        except json.JSONDecodeError:
            logger.error("Model API returned non-JSON response")
            return 1

        result = payload.get("result")
        if result not in (0, 1):
            logger.error(f"Model API returned invalid result payload: {payload}")
            return 1

        logger.info(
            f"Model API result for {filepath}: {'EVADED' if result == 0 else 'DETECTED'}"
        )
        return int(result)

    except requests.exceptions.RequestException as e:
        logger.error(f"Error contacting model API: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error in evasion_model: {e}")
        return 1


# Note: No heuristic fallback. All decisions come from the local model API.


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
