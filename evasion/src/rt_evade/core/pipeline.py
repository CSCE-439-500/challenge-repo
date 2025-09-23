"""Transform pipeline for applying multiple transformations to binary data.

This module provides a composable pipeline system for applying multiple
transformations to binary data in sequence, with logging and hash tracking.
"""
import hashlib
import json
import logging
from typing import List

from .transform import TransformPlan

logger = logging.getLogger(__name__)


def _sha256(data: bytes) -> str:
    """Calculate SHA256 hash of binary data.

    Args:
        data: Binary data to hash

    Returns:
        Hexadecimal string representation of the hash
    """
    return hashlib.sha256(data).hexdigest()


class TransformPipeline:
    """Composable pipeline to apply multiple transforms to a byte buffer."""

    def __init__(self) -> None:
        self._steps: List[TransformPlan] = []

    def add(self, plan: TransformPlan) -> None:
        """Add a transformation plan to the pipeline.

        Args:
            plan: The transformation plan to add
        """
        self._steps.append(plan)

    def apply_all(self, data: bytes) -> bytes:
        """Apply all transformation plans in sequence to the input data.

        Args:
            data: Input binary data to transform

        Returns:
            Transformed binary data after applying all steps
        """
        before_hash = _sha256(data)
        current = data
        for idx, step in enumerate(self._steps):
            prev_hash = _sha256(current)
            current = step.apply(current)
            step_hash = _sha256(current)
            logger.info(
                "action=transform idx=%d step=%s input_hash=%s output_hash=%s",
                idx,
                step.name,
                prev_hash,
                step_hash,
            )
        after_hash = _sha256(current)
        summary = {
            "steps": [s.name for s in self._steps],
            "input_hash": before_hash,
            "output_hash": after_hash,
        }
        logger.info("action=pipeline_summary data=%s", json.dumps(summary))
        return current
