import hashlib
import json
import logging
from typing import List

from .transform import TransformPlan

logger = logging.getLogger(__name__)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TransformPipeline:
    """Composable pipeline to apply multiple transforms to a byte buffer."""

    def __init__(self) -> None:
        self._steps: List[TransformPlan] = []

    def add(self, plan: TransformPlan) -> None:
        self._steps.append(plan)

    def apply_all(self, data: bytes) -> bytes:
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


