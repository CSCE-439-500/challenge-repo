"""Core transformation types for binary data processing.

This module defines the core types used for representing and applying
transformations to binary data in the rt_evade toolkit.
"""
from dataclasses import dataclass
from typing import Callable


TransformFunc = Callable[[bytes], bytes]


@dataclass(frozen=True)
class TransformPlan:
    """Description of a single in-memory byte transformation.

    Attributes:
        name: Human-readable name.
        apply: Pure function mapping input bytes to output bytes.
    """

    name: str
    apply: TransformFunc
