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


