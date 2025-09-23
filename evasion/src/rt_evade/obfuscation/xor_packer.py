from dataclasses import dataclass

from ..core.transform import TransformPlan


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("XOR key must be non-empty")
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


@dataclass(frozen=True)
class XorPacker:
    """XOR pack the entire buffer to conceal headers and strings at rest."""

    key: bytes

    def as_plan(self) -> TransformPlan:
        return TransformPlan(
            name="xor_pack",
            apply=lambda data: _xor_bytes(data, self.key),
        )


