import base64
import re
from dataclasses import dataclass

from ..core.transform import TransformPlan


_PRINTABLE_ASCII = re.compile(rb"[ -~]{6,}")


def _encode_string_literals(buffer: bytes) -> bytes:
    # Replace printable ASCII spans with base64-encoded placeholders
    out = bytearray()
    last = 0
    for m in _PRINTABLE_ASCII.finditer(buffer):
        start, end = m.span()
        out.extend(buffer[last:start])
        encoded = base64.b64encode(buffer[start:end])
        out.extend(b"b64:" + encoded + b":")
        last = end
    out.extend(buffer[last:])
    return bytes(out)


@dataclass(frozen=True)
class Base64StringObfuscator:
    """Encode readable ASCII spans with base64 markers.

    This is a static-at-rest obfuscation that preserves size order but changes
    string tokens to reduce keyword-based detections. Decoding is expected at
    runtime by a cooperating dropper.
    """

    def as_plan(self) -> TransformPlan:
        return TransformPlan(name="base64_strings", apply=_encode_string_literals)


