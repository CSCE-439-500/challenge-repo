"""Runtime decoding utilities for obfuscated binary data.

This module provides runtime decoding capabilities to reverse obfuscations
applied to binary data, including Base64 string decoding and XOR decryption.
"""
import base64
import re
from dataclasses import dataclass
from typing import Callable


_B64_MARKER = re.compile(rb"b64:([A-Za-z0-9+/=]+):")


def _decode_base64_markers(buffer: bytes) -> bytes:
    """Decode Base64 markers in binary data.

    Args:
        buffer: Binary data containing Base64 markers

    Returns:
        Decoded binary data with Base64 markers replaced
    """
    out = bytearray()
    last = 0
    for m in _B64_MARKER.finditer(buffer):
        start, end = m.span()
        out.extend(buffer[last:start])
        encoded = m.group(1)
        out.extend(base64.b64decode(encoded))
        last = end
    out.extend(buffer[last:])
    return bytes(out)


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """Apply XOR decryption to binary data.

    Args:
        data: Binary data to decrypt
        key: XOR key (will be repeated if shorter than data)

    Returns:
        XOR-decrypted binary data
    """
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


@dataclass(frozen=True)
class RuntimeDecode:
    """Runtime decode helpers to reverse obfuscations in memory.

    Note: This module avoids disk writes and returns decoded buffers for
    downstream loaders. Execution/loading is out of scope for this skeleton.
    """

    decode_strings: bool = True
    xor_key_supplier: Callable[[], bytes] | None = None

    def apply(self, data: bytes) -> bytes:
        """Apply runtime decoding to binary data.

        Args:
            data: Binary data to decode

        Returns:
            Decoded binary data

        Raises:
            ValueError: If XOR key supplier returns empty key
        """
        current = data
        if self.xor_key_supplier is not None:
            key = self.xor_key_supplier()
            if not key:
                raise ValueError("xor_key_supplier returned empty key")
            current = _xor_bytes(current, key)
        if self.decode_strings:
            current = _decode_base64_markers(current)
        return current
