import os
import subprocess
from pathlib import Path

import pytest

from rt_evade.core.pipeline import TransformPipeline
from rt_evade.obfuscation.base64_strings import Base64StringObfuscator
from rt_evade.obfuscation.xor_packer import XorPacker
from rt_evade.dropper.runtime_decode import RuntimeDecode


def run_binary(path: Path) -> str:
    print(f"[run] Executing: {path}")
    proc = subprocess.run([str(path)], check=True, capture_output=True)
    out = proc.stdout.decode("utf-8")
    print(f"[run] Exit=0, stdout=<{out}>")
    return out


@pytest.mark.skipif(os.name == "nt", reason="POSIX exec required")
def test_hello_world_runtime_parity(hello_bin: Path, tmp_path: Path, ensure_env) -> None:
    print("[test] Running baseline binary...")
    baseline = run_binary(hello_bin)
    assert baseline.strip() == "Hello, World!"

    original_bytes = hello_bin.read_bytes()
    print(f"[test] Original size={len(original_bytes)} bytes")

    # Obfuscate: base64 strings + XOR pack
    pipeline = TransformPipeline()
    pipeline.add(Base64StringObfuscator().as_plan())
    key = b"test-key"
    pipeline.add(XorPacker(key=key).as_plan())
    obfuscated = pipeline.apply_all(original_bytes)
    print(f"[test] Obfuscated size={len(obfuscated)} bytes")

    # Runtime decode in memory
    decoder = RuntimeDecode(
        decode_strings=True,
        xor_key_supplier=lambda: key,
    )
    decoded = decoder.apply(obfuscated)
    print(f"[test] Decoded size={len(decoded)} bytes")

    # Write decoded to temp executable and compare output
    decoded_path = tmp_path / "hello-decoded"
    decoded_path.write_bytes(decoded)
    decoded_path.chmod(0o755)

    print("[test] Running decoded binary...")
    after = run_binary(decoded_path)
    assert after == baseline


