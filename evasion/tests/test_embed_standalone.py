import importlib
import os
import sys
from pathlib import Path

import pytest

from rt_evade.core.pipeline import TransformPipeline
from rt_evade.obfuscation.base64_strings import Base64StringObfuscator
from rt_evade.obfuscation.xor_packer import XorPacker
from rt_evade.dropper.embed import generate_embedded_payload_module


@pytest.mark.skipif(os.name == "nt", reason="POSIX exec required")
def test_embed_and_standalone_executes_payload(tmp_path: Path, hello_bin: Path) -> None:
    # No environment variables required at runtime

    # Obfuscate test binary
    original = hello_bin.read_bytes()
    pipeline = TransformPipeline()
    pipeline.add(Base64StringObfuscator().as_plan())
    pipeline.add(XorPacker(key=b"embed-key").as_plan())
    obf = pipeline.apply_all(original)

    # Generate embedded payload module in temp dir and import it
    module_path = tmp_path / "embedded_payload.py"
    # Build-time guards require explicit enablement
    os.environ["REDTEAM_MODE"] = "true"
    os.environ["ALLOW_ACTIONS"] = "true"
    generate_embedded_payload_module(obf, module_path, embedded_key=b"embed-key")

    sys.path.insert(0, str(tmp_path))
    try:
        # Import standalone dropper and run
        standalone = importlib.import_module("rt_evade.dropper.standalone")
        rc = standalone.main()
        assert rc == 0
    finally:
        sys.path = [p for p in sys.path if p != str(tmp_path)]

