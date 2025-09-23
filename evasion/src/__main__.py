import argparse
import logging
import os
import sys
from typing import List

from .rt_evade.core.guards import require_redteam_mode, guard_can_write
from .rt_evade.core.pipeline import TransformPipeline
from .rt_evade.core.transform import TransformPlan
from .rt_evade.obfuscation.base64_strings import Base64StringObfuscator
from .rt_evade.obfuscation.xor_packer import XorPacker


def _setup_logging() -> None:
    level = logging.getLevelName(os.getenv("LOG_LEVEL", "INFO").upper())
    logging.basicConfig(level=level, format="time=%(asctime)s level=%(levelname)s msg=%(message)s")


def load_bytes_from_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write_bytes_to_file(path: str, data: bytes) -> None:
    guard_can_write()
    with open(path, "wb") as f:
        f.write(data)


def build_default_plan(args: argparse.Namespace) -> List[TransformPlan]:
    plans: List[TransformPlan] = []
    if args.base64_strings:
        plans.append(Base64StringObfuscator().as_plan())
    if args.xor_pack:
        key_env = os.getenv("DECODE_KEY", "")
        if not key_env:
            raise RuntimeError("DECODE_KEY env var must be set when --xor-pack is enabled")
        plans.append(XorPacker(key=key_env.encode("utf-8")).as_plan())
    return plans


def main(argv: List[str] | None = None) -> int:
    _setup_logging()
    parser = argparse.ArgumentParser(description="Red-team static ML evasion toolkit (binary-in, binary-out)")
    parser.add_argument("input", help="Path to input binary")
    parser.add_argument("--output", help="Optional output path (requires ALLOW_ACTIONS=true)")
    parser.add_argument("--base64-strings", action="store_true", help="Apply Base64 string obfuscation layer")
    parser.add_argument("--xor-pack", action="store_true", help="Apply XOR packing layer (requires DECODE_KEY)")
    args = parser.parse_args(argv)

    require_redteam_mode()

    original = load_bytes_from_file(args.input)

    pipeline = TransformPipeline()
    for plan in build_default_plan(args):
        pipeline.add(plan)

    transformed = pipeline.apply_all(original)

    if args.output:
        write_bytes_to_file(args.output, transformed)
        logging.info("action=write_output path=%s size=%d", args.output, len(transformed))
    else:
        logging.info("action=dry_run size=%d note=use --output and ALLOW_ACTIONS=true to write", len(transformed))

    return 0


if __name__ == "__main__":
    sys.exit(main())

