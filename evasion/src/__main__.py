"""Main entry point for the rt_evade toolkit.

This module provides the command-line interface for the red-team static ML evasion toolkit.
It supports PE obfuscation, dropper functionality, and embedded payload generation.
"""
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
from .rt_evade.dropper.cli import main as dropper_main
from .rt_evade.pe.obfuscator import PEObfuscator, PEObfuscationConfig


def _setup_logging() -> None:
    """Set up logging configuration based on environment variables."""
    level = logging.getLevelName(os.getenv("LOG_LEVEL", "INFO").upper())
    logging.basicConfig(
        level=level, format="time=%(asctime)s level=%(levelname)s msg=%(message)s"
    )


def load_bytes_from_file(path: str) -> bytes:
    """Load binary data from a file.

    Args:
        path: Path to the file to read

    Returns:
        The binary content of the file
    """
    with open(path, "rb") as f:
        return f.read()


def write_bytes_to_file(path: str, data: bytes) -> None:
    """Write binary data to a file.

    Args:
        path: Path where to write the data
        data: Binary data to write
    """
    guard_can_write()
    with open(path, "wb") as f:
        f.write(data)


def build_default_plan(args: argparse.Namespace) -> List[TransformPlan]:
    """Build a list of transformation plans based on command line arguments.

    Args:
        args: Parsed command line arguments

    Returns:
        List of transformation plans to apply
    """
    plans: List[TransformPlan] = []
    if args.pe_obfuscate:
        config = PEObfuscationConfig(
            enable_mimicry=args.pe_mimicry,
            enable_string_obfuscation=args.pe_strings,
            enable_import_inflation=args.pe_imports,
            enable_section_padding=args.pe_padding,
            enable_compression=args.pe_compression,
            enable_code_encryption=args.pe_encryption,
            target_category=args.pe_category,
        )
        obfuscator = PEObfuscator(config)
        plans.append(
            obfuscator.create_obfuscation_plan(b"")
        )  # Will be applied to actual data
    return plans


def _setup_transform_parser(subparsers) -> argparse.ArgumentParser:
    """Set up the transform subcommand parser."""
    parser = subparsers.add_parser(
        "transform",
        help="Apply PE obfuscation transforms to input and optionally write output",
    )
    parser.add_argument("input", help="Path to input PE file")
    parser.add_argument(
        "--output", help="Optional output path (requires ALLOW_ACTIONS=true)"
    )

    # PE obfuscation options
    parser.add_argument(
        "--pe-obfuscate",
        action="store_true",
        default=True,
        help="Apply PE-aware obfuscation (default: True)",
    )
    parser.add_argument(
        "--pe-mimicry",
        action="store_true",
        default=True,
        help="Enable PE mimicry (default: True)",
    )
    parser.add_argument(
        "--pe-strings",
        action="store_true",
        default=True,
        help="Enable PE string obfuscation (default: True)",
    )
    parser.add_argument(
        "--pe-imports",
        action="store_true",
        default=True,
        help="Enable PE import inflation (default: True)",
    )
    parser.add_argument(
        "--pe-padding",
        action="store_true",
        default=True,
        help="Enable PE section padding (default: True)",
    )
    parser.add_argument(
        "--pe-compression",
        action="store_true",
        default=True,
        help="Enable PE compression (default: True)",
    )
    parser.add_argument(
        "--pe-encryption",
        action="store_true",
        default=True,
        help="Enable PE encryption (default: True)",
    )
    parser.add_argument(
        "--pe-category",
        choices=["system_utility", "web_browser", "office_app"],
        help="Target software category for mimicry",
    )
    return parser


def _setup_dropper_parser(subparsers) -> argparse.ArgumentParser:
    """Set up the dropper subcommand parser."""
    parser = subparsers.add_parser(
        "dropper", help="Decode obfuscated binary and execute it (runtime)"
    )
    parser.add_argument("input", help="Path to obfuscated binary to execute")
    parser.add_argument("--no-strings", action="store_true")
    parser.add_argument("--xor", action="store_true")
    parser.add_argument("--", dest="passthrough", nargs=argparse.REMAINDER)
    return parser


def _setup_embed_parser(subparsers) -> argparse.ArgumentParser:
    """Set up the embed subcommand parser."""
    parser = subparsers.add_parser(
        "embed", help="Embed obfuscated PE into Python module for standalone dropper"
    )
    parser.add_argument("input", help="Path to obfuscated PE binary")
    parser.add_argument(
        "--output", help="Output Python module path (default: embedded_payload.py)"
    )
    parser.add_argument(
        "--embed-key",
        action="store_true",
        help="Embed DECODE_KEY into payload module (no env needed at runtime)",
    )
    parser.add_argument(
        "--base64-strings", action="store_true", help="Apply Base64 string obfuscation"
    )
    parser.add_argument(
        "--xor-pack",
        action="store_true",
        help="Apply XOR packing (requires DECODE_KEY)",
    )
    return parser


def _handle_dropper_command(args) -> int:
    """Handle the dropper subcommand."""
    return dropper_main(
        [args.input]
        + (["--no-strings"] if args.no_strings else [])
        + (["--xor"] if args.xor else [])
        + (["--"] + (args.passthrough or []) if args.passthrough else [])
    )


def _handle_embed_command(args) -> int:
    """Handle the embed subcommand."""
    original = load_bytes_from_file(args.input)

    # Apply PE obfuscation
    pipeline = TransformPipeline()
    if args.pe_obfuscate:
        config = PEObfuscationConfig(
            enable_mimicry=args.pe_mimicry,
            enable_string_obfuscation=args.pe_strings,
            enable_import_inflation=args.pe_imports,
            enable_section_padding=args.pe_padding,
            enable_compression=args.pe_compression,
            enable_code_encryption=args.pe_encryption,
            target_category=args.pe_category,
        )
        obfuscator = PEObfuscator(config)
        pipeline.add(obfuscator.create_obfuscation_plan(original))

    obfuscated = pipeline.apply_all(original)

    # Generate embedded module
    output_path = Path(args.output or "embedded_payload.py")
    module_path, payload_hash = generate_embedded_payload_module(
        obfuscated, output_path
    )

    logging.info("action=embed_complete module=%s hash=%s", module_path, payload_hash)
    return 0


def _handle_transform_command(args) -> int:
    """Handle the transform subcommand."""
    original = load_bytes_from_file(args.input)

    pipeline = TransformPipeline()
    for plan in build_default_plan(args):
        pipeline.add(plan)

    transformed = pipeline.apply_all(original)

    if getattr(args, "output", None):
        write_bytes_to_file(args.output, transformed)
        logging.info(
            "action=write_output path=%s size=%d", args.output, len(transformed)
        )
    else:
        logging.info(
            "action=dry_run size=%d note=use --output and ALLOW_ACTIONS=true to write",
            len(transformed),
        )

    return 0


def main(argv: List[str] | None = None) -> int:
    """Main entry point for the rt_evade toolkit.

    Args:
        argv: Command line arguments (for testing)

    Returns:
        Exit code (0 for success)
    """
    _setup_logging()
    parser = argparse.ArgumentParser(
        description="Red-team static ML evasion toolkit (binary-in, binary-out)"
    )
    sub = parser.add_subparsers(dest="cmd", required=False)

    # Set up subcommands
    _setup_transform_parser(sub)
    _setup_dropper_parser(sub)
    _setup_embed_parser(sub)

    parser.add_argument(
        "--output", help="Optional output path (requires ALLOW_ACTIONS=true)"
    )
    args = parser.parse_args(argv)

    require_redteam_mode()

    if args.cmd == "dropper":
        return _handle_dropper_command(args)

    if args.cmd == "embed":
        return _handle_embed_command(args)

    # Default: transform
    if args.cmd != "transform":
        # Create a new parser for default transform command
        parser = argparse.ArgumentParser()
        parser.add_argument("input", help="Path to input PE file")
        parser.add_argument(
            "--output", help="Optional output path (requires ALLOW_ACTIONS=true)"
        )
        # Add all PE obfuscation options with defaults
        parser.add_argument("--pe-obfuscate", action="store_true", default=True)
        parser.add_argument("--pe-mimicry", action="store_true", default=True)
        parser.add_argument("--pe-strings", action="store_true", default=True)
        parser.add_argument("--pe-imports", action="store_true", default=True)
        parser.add_argument("--pe-padding", action="store_true", default=True)
        parser.add_argument("--pe-compression", action="store_true", default=True)
        parser.add_argument("--pe-encryption", action="store_true", default=True)
        parser.add_argument(
            "--pe-category", choices=["system_utility", "web_browser", "office_app"]
        )
        args = parser.parse_args(argv or [])
    return _handle_transform_command(args)


if __name__ == "__main__":
    sys.exit(main())
