import argparse
import logging
import os
import subprocess
import tempfile
from pathlib import Path

from ..core.guards import guard_can_write, require_redteam_mode
from .runtime_decode import RuntimeDecode


def _setup_logging() -> None:
    level = logging.getLevelName(os.getenv("LOG_LEVEL", "INFO").upper())
    logging.basicConfig(
        level=level, format="time=%(asctime)s level=%(levelname)s msg=%(message)s"
    )


def main(argv: list[str] | None = None) -> int:
    _setup_logging()
    parser = argparse.ArgumentParser(
        description="Dropper CLI: decode obfuscated binary at runtime and execute it"
    )
    parser.add_argument("input", help="Path to obfuscated binary to execute")
    parser.add_argument(
        "--no-strings", action="store_true", help="Do not decode Base64 string markers"
    )
    parser.add_argument(
        "--xor", action="store_true", help="Decode XOR packing using DECODE_KEY env var"
    )
    parser.add_argument(
        "--",
        dest="passthrough",
        nargs=argparse.REMAINDER,
        help="Arguments to pass to decoded binary",
    )
    args = parser.parse_args(argv)

    require_redteam_mode()

    data = Path(args.input).read_bytes()

    def key_supplier() -> bytes:
        key = os.getenv("DECODE_KEY", "").encode("utf-8")
        if not key:
            raise RuntimeError("DECODE_KEY must be set when --xor is used")
        return key

    decoder = RuntimeDecode(
        decode_strings=not args.no_strings,
        xor_key_supplier=key_supplier if args.xor else None,
    )
    decoded = decoder.apply(data)

    # Justification: To execute a native binary, we need an OS entrypoint. We write to a
    # secure temporary file, mark executable, run, then delete. This is ephemeral and
    # guarded by ALLOW_ACTIONS.
    guard_can_write()
    with tempfile.NamedTemporaryFile(prefix="rt-evade-", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        tmp.write(decoded)
    try:
        tmp_path.chmod(0o755)
        cmd = [str(tmp_path)] + (args.passthrough or [])
        logging.info("action=exec path=%s args=%s", tmp_path, args.passthrough or [])
        proc = subprocess.run(cmd, check=False)
        return proc.returncode
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            logging.warning("action=cleanup_failed path=%s", tmp_path)


if __name__ == "__main__":
    raise SystemExit(main())
