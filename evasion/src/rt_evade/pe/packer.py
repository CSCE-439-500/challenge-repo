"""PE packer module for external packers (e.g., UPX).

This module isolates external packing tools into a dedicated step, separate
from in-memory compression. It adheres to red-team guardrails and cleans up
temporary artifacts.
"""

import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Dict, Any, List, Optional

from ..core.guards import require_redteam_mode, guard_can_write

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PackerConfig:
    """Configuration for external packing.

    Attributes:
        enable_packer: Whether to run the packer step.
        packer_name: Name of the external packer binary (e.g., "upx").
        packer_args: Additional CLI args for the packer, e.g., ["--best"].
    """

    enable_packer: bool = False
    packer_name: str = "upx"
    packer_args: Optional[List[str]] = None


class PEPacker:
    """PE external packer step (UPX and future packers)."""

    def __init__(self, config: Optional[PackerConfig] = None) -> None:
        require_redteam_mode()
        self.config = config or PackerConfig()
        logger.info("action=pe_packer_initialized config=%s", self.config)

    def pack_pe(self, pe_data: bytes) -> bytes:
        """Pack the PE using the configured external packer.

        Returns the packed bytes if successful and smaller; otherwise returns
        the original bytes.
        """
        if not self.config.enable_packer:
            logger.info("action=packer_disabled")
            return pe_data

        if self.config.packer_name.lower() == "upx":
            return self._pack_with_upx(pe_data)

        logger.warning(
            "action=unknown_packer packer=%s skipping", self.config.packer_name
        )
        return pe_data

    def _pack_with_upx(self, pe_data: bytes) -> bytes:
        require_redteam_mode()
        guard_can_write()

        input_tmp = None
        output_path = None
        try:
            input_tmp = tempfile.NamedTemporaryFile(
                prefix="rt_upx_in_", suffix=".exe", delete=False
            )
            input_path = input_tmp.name
            fd, tmp_out_path = tempfile.mkstemp(prefix="rt_upx_out_", suffix=".exe")
            os.close(fd)
            os.unlink(tmp_out_path)
            output_path = tmp_out_path

            input_tmp.write(pe_data)
            input_tmp.flush()
            input_tmp.close()

            args = [self.config.packer_name]
            # Allow env override of args
            upx_args_env = os.getenv("UPX_ARGS")
            packer_args = list(self.config.packer_args or [])
            if upx_args_env:
                packer_args = upx_args_env.split()
            if packer_args:
                args.extend(packer_args)
            if "-f" not in args and "--force" not in args:
                args.append("-f")
            args.extend(["-o", output_path, input_path])

            logger.info("action=packer_start packer=upx cmd=%s", " ".join(args))
            completed = subprocess.run(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
            )
            if completed.returncode != 0:
                logger.warning(
                    "action=packer_failed packer=upx code=%d stderr=%s",
                    completed.returncode,
                    completed.stderr.decode(errors="ignore"),
                )
                return pe_data

            with open(output_path, "rb") as f_out:
                packed = f_out.read()

            if len(packed) >= len(pe_data):
                logger.info(
                    "action=packer_no_gain packer=upx original=%d packed=%d",
                    len(pe_data),
                    len(packed),
                )
                return pe_data

            logger.info(
                "action=packer_applied packer=upx original_size=%d packed_size=%d",
                len(pe_data),
                len(packed),
            )
            return packed
        finally:
            for tmp in (
                input_tmp.name if input_tmp else None,
                output_path,
            ):
                if tmp and os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        logger.debug("action=tempfile_cleanup_failed path=%s", tmp)

    def get_packer_report(self, original: bytes, result: bytes) -> Dict[str, Any]:
        """Return a simple packing report."""
        return {
            "enabled": self.config.enable_packer,
            "name": self.config.packer_name,
            "original_size": len(original),
            "result_size": len(result),
            "size_change": len(result) - len(original),
        }


