"""Tests for PE packer functionality (UPX step)."""

import os
from unittest.mock import patch

import pytest

from rt_evade.pe.packer import PEPacker, PackerConfig


@pytest.fixture
def mock_pe_data():
    data = bytearray(1024)
    data[0:2] = b"MZ"
    data[60:64] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"
    return bytes(data)


class TestPEPacker:
    def test_packer_disabled_returns_original(self, mock_pe_data):
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}, clear=True):
            packer = PEPacker(PackerConfig(enable_packer=False))
            out = packer.pack_pe(mock_pe_data)
            assert out == mock_pe_data

    def test_upx_success(self, mock_pe_data):
        with patch.dict(
            os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}, clear=True
        ):

            def fake_run(args, stdout=None, stderr=None, check=None):  # noqa: ARG001
                out_index = args.index("-o") + 1
                output_path = args[out_index]
                with open(output_path, "wb") as f:
                    f.write(b"packed" * 100)

                class R:
                    returncode = 0
                    stdout = b"ok"
                    stderr = b""

                return R()

            packer = PEPacker(
                PackerConfig(
                    enable_packer=True, packer_name="upx", packer_args=["--best"]
                )
            )
            with patch("rt_evade.pe.packer.subprocess.run", side_effect=fake_run):
                out = packer.pack_pe(mock_pe_data + b"X" * 5000)
            assert isinstance(out, bytes)
            assert len(out) < len(mock_pe_data) + 5000

    def test_upx_failure_returns_original(self, mock_pe_data):
        with patch.dict(
            os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}, clear=True
        ):

            def fake_run_fail(
                args, stdout=None, stderr=None, check=None
            ):  # noqa: ARG001
                class R:
                    returncode = 1
                    stdout = b""
                    stderr = b"err"

                return R()

            packer = PEPacker(PackerConfig(enable_packer=True, packer_name="upx"))
            with patch("rt_evade.pe.packer.subprocess.run", side_effect=fake_run_fail):
                out = packer.pack_pe(mock_pe_data + b"Y" * 5000)
            assert out.startswith(b"MZ")

    def test_upx_requires_allow_actions(self, mock_pe_data):
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}, clear=True):
            packer = PEPacker(PackerConfig(enable_packer=True, packer_name="upx"))
            with pytest.raises(PermissionError):
                packer.pack_pe(mock_pe_data + b"Z" * 5000)
