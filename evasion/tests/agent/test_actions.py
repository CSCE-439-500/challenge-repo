"""Unit tests for individual agent actions.

Each action is tested in isolation with dependencies mocked to avoid
performing real PE manipulations or invoking external tools.
"""

import os
import tempfile
from unittest.mock import patch, Mock

import pytest

from obfuscation_agent import ObfuscationAgent


@pytest.fixture
def temp_binary():
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(b"dummy pe content")
        path = f.name
    try:
        yield path
    finally:
        if os.path.exists(path):
            os.unlink(path)


@pytest.fixture
def agent_tmpdir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def test_add_junk_sections_action(agent_tmpdir, temp_binary):
    agent = ObfuscationAgent(output_dir=agent_tmpdir)
    expected = os.path.join(
        agent_tmpdir, "intermediate-files", os.path.basename(temp_binary)
    )

    with patch("obfuscation_agent.agent.add_junk_sections", return_value=expected) as m:
        result = agent.add_junk_sections(temp_binary)
        m.assert_called_once_with(temp_binary, agent_tmpdir)
        assert result == expected


def test_rearrange_sections_action(agent_tmpdir, temp_binary):
    agent = ObfuscationAgent(output_dir=agent_tmpdir)
    expected = os.path.join(
        agent_tmpdir, "intermediate-files", os.path.basename(temp_binary)
    )

    with patch(
        "obfuscation_agent.agent.rearrange_sections", return_value=expected
    ) as m:
        result = agent.rearrange_sections(temp_binary)
        m.assert_called_once_with(temp_binary, agent_tmpdir)
        assert result == expected


def test_change_section_names_action(agent_tmpdir, temp_binary):
    agent = ObfuscationAgent(output_dir=agent_tmpdir)
    expected = os.path.join(
        agent_tmpdir, "intermediate-files", os.path.basename(temp_binary)
    )

    with patch(
        "obfuscation_agent.agent.change_section_names", return_value=expected
    ) as m:
        result = agent.change_section_names(temp_binary)
        m.assert_called_once_with(temp_binary, agent_tmpdir)
        assert result == expected


def test_change_timestamp_action(agent_tmpdir, temp_binary):
    agent = ObfuscationAgent(output_dir=agent_tmpdir)
    expected = os.path.join(
        agent_tmpdir, "intermediate-files", os.path.basename(temp_binary)
    )

    with patch("obfuscation_agent.agent.change_timestamp", return_value=expected) as m:
        result = agent.change_timestamp(temp_binary)
        m.assert_called_once_with(temp_binary, agent_tmpdir)
        assert result == expected


def test_apply_rust_crypter_action(agent_tmpdir, temp_binary):
    agent = ObfuscationAgent(output_dir=agent_tmpdir)
    out_path = os.path.join(
        agent_tmpdir,
        "intermediate-files",
        os.path.basename(temp_binary) + "_rust_stub.exe",
    )

    class FakeRustCrypter:
        def create_encrypted_payload(self, pe_bytes, output_path=None):
            assert isinstance(pe_bytes, (bytes, bytearray))
            assert str(output_path).endswith("_rust_stub.exe")
            return output_path

    with patch(
        "rt_evade.dropper.rust_crypter.RustCrypterIntegration",
        return_value=FakeRustCrypter(),
    ):
        result = agent.apply_rust_crypter(temp_binary)
        assert result.endswith("_rust_stub.exe")


# UPX packing removed from workflow; no test needed
