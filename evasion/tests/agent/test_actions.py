"""Unit tests for individual agent actions.

Each action is tested in isolation with dependencies mocked to avoid
performing real PE manipulations or invoking external tools.
"""

import os
import tempfile
import subprocess
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


def test_revert_checkpoint_action(agent_tmpdir, temp_binary):
    """Test revert_checkpoint action."""
    agent = ObfuscationAgent(output_dir=agent_tmpdir)

    # Create intermediate-files directory
    intermediate_dir = os.path.join(agent_tmpdir, "intermediate-files")
    os.makedirs(intermediate_dir, exist_ok=True)

    # Create first checkpoint with original content
    from obfuscation_agent.state_manager import save_checkpoint

    checkpoint1 = save_checkpoint(
        temp_binary, output_dir=agent_tmpdir, base_name=os.path.basename(temp_binary)
    )

    # Modify the original file to simulate advanced technique result
    with open(temp_binary, "wb") as f:
        f.write(b"advanced_technique_result")

    # Create second checkpoint (this simulates the checkpoint saved after advanced technique)
    checkpoint2 = save_checkpoint(
        temp_binary, output_dir=agent_tmpdir, base_name=os.path.basename(temp_binary)
    )

    # Verify current state
    with open(temp_binary, "rb") as f:
        current_content = f.read()
    assert current_content == b"advanced_technique_result"

    # Test revert_checkpoint (should revert to checkpoint1, skipping checkpoint2)
    result = agent.revert_checkpoint(temp_binary, temp_binary)

    # Verify the result is a different file path (reverted state)
    assert result != temp_binary
    assert result.endswith(".exe")
    assert intermediate_dir in result

    # Verify the reverted file has original content
    with open(result, "rb") as f:
        content = f.read()
    assert content == b"dummy pe content"  # Original content

    # Cleanup
    for checkpoint in [checkpoint1, checkpoint2]:
        if os.path.exists(checkpoint):
            os.unlink(checkpoint)
    if os.path.exists(result):
        os.unlink(result)


def test_revert_checkpoint_no_checkpoints(agent_tmpdir, temp_binary):
    """Test revert_checkpoint when no checkpoints exist."""
    agent = ObfuscationAgent(output_dir=agent_tmpdir)

    # Test revert_checkpoint with no checkpoints
    result = agent.revert_checkpoint(temp_binary, temp_binary)

    # Should return the same file path
    assert result == temp_binary


def test_revert_checkpoint_insufficient_checkpoints(agent_tmpdir, temp_binary):
    """Test revert_checkpoint when there's only one checkpoint."""
    agent = ObfuscationAgent(output_dir=agent_tmpdir)

    # Create only one checkpoint
    from obfuscation_agent.state_manager import save_checkpoint

    checkpoint_path = save_checkpoint(
        temp_binary, output_dir=agent_tmpdir, base_name=os.path.basename(temp_binary)
    )

    # Test revert_checkpoint with only one checkpoint
    result = agent.revert_checkpoint(temp_binary, temp_binary)

    # Should return the same file path (not enough checkpoints to revert)
    assert result == temp_binary

    # Cleanup
    if os.path.exists(checkpoint_path):
        os.unlink(checkpoint_path)


def test_apply_rust_dropper_action(agent_tmpdir, temp_binary):
    """Test apply_rust_dropper action."""
    agent = ObfuscationAgent(output_dir=agent_tmpdir)

    # Mock the subprocess call and file operations
    with patch("subprocess.run") as mock_run, patch("shutil.copy2") as mock_copy, patch(
        "shutil.rmtree"
    ) as mock_rmtree, patch("pathlib.Path.exists") as mock_exists, patch(
        "pathlib.Path.mkdir"
    ) as mock_mkdir:

        # Configure mocks
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""
        mock_exists.return_value = True

        # Mock the generated dropper file
        expected_dropper = os.path.join(
            agent_tmpdir, "intermediate-files", os.path.basename(temp_binary)
        )

        result = agent.apply_rust_dropper(temp_binary)

        # Verify subprocess was called with correct arguments
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0][0] == "cargo"
        assert call_args[0][0][1] == "run"
        assert call_args[0][0][2] == "--bin"
        assert call_args[0][0][3] == "build-droppers"
        assert call_args[0][0][4] == "stealth"

        # Verify advanced technique was marked as used
        assert agent.advanced_techniques_used["rust_dropper"] is True


def test_apply_rust_dropper_subprocess_failure(agent_tmpdir, temp_binary):
    """Test apply_rust_dropper when subprocess fails."""
    agent = ObfuscationAgent(output_dir=agent_tmpdir)

    with patch("subprocess.run") as mock_run, patch("shutil.copy2") as mock_copy, patch(
        "pathlib.Path.exists"
    ) as mock_exists, patch("pathlib.Path.mkdir") as mock_mkdir:

        # Configure mocks for failure
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "Build failed"
        mock_exists.return_value = True

        result = agent.apply_rust_dropper(temp_binary)

        # Should return original file path on failure
        assert result == temp_binary
        # Advanced technique should not be marked as used on failure
        assert agent.advanced_techniques_used["rust_dropper"] is False


def test_apply_rust_dropper_timeout(agent_tmpdir, temp_binary):
    """Test apply_rust_dropper when subprocess times out."""
    agent = ObfuscationAgent(output_dir=agent_tmpdir)

    with patch("subprocess.run") as mock_run, patch("shutil.copy2") as mock_copy, patch(
        "pathlib.Path.exists"
    ) as mock_exists, patch("pathlib.Path.mkdir") as mock_mkdir:

        # Configure mocks for timeout
        mock_run.side_effect = subprocess.TimeoutExpired("cargo", 300)
        mock_exists.return_value = True

        result = agent.apply_rust_dropper(temp_binary)

        # Should return original file path on timeout
        assert result == temp_binary
        # Advanced technique should not be marked as used on timeout
        assert agent.advanced_techniques_used["rust_dropper"] is False


# UPX packing removed from workflow; no test needed
