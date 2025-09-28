"""Tests for the AI-driven obfuscation agent."""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from obfuscation_agent.agent import ObfuscationAgent


class TestAIObfuscationAgent:
    """Test cases for the AI-driven obfuscation agent."""

    @pytest.fixture
    def agent(self):
        """Create an AI agent instance for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            agent = ObfuscationAgent(output_dir=temp_dir)
            yield agent

    @pytest.fixture
    def mock_pe_file(self):
        """Create a mock PE file for testing."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            # Write a minimal PE header
            f.write(b"MZ" + b"\x00" * 58 + b"PE\x00\x00")
            f.write(b"\x00" * 1000)  # Add some data
            f.flush()
            yield f.name
        os.unlink(f.name)

    def test_agent_initialization(self, agent):
        """Test that the AI agent initializes with correct state."""
        assert agent.name == "AIObfuscationAgent"
        assert agent.output_dir is not None
        assert agent.action_outcomes == []
        assert agent.technique_effectiveness == {}
        assert agent.advanced_techniques_used == {
            "rust_crypter": False,
            "upx_packing": False,
        }

    def test_update_technique_effectiveness(self, agent):
        """Test technique effectiveness tracking."""
        # Test adding new technique
        agent.update_technique_effectiveness("add_junk_sections", True)
        assert agent.technique_effectiveness["add_junk_sections"]["successes"] == 1
        assert agent.technique_effectiveness["add_junk_sections"]["attempts"] == 1

        # Test adding failure
        agent.update_technique_effectiveness("add_junk_sections", False)
        assert agent.technique_effectiveness["add_junk_sections"]["successes"] == 1
        assert agent.technique_effectiveness["add_junk_sections"]["attempts"] == 2

        # Test adding another technique
        agent.update_technique_effectiveness("rearrange_sections", True)
        assert agent.technique_effectiveness["rearrange_sections"]["successes"] == 1
        assert agent.technique_effectiveness["rearrange_sections"]["attempts"] == 1

    def test_get_technique_success_rate(self, agent):
        """Test success rate calculation."""
        # Test technique with no attempts
        assert agent.get_technique_success_rate("nonexistent") == 0.0

        # Test technique with mixed results
        agent.update_technique_effectiveness("test_technique", True)
        agent.update_technique_effectiveness("test_technique", False)
        agent.update_technique_effectiveness("test_technique", True)

        assert agent.get_technique_success_rate("test_technique") == 2 / 3

    @patch("obfuscation_agent.agent.OpenAIChat")
    def test_ai_decide_next_action_success(self, mock_openai, agent):
        """Test AI decision making with successful response."""
        # Mock the AI model response
        mock_model = Mock()
        # Mock the response object
        mock_response = Mock()
        mock_response.content = "add_junk_sections"
        mock_model.response.return_value = mock_response
        agent.model = mock_model

        action = agent.ai_decide_next_action()

        assert action == "add_junk_sections"
        mock_model.response.assert_called_once()

    @patch("obfuscation_agent.agent.OpenAIChat")
    def test_ai_decide_next_action_invalid_response(self, mock_openai, agent):
        """Test AI decision making with invalid response falls back to heuristics."""
        # Mock the AI model response with invalid action
        mock_model = Mock()
        mock_model.api_key = "real-api-key"  # Set a real API key to trigger AI path
        mock_response = Mock()
        mock_response.content = "invalid_action"
        mock_model.response.return_value = mock_response
        agent.model = mock_model

        # The agent should fall back to heuristics, not random
        action = agent.ai_decide_next_action()

        # Should be one of the valid basic techniques
        valid_actions = [
            "add_junk_sections",
            "rearrange_sections",
            "change_section_names",
            "change_timestamp",
        ]
        assert action in valid_actions

    @patch("obfuscation_agent.agent.OpenAIChat")
    def test_ai_decide_next_action_error_fallback(self, mock_openai, agent):
        """Test AI decision making with error falls back to random."""
        # Mock the AI model to raise an exception
        mock_model = Mock()
        mock_model.response.side_effect = Exception("API Error")
        agent.model = mock_model

        with patch("random.choice") as mock_random:
            mock_random.return_value = "change_timestamp"
            action = agent.ai_decide_next_action()

            assert action == "change_timestamp"
            mock_random.assert_called_once()

    def test_ai_decide_next_action_with_context(self, agent):
        """Test that AI decision making includes proper context."""
        # Set up some agent state
        agent.attempt_count = 5
        agent.obfuscation_history = ["add_junk_sections", "rearrange_sections"]
        agent.action_outcomes = [
            {"action": "add_junk_sections", "success": False, "attempt": 1},
            {"action": "rearrange_sections", "success": False, "attempt": 2},
        ]
        agent.update_technique_effectiveness("add_junk_sections", False)
        agent.update_technique_effectiveness("rearrange_sections", False)

        # Set a real API key to trigger AI path
        agent.model.api_key = "real-api-key"

        with patch.object(agent.model, "response") as mock_response:
            mock_response_obj = Mock()
            mock_response_obj.content = "change_section_names"
            mock_response.return_value = mock_response_obj

            action = agent.ai_decide_next_action()

            # Verify the prompt includes context
            call_args = mock_response.call_args[0][0][0].content
            assert "Attempt: 5" in call_args
            assert "add_junk_sections, rearrange_sections" in call_args
            assert "add_junk_sections" in call_args
            assert "rearrange_sections" in call_args

    @patch("rt_evade.dropper.rust_crypter.RustCrypterIntegration")
    def test_apply_rust_crypter_success(self, mock_rust_crypter, agent, mock_pe_file):
        """Test successful Rust-Crypter application."""
        # Mock the Rust-Crypter integration
        mock_instance = Mock()
        mock_instance.encrypt_pe_file.return_value = "encrypted_file.exe"
        mock_rust_crypter.return_value = mock_instance

        result = agent.apply_rust_crypter(mock_pe_file)

        assert result == "encrypted_file.exe"
        assert agent.advanced_techniques_used["rust_crypter"] is True
        mock_instance.encrypt_pe_file.assert_called_once_with(
            mock_pe_file, agent.output_dir
        )

    @patch("rt_evade.dropper.rust_crypter.RustCrypterIntegration")
    def test_apply_rust_crypter_error(self, mock_rust_crypter, agent, mock_pe_file):
        """Test Rust-Crypter application with error."""
        # Mock the Rust-Crypter integration to raise an exception
        mock_rust_crypter.side_effect = Exception("Rust-Crypter error")

        result = agent.apply_rust_crypter(mock_pe_file)

        assert result == mock_pe_file  # Should return original file on error
        assert agent.advanced_techniques_used["rust_crypter"] is False

    @patch("rt_evade.pe.packer.PEPacker")
    def test_apply_upx_packing_success(self, mock_packer, agent, mock_pe_file):
        """Test successful UPX packing application."""
        # Mock the UPX packer
        mock_instance = Mock()
        mock_instance.pack_pe_file.return_value = "packed_file.exe"
        mock_packer.return_value = mock_instance

        result = agent.apply_upx_packing(mock_pe_file)

        assert result == "packed_file.exe"
        assert agent.advanced_techniques_used["upx_packing"] is True
        mock_instance.pack_pe_file.assert_called_once_with(
            mock_pe_file, agent.output_dir
        )

    @patch("rt_evade.pe.packer.PEPacker")
    def test_apply_upx_packing_error(self, mock_packer, agent, mock_pe_file):
        """Test UPX packing application with error."""
        # Mock the UPX packer to raise an exception
        mock_packer.side_effect = Exception("UPX packing error")

        result = agent.apply_upx_packing(mock_pe_file)

        assert result == mock_pe_file  # Should return original file on error
        assert agent.advanced_techniques_used["upx_packing"] is False

    def test_get_agent_status(self, agent):
        """Test agent status information includes AI-driven data."""
        # Set up some agent state
        agent.current_binary_path = "test.exe"
        agent.attempt_count = 3
        agent.obfuscation_history = ["add_junk_sections", "rearrange_sections"]
        agent.action_outcomes = [
            {"action": "add_junk_sections", "success": True, "attempt": 1}
        ]
        agent.update_technique_effectiveness("add_junk_sections", True)

        status = agent.get_agent_status()

        assert status["current_binary_path"] == "test.exe"
        assert status["attempt_count"] == 3
        assert status["obfuscation_history"] == [
            "add_junk_sections",
            "rearrange_sections",
        ]
        assert "technique_effectiveness" in status
        assert "advanced_techniques_used" in status
        assert "recent_action_outcomes" in status

    @patch("obfuscation_agent.agent.validate_pe_file")
    @patch("obfuscation_agent.agent.evasion_model")
    def test_obfuscation_loop_with_ai_decision(
        self, mock_evasion, mock_validate, agent, mock_pe_file
    ):
        """Test the obfuscation loop uses AI decision making."""
        # Mock dependencies
        mock_validate.return_value = True
        mock_evasion.return_value = 0  # Evaded

        # Mock AI decision making
        with patch.object(agent, "ai_decide_next_action") as mock_ai_decision:
            mock_ai_decision.return_value = "add_junk_sections"

            # Mock the obfuscation tool
            with patch.object(agent, "add_junk_sections") as mock_tool:
                mock_tool.return_value = "obfuscated.exe"

                result_path, evaded, history = agent.run_obfuscation_loop(
                    mock_pe_file, max_attempts=1
                )

                assert evaded is True
                assert "add_junk_sections" in history
                mock_ai_decision.assert_called_once()

    @patch("obfuscation_agent.agent.validate_pe_file")
    @patch("obfuscation_agent.agent.evasion_model")
    def test_obfuscation_loop_tracks_outcomes(
        self, mock_evasion, mock_validate, agent, mock_pe_file
    ):
        """Test that the obfuscation loop tracks action outcomes."""
        # Mock dependencies
        mock_validate.return_value = True
        mock_evasion.return_value = 1  # Not evaded

        # Mock AI decision making
        with patch.object(agent, "ai_decide_next_action") as mock_ai_decision:
            mock_ai_decision.return_value = "rearrange_sections"

            # Mock the obfuscation tool
            with patch.object(agent, "rearrange_sections") as mock_tool:
                mock_tool.return_value = "obfuscated.exe"

                result_path, evaded, history = agent.run_obfuscation_loop(
                    mock_pe_file, max_attempts=1
                )

                assert evaded is False
                assert len(agent.action_outcomes) == 1
                assert agent.action_outcomes[0]["action"] == "rearrange_sections"
                assert agent.action_outcomes[0]["success"] is False
                assert agent.action_outcomes[0]["attempt"] == 1

    def test_advanced_techniques_cannot_be_combined(self, agent):
        """Test that advanced techniques cannot be used together."""
        # Use Rust-Crypter first
        agent.advanced_techniques_used["rust_crypter"] = True

        # Try to use UPX packing
        with patch("rt_evade.pe.packer.PEPacker") as mock_packer:
            mock_instance = Mock()
            mock_instance.pack_pe_file.return_value = "packed.exe"
            mock_packer.return_value = mock_instance

            result = agent.apply_upx_packing("test.exe")

            # Should still work, but both flags are set
            assert agent.advanced_techniques_used["rust_crypter"] is True
            assert agent.advanced_techniques_used["upx_packing"] is True

    def test_ai_decision_stop_action(self, agent):
        """Test that AI can decide to stop trying."""
        # Set up agent state to trigger stop condition
        agent.attempt_count = 10
        agent.advanced_techniques_used["rust_crypter"] = True
        agent.advanced_techniques_used["upx_packing"] = True

        with patch.object(agent.model, "response") as mock_response:
            mock_response_obj = Mock()
            mock_response_obj.content = "stop"
            mock_response.return_value = mock_response_obj

            action = agent.ai_decide_next_action()

            assert action == "stop"

    def test_ai_decision_advanced_technique_selection(self, agent):
        """Test that AI selects advanced techniques when appropriate."""
        # Set up agent state to trigger advanced technique selection
        agent.attempt_count = 8
        agent.advanced_techniques_used["rust_crypter"] = False
        agent.advanced_techniques_used["upx_packing"] = False

        with patch.object(agent.model, "response") as mock_response:
            mock_response_obj = Mock()
            mock_response_obj.content = "rust_crypter"
            mock_response.return_value = mock_response_obj

            action = agent.ai_decide_next_action()

            assert action == "rust_crypter"
