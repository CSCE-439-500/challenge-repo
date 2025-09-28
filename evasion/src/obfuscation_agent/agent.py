"""Agno agent implementation for automated binary obfuscation.

This module implements the ObfuscationAgent using the Agno framework
to autonomously apply obfuscation techniques until evasion is achieved.
"""

import random
import logging
import json
import os
from typing import List, Tuple, Optional, Dict, Any
from dotenv import load_dotenv

from agno.agent import Agent
from agno.tools import tool
from agno.models.openai import OpenAIChat
from agno.models.message import Message

# Load environment variables from .env file
load_dotenv()

from .obfuscation_tools import (
    add_junk_sections,
    rearrange_sections,
    change_section_names,
    change_timestamp,
    validate_pe_file,
)
from .state_manager import (
    save_checkpoint,
    revert_to_checkpoint,
    cleanup_old_checkpoints,
)
from .evasion_model import evasion_model

# Removed REDTEAM_MODE requirement

# Advanced technique imports (will be imported when needed to avoid circular imports)

logger = logging.getLogger(__name__)


class ObfuscationAgent(Agent):
    """Agent for automated binary obfuscation using Agno framework.

    This agent applies various obfuscation techniques to binary files
    with the goal of evading detection by a classification model.
    """

    def __init__(self, output_dir: str = None, **kwargs):
        """Initialize the ObfuscationAgent.

        Args:
            output_dir: Directory to save obfuscated files
            **kwargs: Additional arguments passed to parent Agent class
        """
        # Set default values for agent configuration
        kwargs.setdefault("name", "AIObfuscationAgent")
        kwargs.setdefault(
            "description",
            "This AI agent is designed to intelligently apply obfuscation techniques to a binary file "
            "with the goal of evading a classification model. It learns from previous actions, "
            "tracks patterns of success/failure, and makes intelligent decisions about when to apply "
            "advanced techniques like Rust-Crypter or UPX packing.",
        )

        # Initialize OpenAI model with API key from environment
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.warning(
                "OPENAI_API_KEY not found in environment variables. AI features will be limited."
            )
            api_key = "dummy-key"  # Fallback for testing

        kwargs.setdefault("model", OpenAIChat(id="gpt-4o", api_key=api_key))

        super().__init__(**kwargs)

        # Agent state
        self.current_binary_path = None
        self.obfuscation_history = []
        self.attempt_count = 0
        self.output_dir = output_dir

        # AI-driven state tracking
        self.action_outcomes = []  # Track what worked/didn't work
        self.technique_effectiveness = {}  # Track success rates per technique
        self.advanced_techniques_used = {"rust_crypter": False, "upx_packing": False}

        logger.info("AIObfuscationAgent initialized")

    def _copy_final_file(self, current_file: str, initial_file: str) -> str:
        """Copy the final successful file to the main output directory.

        Args:
            current_file: Path to the current obfuscated file
            initial_file: Path to the initial input file

        Returns:
            Path to the final file in the main output directory
        """
        if not self.output_dir:
            return current_file

        # Get the base name from the initial file
        initial_name = os.path.basename(initial_file)
        name, ext = os.path.splitext(initial_name)

        # Create the final file path
        final_path = os.path.join(self.output_dir, f"{name}{ext}")

        # Copy the file
        import shutil

        shutil.copy2(current_file, final_path)

        logger.info(f"Final obfuscated file saved to: {final_path}")
        return final_path

    def add_junk_sections(self, filepath: str) -> str:
        """Adds a new, empty section to the PE header of the binary.

        Args:
            filepath: Path to the binary file to modify

        Returns:
            Path to the modified binary file
        """
        logger.info(f"Applying add_junk_sections to {filepath}")
        result = add_junk_sections(filepath, self.output_dir)
        logger.info(f"add_junk_sections completed. Result: {result}")
        return result

    def rearrange_sections(self, filepath: str) -> str:
        """Changes the order of existing sections in the PE file.

        Args:
            filepath: Path to the binary file to modify

        Returns:
            Path to the modified binary file
        """
        logger.info(f"Applying rearrange_sections to {filepath}")
        result = rearrange_sections(filepath, self.output_dir)
        logger.info(f"rearrange_sections completed. Result: {result}")
        return result

    def change_section_names(self, filepath: str) -> str:
        """Renames sections (e.g., from .text to .code) in the PE file.

        Args:
            filepath: Path to the binary file to modify

        Returns:
            Path to the modified binary file
        """
        logger.info(f"Applying change_section_names to {filepath}")
        result = change_section_names(filepath, self.output_dir)
        logger.info(f"change_section_names completed. Result: {result}")
        return result

    def change_timestamp(self, filepath: str) -> str:
        """Modifies the PE file's timestamp.

        Args:
            filepath: Path to the binary file to modify

        Returns:
            Path to the modified binary file
        """
        logger.info(f"Applying change_timestamp to {filepath}")
        result = change_timestamp(filepath, self.output_dir)
        logger.info(f"change_timestamp completed. Result: {result}")
        return result

    def test_evasion(self, filepath: str) -> int:
        """Tests the binary against the evasion model.

        Args:
            filepath: Path to the binary file to test

        Returns:
            0 if evaded (not detected), 1 if detected
        """
        try:
            logger.info(f"Testing evasion for {filepath}")
            result = evasion_model(filepath)
            status = "EVADED" if result == 0 else "DETECTED"
            logger.info(f"Evasion test result: {status}")
            return result
        except Exception as e:
            logger.error(f"Error testing evasion: {e}")
            return 1

    def update_technique_effectiveness(self, technique: str, success: bool):
        """Update the effectiveness tracking for a technique.

        Args:
            technique: Name of the obfuscation technique
            success: Whether the technique led to evasion
        """
        if technique not in self.technique_effectiveness:
            self.technique_effectiveness[technique] = {"successes": 0, "attempts": 0}

        self.technique_effectiveness[technique]["attempts"] += 1
        if success:
            self.technique_effectiveness[technique]["successes"] += 1

    def get_technique_success_rate(self, technique: str) -> float:
        """Get the success rate for a specific technique.

        Args:
            technique: Name of the obfuscation technique

        Returns:
            Success rate as a float between 0.0 and 1.0
        """
        if technique not in self.technique_effectiveness:
            return 0.0

        stats = self.technique_effectiveness[technique]
        if stats["attempts"] == 0:
            return 0.0

        return stats["successes"] / stats["attempts"]

    def ai_decide_next_action(self) -> str:
        """Use AI to decide the next obfuscation action based on history and context.

        Returns:
            Name of the next action to take
        """
        # Prepare context for AI
        context = {
            "attempt_count": self.attempt_count,
            "obfuscation_history": self.obfuscation_history,
            "technique_effectiveness": self.technique_effectiveness,
            "advanced_techniques_used": self.advanced_techniques_used,
            "action_outcomes": self.action_outcomes[-5:],  # Last 5 actions
        }

        # Create prompt for AI
        prompt = f"""
You are an AI agent specialized in binary obfuscation for evasion. Based on the current context, decide the next action to take.

Current Context:
- Attempt: {self.attempt_count}
- Previous actions: {', '.join(self.obfuscation_history) if self.obfuscation_history else 'None'}
- Technique effectiveness: {json.dumps(self.technique_effectiveness, indent=2)}
- Advanced techniques used: {json.dumps(self.advanced_techniques_used, indent=2)}
- Recent outcomes: {self.action_outcomes[-5:] if self.action_outcomes else 'None'}

Available Actions:
1. Basic obfuscation techniques:
   - add_junk_sections: Add random junk data sections
   - rearrange_sections: Randomly reorder PE sections
   - change_section_names: Rename sections to appear benign
   - change_timestamp: Modify PE timestamp

2. Advanced techniques (use only once each, cannot combine):
   - rust_crypter: Apply Rust-Crypter encryption (if not used)
   - upx_packing: Apply UPX packing (if not used)

3. Special actions:
   - stop: Stop trying if enough attempts made

Rules:
- If attempt_count >= 8 and neither advanced technique used, choose rust_crypter or upx_packing
- If both advanced techniques used, choose stop
- Prefer techniques with higher success rates
- Avoid repeating the same technique consecutively
- Consider the pattern of recent failures

Respond with ONLY the action name (e.g., "add_junk_sections", "rust_crypter", "stop").
"""

        try:
            # Try to use the AI model first
            if self.model.api_key and self.model.api_key != "dummy-key":
                # Create messages for the AI model
                messages = [Message(role="user", content=prompt)]

                # Use the AI model to decide
                response = self.model.response(messages)
                action = response.content.strip().lower()

                # Validate the action
                valid_actions = [
                    "add_junk_sections",
                    "rearrange_sections",
                    "change_section_names",
                    "change_timestamp",
                    "rust_crypter",
                    "upx_packing",
                    "stop",
                ]

                if action in valid_actions:
                    logger.info(f"AI decided next action: {action}")
                    return action
                else:
                    logger.warning(
                        f"AI returned invalid action '{action}', falling back to heuristics"
                    )
            else:
                logger.info("No valid API key, using intelligent heuristics")

            # Fallback to intelligent heuristics
            # Check if we should use advanced techniques
            if self.attempt_count >= 8 and not any(
                self.advanced_techniques_used.values()
            ):
                # Choose between Rust-Crypter and UPX packing
                if not self.advanced_techniques_used["rust_crypter"]:
                    logger.info(
                        "Heuristics decided next action: rust_crypter (advanced technique)"
                    )
                    return "rust_crypter"
                elif not self.advanced_techniques_used["upx_packing"]:
                    logger.info(
                        "Heuristics decided next action: upx_packing (advanced technique)"
                    )
                    return "upx_packing"

            # Check if we should stop
            if all(self.advanced_techniques_used.values()) and self.attempt_count >= 10:
                logger.info(
                    "Heuristics decided next action: stop (max attempts with advanced techniques)"
                )
                return "stop"

            # Use technique effectiveness to guide selection
            available_basic_techniques = [
                "add_junk_sections",
                "rearrange_sections",
                "change_section_names",
                "change_timestamp",
            ]

            # Avoid repeating the last technique
            if self.obfuscation_history:
                last_technique = self.obfuscation_history[-1]
                if last_technique in available_basic_techniques:
                    available_basic_techniques.remove(last_technique)

            # If no techniques available, use all
            if not available_basic_techniques:
                available_basic_techniques = [
                    "add_junk_sections",
                    "rearrange_sections",
                    "change_section_names",
                    "change_timestamp",
                ]

            # Choose technique based on success rate (prefer higher success rates)
            technique_scores = []
            for technique in available_basic_techniques:
                success_rate = self.get_technique_success_rate(technique)
                # Add some randomness to avoid always picking the same technique
                score = success_rate + random.uniform(0, 0.3)
                technique_scores.append((technique, score))

            # Sort by score and pick the best one
            technique_scores.sort(key=lambda x: x[1], reverse=True)
            selected_technique = technique_scores[0][0]

            logger.info(
                f"Heuristics decided next action: {selected_technique} (based on effectiveness: {self.get_technique_success_rate(selected_technique):.2f})"
            )
            return selected_technique

        except Exception as e:
            logger.error(
                f"Error in AI decision making: {e}, falling back to random selection"
            )
            return random.choice(
                [
                    "add_junk_sections",
                    "rearrange_sections",
                    "change_section_names",
                    "change_timestamp",
                ]
            )

    def apply_rust_crypter(self, filepath: str) -> str:
        """Apply Rust-Crypter encryption to the binary.

        Args:
            filepath: Path to the binary file to encrypt

        Returns:
            Path to the encrypted binary file
        """
        try:
            logger.info(f"Applying Rust-Crypter encryption to {filepath}")

            # Import Rust-Crypter integration
            from rt_evade.dropper.rust_crypter import RustCrypterIntegration

            # Create Rust-Crypter instance
            rust_crypter = RustCrypterIntegration()

            # Encrypt the file
            encrypted_path = rust_crypter.encrypt_pe_file(filepath, self.output_dir)

            self.advanced_techniques_used["rust_crypter"] = True
            logger.info(f"Rust-Crypter encryption completed: {encrypted_path}")
            return encrypted_path

        except Exception as e:
            logger.error(f"Error applying Rust-Crypter: {e}")
            return filepath

    def apply_upx_packing(self, filepath: str) -> str:
        """Apply UPX packing to the binary.

        Args:
            filepath: Path to the binary file to pack

        Returns:
            Path to the packed binary file
        """
        try:
            logger.info(f"Applying UPX packing to {filepath}")

            # Import UPX packer
            from rt_evade.pe.packer import PEPacker

            # Create packer instance
            packer = PEPacker()

            # Pack the file
            packed_path = packer.pack_pe_file(filepath, self.output_dir)

            self.advanced_techniques_used["upx_packing"] = True
            logger.info(f"UPX packing completed: {packed_path}")
            return packed_path

        except Exception as e:
            logger.error(f"Error applying UPX packing: {e}")
            return filepath

    def run_obfuscation_loop(
        self, initial_binary_path: str, max_attempts: int = 10
    ) -> Tuple[str, bool, List[str]]:
        """Run the main obfuscation loop until evasion or max attempts.

        Args:
            initial_binary_path: Path to the initial binary file
            max_attempts: Maximum number of obfuscation attempts

        Returns:
            Tuple of (final_binary_path, evaded_status, obfuscation_history)
        """
        try:
            self.current_binary_path = initial_binary_path
            self.obfuscation_history = []
            self.attempt_count = 0
            evaded = False

            logger.info(f"Starting obfuscation attempts on: {initial_binary_path}")

            # Validate initial file
            if not validate_pe_file(initial_binary_path):
                logger.info(f"Error: {initial_binary_path} is not a valid PE file")
                return initial_binary_path, False, []

            while not evaded and self.attempt_count < max_attempts:
                self.attempt_count += 1
                logger.info(f"Attempt {self.attempt_count}/{max_attempts}")

                # Save checkpoint before modification
                try:
                    checkpoint_path = save_checkpoint(
                        self.current_binary_path, self.output_dir
                    )
                    logger.info(f"Checkpoint saved: {checkpoint_path}")
                except Exception as e:
                    logger.info(f"Warning: Failed to save checkpoint: {e}")
                    checkpoint_path = None

                try:
                    # Use AI to decide next action
                    action = self.ai_decide_next_action()
                    logger.info(f"AI selected action: {action}")

                    # Handle special actions
                    if action == "stop":
                        logger.info("AI decided to stop trying")
                        break

                    # Apply the selected action
                    if action == "add_junk_sections":
                        obfuscated_binary_path = self.add_junk_sections(
                            self.current_binary_path
                        )
                    elif action == "rearrange_sections":
                        obfuscated_binary_path = self.rearrange_sections(
                            self.current_binary_path
                        )
                    elif action == "change_section_names":
                        obfuscated_binary_path = self.change_section_names(
                            self.current_binary_path
                        )
                    elif action == "change_timestamp":
                        obfuscated_binary_path = self.change_timestamp(
                            self.current_binary_path
                        )
                    elif action == "rust_crypter":
                        obfuscated_binary_path = self.apply_rust_crypter(
                            self.current_binary_path
                        )
                    elif action == "upx_packing":
                        obfuscated_binary_path = self.apply_upx_packing(
                            self.current_binary_path
                        )
                    else:
                        logger.warning(f"Unknown action: {action}, skipping")
                        continue

                    # Validate the result
                    if not validate_pe_file(obfuscated_binary_path):
                        logger.info(
                            f"Warning: Obfuscation result is not a valid PE file"
                        )
                        if checkpoint_path:
                            revert_to_checkpoint(
                                self.current_binary_path, checkpoint_path
                            )
                        continue

                    self.obfuscation_history.append(action)
                    logger.info(
                        f"Applied {action}. New binary: {obfuscated_binary_path}"
                    )

                    # Test against evasion model
                    evasion_result = self.test_evasion(obfuscated_binary_path)

                    # Track the outcome
                    success = evasion_result == 0
                    self.action_outcomes.append(
                        {
                            "action": action,
                            "success": success,
                            "attempt": self.attempt_count,
                        }
                    )

                    # Update technique effectiveness
                    self.update_technique_effectiveness(action, success)

                    if evasion_result == 0:
                        evaded = True
                        logger.info(
                            f"Binary successfully evaded detection after {self.attempt_count} attempts!"
                        )
                        # Copy final file to main output directory
                        final_path = self._copy_final_file(
                            obfuscated_binary_path, initial_binary_path
                        )
                        self.current_binary_path = final_path
                    else:
                        logger.info("Binary still detected. Continuing obfuscation.")
                        self.current_binary_path = obfuscated_binary_path

                    # Clean up old checkpoints
                    if checkpoint_path:
                        cleanup_old_checkpoints(initial_binary_path, keep_count=3)

                except Exception as e:
                    # Handle errors and revert
                    logger.info(
                        f"Error during obfuscation: {e}. Reverting to checkpoint."
                    )
                    if checkpoint_path:
                        if revert_to_checkpoint(
                            self.current_binary_path, checkpoint_path
                        ):
                            logger.info(f"Reverted to: {self.current_binary_path}")
                        else:
                            logger.info("Failed to revert to checkpoint")
                    else:
                        logger.info("No checkpoint available for revert")

            if not evaded:
                logger.info("Max attempts reached. Binary could not evade detection.")
                # Copy the last attempted file to the main output directory
                if self.current_binary_path and self.output_dir:
                    final_path = self._copy_final_file(
                        self.current_binary_path, initial_binary_path
                    )
                    self.current_binary_path = final_path

            logger.info("Obfuscation process complete.")
            return self.current_binary_path, evaded, self.obfuscation_history

        except Exception as e:
            logger.info(f"Critical error in obfuscation loop: {e}")
            return (
                self.current_binary_path or initial_binary_path,
                False,
                self.obfuscation_history,
            )

    def get_agent_status(self) -> dict:
        """Get current agent status information.

        Returns:
            Dictionary containing agent status
        """
        return {
            "current_binary_path": self.current_binary_path,
            "attempt_count": self.attempt_count,
            "obfuscation_history": self.obfuscation_history,
            "technique_effectiveness": self.technique_effectiveness,
            "advanced_techniques_used": self.advanced_techniques_used,
            "recent_action_outcomes": self.action_outcomes[-5:],
            "agent_name": self.name,
            "agent_description": self.description,
        }
