"""Agno agent implementation for automated binary obfuscation.

This module implements the ObfuscationAgent using the Agno framework
to autonomously apply obfuscation techniques until evasion is achieved.
"""

import random
import logging
from typing import List, Tuple, Optional

from agno.agent import Agent
from agno.tools import tool
from agno.models.openai import OpenAIChat

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
        kwargs.setdefault("name", "BinaryObfuscationAgent")
        kwargs.setdefault(
            "description",
            "This agent is designed to apply various obfuscation techniques to a binary file "
            "with the goal of evading a classification model. It tracks the state of the binary, "
            "reverts on failure, and continuously tries new techniques.",
        )
        kwargs.setdefault("model", OpenAIChat(id="gpt-4o"))

        super().__init__(**kwargs)

        # Agent state
        self.current_binary_path = None
        self.obfuscation_history = []
        self.attempt_count = 0
        self.output_dir = output_dir

        logger.info("ObfuscationAgent initialized")

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
                    checkpoint_path = save_checkpoint(self.current_binary_path)
                    logger.info(f"Checkpoint saved: {checkpoint_path}")
                except Exception as e:
                    logger.info(f"Warning: Failed to save checkpoint: {e}")
                    checkpoint_path = None

                try:
                    # Select a random obfuscation tool
                    available_tools = [
                        self.add_junk_sections,
                        self.rearrange_sections,
                        self.change_section_names,
                        self.change_timestamp,
                    ]

                    selected_tool = random.choice(available_tools)
                    obfuscation_name = selected_tool.__name__

                    logger.info(f"Agent selected tool: {obfuscation_name}")

                    # Apply obfuscation
                    obfuscated_binary_path = selected_tool(self.current_binary_path)

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

                    self.obfuscation_history.append(obfuscation_name)
                    logger.info(
                        f"Applied {obfuscation_name}. New binary: {obfuscated_binary_path}"
                    )

                    # Test against evasion model
                    evasion_result = self.test_evasion(obfuscated_binary_path)

                    if evasion_result == 0:
                        evaded = True
                        logger.info(
                            f"Binary successfully evaded detection after {self.attempt_count} attempts!"
                        )
                        self.current_binary_path = obfuscated_binary_path
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
            "agent_name": self.name,
            "agent_description": self.description,
        }
