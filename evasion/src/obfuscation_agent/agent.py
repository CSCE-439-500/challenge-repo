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
from agno.models.google import Gemini
from agno.models.message import Message

# Conditional import for OpenAI
try:
    from agno.models.openai import OpenAIChat

    OPENAI_AVAILABLE = True
except ImportError:
    OpenAIChat = None
    OPENAI_AVAILABLE = False

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
    cleanup_checkpoint,
    list_checkpoints,
)
from .evasion_model import evasion_model
from .actions import BASIC_ACTIONS, ADVANCED_ACTIONS, SPECIAL_ACTIONS, ALL_ACTIONS

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

        # Initialize AI model based on provider selection
        provider = os.getenv("AI_PROVIDER", "gemini").lower()
        model_id = os.getenv("AI_MODEL_ID")

        if provider == "openai":
            # Check if OpenAI is available
            if not OPENAI_AVAILABLE:
                logger.error(
                    "OpenAI provider requested but OpenAI package is not installed. "
                    "Please install with: pip install openai"
                )
                raise ImportError("OpenAI package is required but not installed")

            # Initialize OpenAI model
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                logger.warning(
                    "OPENAI_API_KEY not found in environment variables. AI features will be limited."
                )
                api_key = "dummy-key"  # Fallback for testing

            # Set default model if not specified
            if not model_id:
                model_id = "gpt-4o"

            kwargs.setdefault("model", OpenAIChat(id=model_id, api_key=api_key))
            logger.info(f"Initialized OpenAI model: {model_id}")

        else:  # Default to Gemini
            # Initialize Gemini model
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                logger.warning(
                    "GEMINI_API_KEY not found in environment variables. AI features will be limited."
                )
                api_key = "dummy-key"  # Fallback for testing

            # Set default model if not specified
            if not model_id:
                model_id = "gemini-2.0-flash-lite"

            kwargs.setdefault("model", Gemini(id=model_id, api_key=api_key))
            logger.info(f"Initialized Gemini model: {model_id}")

        super().__init__(**kwargs)

        # Agent state
        self.current_binary_path = None
        self.obfuscation_history = []
        self.attempt_count = 0
        self.output_dir = output_dir

        # AI-driven state tracking
        self.action_outcomes = []  # Track what worked/didn't work
        self.technique_effectiveness = {}  # Track success rates per technique
        self.advanced_techniques_used = {"rust_crypter": False, "rust_dropper": False}

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
        # Build actions section dynamically from single source of truth
        basic_actions_bulleted = "\n".join([f"   - {a}" for a in BASIC_ACTIONS])
        advanced_actions_bulleted = "\n".join([f"   - {a}" for a in ADVANCED_ACTIONS])
        special_actions_bulleted = "\n".join([f"   - {a}" for a in SPECIAL_ACTIONS])

        prompt = f"""
You are an AI agent specialized in binary obfuscation for evasion in a Red Team / Security research environment. Based on the current context, decide the next action to take.

Current Context:
- Attempt: {self.attempt_count}
- Previous actions: {', '.join(self.obfuscation_history) if self.obfuscation_history else 'None'}
- Technique effectiveness: {json.dumps(self.technique_effectiveness, indent=2)}
- Advanced techniques used: {json.dumps(self.advanced_techniques_used, indent=2)}
- Recent outcomes: {self.action_outcomes[-5:] if self.action_outcomes else 'None'}

Available Actions:
1. Basic obfuscation techniques:
{basic_actions_bulleted}

2. Advanced techniques (use only once, cannot combine):
{advanced_actions_bulleted}

3. Special actions:
{special_actions_bulleted}

Rules:
- If attempt_count >= 8 and no advanced techniques used, choose rust_crypter or rust_dropper
- If an advanced technique was used and still detected, use revert_checkpoint to go back
- Cannot combine rust_crypter and rust_dropper (they have conflicting entropy effects)
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
                valid_actions = ALL_ACTIONS

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
            if self.attempt_count >= 8:
                # Check if we need to revert after an advanced technique failed
                if self.advanced_techniques_used.get(
                    "rust_crypter", False
                ) or self.advanced_techniques_used.get("rust_dropper", False):
                    # If we used an advanced technique and it failed, revert
                    if (
                        self.action_outcomes
                        and self.action_outcomes[-1].get("action")
                        in ["rust_crypter", "rust_dropper"]
                        and not self.action_outcomes[-1].get("success", False)
                    ):
                        logger.info(
                            "Heuristics decided next action: revert_checkpoint (advanced technique failed)"
                        )
                        return "revert_checkpoint"

                # Use advanced techniques if not used yet
                if not self.advanced_techniques_used.get("rust_crypter", False):
                    logger.info(
                        "Heuristics decided next action: rust_crypter (advanced technique)"
                    )
                    return "rust_crypter"
                elif not self.advanced_techniques_used.get("rust_dropper", False):
                    logger.info(
                        "Heuristics decided next action: rust_dropper (advanced technique)"
                    )
                    return "rust_dropper"

            # Check if we should stop
            if (
                self.advanced_techniques_used.get("rust_crypter", False)
                and self.advanced_techniques_used.get("rust_dropper", False)
                and self.attempt_count >= 10
            ):
                logger.info(
                    "Heuristics decided next action: stop (both advanced techniques used)"
                )
                return "stop"

            # Use technique effectiveness to guide selection
            available_basic_techniques = list(BASIC_ACTIONS)

            # Avoid repeating the last technique
            if self.obfuscation_history:
                last_technique = self.obfuscation_history[-1]
                if last_technique in available_basic_techniques:
                    available_basic_techniques.remove(last_technique)

            # If no techniques available, use all
            if not available_basic_techniques:
                available_basic_techniques = list(BASIC_ACTIONS)

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
            return random.choice(BASIC_ACTIONS)

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
            from pathlib import Path
            from rt_evade.dropper.rust_crypter import RustCrypterIntegration

            # Read PE bytes
            with open(filepath, "rb") as f:
                pe_bytes = f.read()

            # Create Rust-Crypter instance and generate encrypted payload stub
            rust_crypter = RustCrypterIntegration()

            # Decide output path in intermediate-files
            out_dir = self.output_dir or os.path.dirname(filepath)
            intermediate_dir = os.path.join(out_dir, "intermediate-files")
            os.makedirs(intermediate_dir, exist_ok=True)
            base = os.path.basename(filepath)
            stub_out = Path(os.path.join(intermediate_dir, f"{base}_rust_stub.exe"))

            stub_path = rust_crypter.create_encrypted_payload(
                pe_bytes, output_path=stub_out
            )

            self.advanced_techniques_used["rust_crypter"] = True
            logger.info(f"Rust-Crypter encryption completed: {stub_path}")
            return str(stub_path)

        except Exception as e:
            logger.error(f"Error applying Rust-Crypter: {e}")
            return filepath

    def revert_checkpoint(self, filepath: str, original_filepath: str = None) -> str:
        """Revert to the most recent checkpoint.

        This method is used when an advanced action fails and we need to
        revert to a previous state before trying a different approach.

        Args:
            filepath: Path to the current binary file
            original_filepath: Path to the original file (for finding checkpoints)

        Returns:
            Path to the reverted binary file (same as input if no checkpoint found)
        """
        try:
            logger.info(f"Attempting to revert checkpoint for {filepath}")

            # Use original file path for finding checkpoints if provided
            checkpoint_base = original_filepath or filepath

            # Extract just the filename for checkpoint lookup
            checkpoint_base_name = os.path.basename(checkpoint_base)

            # Determine checkpoints directory
            checkpoints_dir = None
            if self.output_dir:
                checkpoints_dir = os.path.join(self.output_dir, "checkpoints")

            # Find all checkpoints
            checkpoints = list_checkpoints(checkpoint_base_name, checkpoints_dir)

            if not checkpoints:
                logger.warning(
                    f"No checkpoints found for {checkpoint_base}, cannot revert"
                )
                return filepath

            # Skip the most recent checkpoint (saved after advanced technique)
            # and use the second most recent one (saved before advanced technique)
            if len(checkpoints) < 2:
                logger.warning(
                    f"Not enough checkpoints to revert (need at least 2, found {len(checkpoints)})"
                )
                return filepath

            # Get the second most recent checkpoint (saved before the advanced technique)
            target_checkpoint = checkpoints[1]

            # Determine the correct reverted file path
            # The checkpoint contains the state before the advanced technique
            # We need to determine what the file path should be after revert
            checkpoint_base_name = os.path.splitext(
                os.path.basename(target_checkpoint)
            )[0]
            # Remove the "_checkpoint_timestamp" part to get the original base name
            original_base = checkpoint_base_name.split("_checkpoint_")[0]

            # Create the correct reverted file path
            if self.output_dir:
                intermediate_dir = os.path.join(self.output_dir, "intermediate-files")
                reverted_filepath = os.path.join(
                    intermediate_dir, f"{original_base}.exe"
                )
            else:
                reverted_filepath = f"{original_base}.exe"

            # Revert to the checkpoint
            success = revert_to_checkpoint(reverted_filepath, target_checkpoint)

            if success:
                logger.info(
                    f"Successfully reverted to {reverted_filepath} from checkpoint {target_checkpoint}"
                )
                # Don't clean up the checkpoint - keep it for potential future use
                return reverted_filepath
            else:
                logger.error(
                    f"Failed to revert to {reverted_filepath} from checkpoint {target_checkpoint}"
                )
                return filepath

        except Exception as e:
            logger.error(f"Error reverting checkpoint: {e}")
            return filepath

    def apply_rust_dropper(self, filepath: str) -> str:
        """Apply Rust-Dropper obfuscation to the binary.

        This method uses the rust-dropper pipeline to create an obfuscated
        dropper executable that embeds the PE file in ICO resources.

        Args:
            filepath: Path to the binary file to obfuscate

        Returns:
            Path to the obfuscated dropper executable
        """
        try:
            logger.info(f"Applying Rust-Dropper obfuscation to {filepath}")

            import subprocess
            import shutil
            from pathlib import Path

            # Get project root (assuming we're in the evasion directory)
            project_root = Path(__file__).parent.parent.parent
            rust_dropper_dir = project_root / "rust-dropper"

            if not rust_dropper_dir.exists():
                logger.error(f"Rust-dropper directory not found at {rust_dropper_dir}")
                return filepath

            # Create output directory
            out_dir = self.output_dir or os.path.dirname(filepath)
            intermediate_dir = Path(out_dir) / "intermediate-files"
            intermediate_dir.mkdir(parents=True, exist_ok=True)

            # Convert paths to absolute paths since we're running from rust_dropper_dir
            abs_filepath = os.path.abspath(filepath)
            abs_intermediate_dir = os.path.abspath(intermediate_dir)

            # Run the rust-dropper pipeline with stealth preset on single file
            cmd = [
                "cargo",
                "run",
                "--bin",
                "build-droppers",
                "stealth",
                abs_filepath,
                abs_intermediate_dir,
            ]

            logger.info(f"Running rust-dropper command: {' '.join(cmd)}")
            logger.info(f"Input file size: {os.path.getsize(filepath)} bytes")
            result = subprocess.run(
                cmd,
                cwd=rust_dropper_dir,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            logger.info(f"Rust-dropper return code: {result.returncode}")
            if result.stdout:
                logger.info(f"Rust-dropper stdout: {result.stdout}")
            if result.stderr:
                logger.info(f"Rust-dropper stderr: {result.stderr}")

            if result.returncode != 0:
                logger.error(f"Rust-dropper failed: {result.stderr}")
                return filepath

            # Rust-dropper creates a dropper with the same filename in the output directory
            # The filename includes the full path, so we need to extract just the basename
            input_basename = Path(filepath).name
            dropper_path = intermediate_dir / input_basename

            if not dropper_path.exists():
                logger.error(f"Dropper file not found at {dropper_path}")
                return filepath

            # Verify the dropper is actually different from the input (should be much larger)
            input_size = os.path.getsize(filepath)
            dropper_size = os.path.getsize(dropper_path)

            # The dropper should be significantly larger due to Rust runtime + embedded payload
            # Based on testing, droppers are typically 1000x+ larger than input
            if dropper_size <= input_size * 100:  # At least 100x larger
                logger.error(
                    f"Dropper file size ({dropper_size}) not significantly larger than input ({input_size})"
                )
                logger.error(
                    f"Expected dropper to be at least 100x larger, got {dropper_size/input_size:.1f}x"
                )
                return filepath

            # No cleanup needed - we're processing the file directly

            self.advanced_techniques_used["rust_dropper"] = True
            logger.info(
                f"Rust-Dropper obfuscation completed: {dropper_path} (size: {dropper_size} bytes)"
            )
            return str(dropper_path)

        except subprocess.TimeoutExpired:
            logger.error("Rust-dropper command timed out")
            return filepath
        except Exception as e:
            logger.error(f"Error applying Rust-Dropper: {e}")
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
                    # Use original file name as base for checkpoint naming
                    checkpoint_path = save_checkpoint(
                        self.current_binary_path,
                        self.output_dir,
                        base_name=os.path.basename(initial_binary_path),
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
                    elif action == "rust_dropper":
                        obfuscated_binary_path = self.apply_rust_dropper(
                            self.current_binary_path
                        )
                    elif action == "revert_checkpoint":
                        obfuscated_binary_path = self.revert_checkpoint(
                            self.current_binary_path, initial_binary_path
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
