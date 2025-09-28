"""State management module for checkpoint and revert functionality.

This module provides functions to save checkpoints of binary files
and revert to previous states when obfuscation fails.
"""

import os
import shutil
import logging
from datetime import datetime
from typing import Optional

# Removed REDTEAM_MODE requirement

logger = logging.getLogger(__name__)


def save_checkpoint(filepath: str, output_dir: str = None) -> str:
    """Save a checkpoint of the binary file.

    Args:
        filepath: Path to the binary file to checkpoint
        output_dir: Output directory to save checkpoints in

    Returns:
        Path to the checkpoint file

    Raises:
        Exception: If checkpoint creation fails
    """
    try:

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        # Generate timestamp for checkpoint name (with microseconds for uniqueness)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

        if output_dir:
            # Save checkpoint in the output directory's checkpoints folder
            checkpoints_dir = os.path.join(output_dir, "checkpoints")
            os.makedirs(checkpoints_dir, exist_ok=True)
            filename = os.path.basename(filepath)
            base_name = os.path.splitext(filename)[0]
            extension = os.path.splitext(filename)[1]
            checkpoint_path = os.path.join(
                checkpoints_dir, f"{base_name}_checkpoint_{timestamp}{extension}"
            )
        else:
            # Fallback to original behavior
            base_name = os.path.splitext(filepath)[0]
            extension = os.path.splitext(filepath)[1]
            checkpoint_path = f"{base_name}_checkpoint_{timestamp}{extension}"

        # Copy file to checkpoint location
        shutil.copy2(filepath, checkpoint_path)

        logger.info(f"Checkpoint saved: {checkpoint_path}")
        return checkpoint_path

    except Exception as e:
        logger.error(f"Error saving checkpoint: {e}")
        raise


def revert_to_checkpoint(original_path: str, checkpoint_path: str) -> bool:
    """Revert the original file to a checkpoint state.

    Args:
        original_path: Path to the original file to restore
        checkpoint_path: Path to the checkpoint file

    Returns:
        True if revert successful, False otherwise
    """
    try:

        if not os.path.exists(checkpoint_path):
            logger.error(f"Checkpoint file not found: {checkpoint_path}")
            return False

        # Copy checkpoint back to original location
        shutil.copy2(checkpoint_path, original_path)

        logger.info(f"Reverted {original_path} to checkpoint {checkpoint_path}")
        return True

    except Exception as e:
        logger.error(f"Error reverting to checkpoint: {e}")
        return False


def cleanup_checkpoint(checkpoint_path: str) -> bool:
    """Clean up a checkpoint file.

    Args:
        checkpoint_path: Path to the checkpoint file to delete

    Returns:
        True if cleanup successful, False otherwise
    """
    try:
        if os.path.exists(checkpoint_path):
            os.remove(checkpoint_path)
            logger.info(f"Cleaned up checkpoint: {checkpoint_path}")
            return True
        return True

    except Exception as e:
        logger.error(f"Error cleaning up checkpoint: {e}")
        return False


def list_checkpoints(base_path: str) -> list:
    """List all checkpoint files for a given base file.

    Args:
        base_path: Base path of the file (without extension)

    Returns:
        List of checkpoint file paths
    """
    try:
        base_name = os.path.splitext(base_path)[0]
        base_dir = os.path.dirname(base_name)
        base_file = os.path.basename(base_name)

        if not base_dir:
            base_dir = "."

        # Find all checkpoint files
        checkpoints = []
        if os.path.exists(base_dir):
            for filename in os.listdir(base_dir):
                if filename.startswith(base_file) and "_checkpoint_" in filename:
                    checkpoints.append(os.path.join(base_dir, filename))

        # Sort by modification time (newest first)
        checkpoints.sort(key=lambda x: os.path.getmtime(x), reverse=True)

        return checkpoints

    except Exception as e:
        logger.error(f"Error listing checkpoints: {e}")
        return []


def cleanup_old_checkpoints(base_path: str, keep_count: int = 5) -> int:
    """Clean up old checkpoint files, keeping only the most recent ones.

    Args:
        base_path: Base path of the file (without extension)
        keep_count: Number of recent checkpoints to keep

    Returns:
        Number of checkpoints cleaned up
    """
    try:
        checkpoints = list_checkpoints(base_path)

        if len(checkpoints) <= keep_count:
            return 0

        # Remove old checkpoints
        to_remove = checkpoints[keep_count:]
        removed_count = 0

        for checkpoint in to_remove:
            if cleanup_checkpoint(checkpoint):
                removed_count += 1

        logger.info(f"Cleaned up {removed_count} old checkpoints")
        return removed_count

    except Exception as e:
        logger.error(f"Error cleaning up old checkpoints: {e}")
        return 0
