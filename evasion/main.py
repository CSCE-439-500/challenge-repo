#!/usr/bin/env python3
"""Main entry point for the Automated Malware Obfuscation Agent.

This script provides a command-line interface for running the obfuscation agent
against binary files to test evasion techniques.
"""

import argparse
import os
import sys
import logging
from typing import Optional

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from obfuscation_agent.agent import ObfuscationAgent
from obfuscation_agent.obfuscation_tools import validate_pe_file

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    """Main function for the obfuscation agent CLI."""
    parser = argparse.ArgumentParser(
        description="Automated binary obfuscation agent for evasion testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py sample.exe
  python main.py sample.exe --max-attempts 20
  python main.py sample.exe --verbose
        """,
    )

    parser.add_argument(
        "binary_path", type=str, help="Path to the initial binary file to obfuscate"
    )

    parser.add_argument(
        "--max-attempts",
        type=int,
        default=10,
        help="Maximum number of obfuscation attempts (default: 10)",
    )

    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    parser.add_argument(
        "--output-dir",
        type=str,
        default=".",
        help="Directory to save output files (default: current directory)",
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Validate input file
        initial_binary_path = args.binary_path
        if not os.path.exists(initial_binary_path):
            print(f"Error: Binary file not found at {initial_binary_path}")
            return 1

        if not validate_pe_file(initial_binary_path):
            print(f"Error: {initial_binary_path} is not a valid PE file")
            return 1

        print(f"Starting obfuscation agent...")
        print(f"Target binary: {initial_binary_path}")
        print(f"Max attempts: {args.max_attempts}")
        print(f"Output directory: {args.output_dir}")
        print("-" * 50)

        # Create output directory if it doesn't exist
        os.makedirs(args.output_dir, exist_ok=True)

        # Instantiate the Agno Agent
        agent = ObfuscationAgent(output_dir=args.output_dir)

        # Run the obfuscation loop
        final_binary, evaded_status, history = agent.run_obfuscation_loop(
            initial_binary_path, args.max_attempts
        )

        # Print summary
        print("\n" + "=" * 50)
        print("OBFUSCATION SUMMARY")
        print("=" * 50)
        print(f"Initial Binary: {initial_binary_path}")
        print(f"Final Binary: {final_binary}")
        print(f"Evasion Status: {'EVADED' if evaded_status else 'NOT EVADED'}")
        print(f"Attempts Made: {len(history)}")
        print(f"Obfuscation History: {', '.join(history) if history else 'None'}")

        # Final binary is already in the correct location
        print(f"Final binary saved to: {final_binary}")

        return 0 if evaded_status else 1

    except Exception as e:
        logger.error(f"Critical error: {e}")
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
