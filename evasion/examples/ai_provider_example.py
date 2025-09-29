#!/usr/bin/env python3
"""
Example demonstrating how to use the AI obfuscation agent with different providers.

This example shows how to configure and use the agent with both Gemini and OpenAI providers.
"""

import os
import tempfile
from obfuscation_agent.agent import ObfuscationAgent


def example_gemini_usage():
    """Example using Gemini provider."""
    print("=== Gemini Provider Example ===")
    
    # Set environment variables for Gemini
    os.environ['AI_PROVIDER'] = 'gemini'
    os.environ['GEMINI_API_KEY'] = 'your-gemini-api-key-here'
    os.environ['AI_MODEL_ID'] = 'gemini-2.0-flash-lite'  # Optional, defaults to this
    
    # Create agent
    agent = ObfuscationAgent()
    print(f"Agent initialized with provider: {agent.model.provider}")
    print(f"Model ID: {agent.model.id}")
    
    return agent


def example_openai_usage():
    """Example using OpenAI provider."""
    print("\n=== OpenAI Provider Example ===")
    
    # Set environment variables for OpenAI
    os.environ['AI_PROVIDER'] = 'openai'
    os.environ['OPENAI_API_KEY'] = 'your-openai-api-key-here'
    os.environ['AI_MODEL_ID'] = 'gpt-4o'  # Optional, defaults to this
    
    try:
        # Create agent
        agent = ObfuscationAgent()
        print(f"Agent initialized with provider: {agent.model.provider}")
        print(f"Model ID: {agent.model.id}")
        return agent
    except ImportError as e:
        print(f"OpenAI not available: {e}")
        print("To use OpenAI, install with: pip install openai")
        return None


def example_custom_model():
    """Example using custom model selection."""
    print("\n=== Custom Model Example ===")
    
    # Set environment variables for custom model
    os.environ['AI_PROVIDER'] = 'openai'
    os.environ['OPENAI_API_KEY'] = 'your-openai-api-key-here'
    os.environ['AI_MODEL_ID'] = 'gpt-3.5-turbo'  # Custom model
    
    try:
        # Create agent
        agent = ObfuscationAgent()
        print(f"Agent initialized with provider: {agent.model.provider}")
        print(f"Model ID: {agent.model.id}")
        return agent
    except ImportError as e:
        print(f"OpenAI not available: {e}")
        return None


def example_obfuscation_workflow(agent, sample_file):
    """Example of running obfuscation workflow."""
    if not agent:
        print("No agent available for workflow example")
        return
    
    print(f"\n=== Obfuscation Workflow Example ===")
    print(f"Using agent: {agent.name}")
    print(f"Provider: {agent.model.provider}")
    print(f"Model: {agent.model.id}")
    
    # Run obfuscation loop
    try:
        final_path, evaded, history = agent.run_obfuscation_loop(
            sample_file, 
            max_attempts=3
        )
        
        print(f"Obfuscation completed!")
        print(f"Final file: {final_path}")
        print(f"Evaded detection: {evaded}")
        print(f"Techniques used: {history}")
        
    except Exception as e:
        print(f"Error during obfuscation: {e}")


def main():
    """Main example function."""
    print("AI Obfuscation Agent - Provider Examples")
    print("=" * 50)
    
    # Create a temporary sample file for testing
    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
        # Write minimal PE header
        f.write(b'MZ' + b'\x00' * 58 + b'PE\x00\x00')
        f.write(b'\x00' * 1000)
        sample_file = f.name
    
    try:
        # Example 1: Gemini provider
        gemini_agent = example_gemini_usage()
        
        # Example 2: OpenAI provider
        openai_agent = example_openai_usage()
        
        # Example 3: Custom model
        custom_agent = example_custom_model()
        
        # Example 4: Obfuscation workflow
        if gemini_agent:
            example_obfuscation_workflow(gemini_agent, sample_file)
        
    finally:
        # Cleanup
        if os.path.exists(sample_file):
            os.unlink(sample_file)


if __name__ == "__main__":
    main()