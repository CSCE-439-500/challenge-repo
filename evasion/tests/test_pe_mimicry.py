"""Tests for PE mimicry functionality.

This module contains pytest tests for the PE mimicry component,
including template matching and benign software characteristic copying.
"""

import os
import pytest
from unittest.mock import patch

from rt_evade.pe.mimicry import PEMimicryEngine, BenignTemplate


class TestPEMimicryEngine:
    """Test PE mimicry functionality."""

    def test_mimicry_engine_initialization(self):
        """Test mimicry engine initialization."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            engine = PEMimicryEngine()
            assert engine is not None
            assert isinstance(engine.templates, list)

    def test_mimicry_engine_requires_redteam_mode(self):
        """Test that mimicry engine requires REDTEAM_MODE."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="REDTEAM_MODE not enabled"):
                PEMimicryEngine()

    def test_find_similar_template(self):
        """Test finding similar templates."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            engine = PEMimicryEngine()

            # Test with sample characteristics
            characteristics = {
                "header": {
                    "machine": 0x014C,
                    "subsystem": 1,
                    "dll_characteristics": 0x8140,
                },
                "sections": {
                    ".text": {"characteristics": 0x60000020, "is_executable": True},
                    ".data": {"characteristics": 0xC0000040, "is_executable": False},
                },
                "imports": {"kernel32.dll": ["GetModuleHandleW", "GetProcAddress"]},
            }

            template = engine.find_similar_template(characteristics)
            # Should return None or a valid template
            assert template is None or isinstance(template, BenignTemplate)

    def test_generate_mimicry_plan(self):
        """Test generating mimicry plan."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            engine = PEMimicryEngine()

            characteristics = {
                "header": {"machine": 0x014C, "subsystem": 1},
                "sections": {".text": {"characteristics": 0x60000020}},
                "imports": {"kernel32.dll": ["GetModuleHandleW"]},
            }

            plan = engine.generate_mimicry_plan(characteristics)
            assert isinstance(plan, dict)
            if plan:  # If a plan is generated
                assert "template_name" in plan
                assert "modifications" in plan

    def test_benign_template_creation(self):
        """Test BenignTemplate creation."""
        template = BenignTemplate(
            name="test.exe",
            category="system_utility",
            characteristics={
                "header": {"machine": 0x014C, "subsystem": 1},
                "sections": {".text": {"characteristics": 0x60000020}},
                "imports": {"kernel32.dll": ["GetModuleHandleW"]},
            },
            section_names=[".text", ".data"],
            import_dlls=["kernel32.dll"],
            common_functions=["GetModuleHandleW", "GetProcAddress"],
        )

        assert template.name == "test.exe"
        assert template.category == "system_utility"
        assert len(template.section_names) == 2
        assert len(template.import_dlls) == 1
        assert len(template.common_functions) == 2
