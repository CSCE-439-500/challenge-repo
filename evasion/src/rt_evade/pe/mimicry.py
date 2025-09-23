"""PE mimicry engine for benign software template matching.

This module provides capabilities to make PE files look like legitimate software
by copying characteristics from benign PE samples.
"""

import logging
import os
import random
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

from ..core.guards import require_redteam_mode
from .reader import PEReader, PEHeaderInfo, PESectionInfo, PEImportInfo

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BenignTemplate:
    """Template information for a benign PE file."""

    name: str
    category: str
    characteristics: Dict[str, Any]
    section_names: List[str]
    import_dlls: List[str]
    common_functions: List[str]


class PEMimicryEngine:
    """PE mimicry engine for making malicious PE files look benign.

    This class provides template matching and characteristic copying
    to make PE files appear like legitimate software.
    """

    def __init__(self, template_db_path: Optional[str] = None):
        """Initialize mimicry engine with template database.

        Args:
            template_db_path: Path to benign template database JSON file
        """
        require_redteam_mode()

        self.template_db_path = template_db_path or "benign_templates.json"
        self.templates: List[BenignTemplate] = []
        self._load_templates()

        logger.info(
            "action=mimicry_engine_initialized templates=%d", len(self.templates)
        )

    def _load_templates(self) -> None:
        """Load benign PE templates from database."""
        if not os.path.exists(self.template_db_path):
            logger.warning(
                "action=template_db_not_found path=%s", self.template_db_path
            )
            self._create_default_templates()
            return

        try:
            with open(self.template_db_path, "r") as f:
                data = json.load(f)

            for template_data in data.get("templates", []):
                template = BenignTemplate(
                    name=template_data["name"],
                    category=template_data["category"],
                    characteristics=template_data["characteristics"],
                    section_names=template_data["section_names"],
                    import_dlls=template_data["import_dlls"],
                    common_functions=template_data["common_functions"],
                )
                self.templates.append(template)

            logger.info("action=templates_loaded count=%d", len(self.templates))

        except Exception as e:
            logger.error("action=template_load_failed error=%s", e)
            self._create_default_templates()

    def _create_default_templates(self) -> None:
        """Create default benign templates for common software categories."""
        default_templates = [
            # Windows System Utility
            BenignTemplate(
                name="notepad.exe",
                category="system_utility",
                characteristics={
                    "header": {
                        "machine": 0x014C,  # x86
                        "subsystem": 1,  # GUI
                        "dll_characteristics": 0x8140,  # ASLR + NX + Terminal Server Aware
                    },
                    "sections": {
                        ".text": {"characteristics": 0x60000020, "is_executable": True},
                        ".rdata": {
                            "characteristics": 0x40000040,
                            "is_executable": False,
                        },
                        ".data": {
                            "characteristics": 0xC0000040,
                            "is_executable": False,
                        },
                        ".rsrc": {
                            "characteristics": 0x40000040,
                            "is_executable": False,
                        },
                    },
                    "imports": {
                        "kernel32.dll": [
                            "GetModuleHandleW",
                            "GetProcAddress",
                            "LoadLibraryW",
                        ],
                        "user32.dll": [
                            "CreateWindowExW",
                            "DefWindowProcW",
                            "DispatchMessageW",
                        ],
                        "gdi32.dll": ["CreateFontW", "SelectObject", "TextOutW"],
                    },
                },
                section_names=[".text", ".rdata", ".data", ".rsrc"],
                import_dlls=["kernel32.dll", "user32.dll", "gdi32.dll"],
                common_functions=[
                    "GetModuleHandleW",
                    "GetProcAddress",
                    "CreateWindowExW",
                ],
            ),
            # Web Browser
            BenignTemplate(
                name="chrome.exe",
                category="web_browser",
                characteristics={
                    "header": {
                        "machine": 0x8664,  # x64
                        "subsystem": 2,  # Console
                        "dll_characteristics": 0x8140,
                    },
                    "sections": {
                        ".text": {"characteristics": 0x60000020, "is_executable": True},
                        ".rdata": {
                            "characteristics": 0x40000040,
                            "is_executable": False,
                        },
                        ".data": {
                            "characteristics": 0xC0000040,
                            "is_executable": False,
                        },
                        ".pdata": {
                            "characteristics": 0x40000040,
                            "is_executable": False,
                        },
                        ".rsrc": {
                            "characteristics": 0x40000040,
                            "is_executable": False,
                        },
                    },
                    "imports": {
                        "kernel32.dll": [
                            "CreateProcessW",
                            "GetCurrentProcess",
                            "ExitProcess",
                        ],
                        "ntdll.dll": ["RtlAllocateHeap", "RtlFreeHeap"],
                        "advapi32.dll": ["RegOpenKeyExW", "RegQueryValueExW"],
                    },
                },
                section_names=[".text", ".rdata", ".data", ".pdata", ".rsrc"],
                import_dlls=["kernel32.dll", "ntdll.dll", "advapi32.dll"],
                common_functions=[
                    "CreateProcessW",
                    "GetCurrentProcess",
                    "RegOpenKeyExW",
                ],
            ),
            # Office Application
            BenignTemplate(
                name="winword.exe",
                category="office_app",
                characteristics={
                    "header": {
                        "machine": 0x8664,  # x64
                        "subsystem": 2,  # Console
                        "dll_characteristics": 0x8140,
                    },
                    "sections": {
                        ".text": {"characteristics": 0x60000020, "is_executable": True},
                        ".rdata": {
                            "characteristics": 0x40000040,
                            "is_executable": False,
                        },
                        ".data": {
                            "characteristics": 0xC0000040,
                            "is_executable": False,
                        },
                        ".rsrc": {
                            "characteristics": 0x40000040,
                            "is_executable": False,
                        },
                    },
                    "imports": {
                        "kernel32.dll": ["GetModuleHandleW", "GetProcAddress"],
                        "ole32.dll": ["CoInitialize", "CoUninitialize"],
                        "oleaut32.dll": ["SysAllocString", "SysFreeString"],
                    },
                },
                section_names=[".text", ".rdata", ".data", ".rsrc"],
                import_dlls=["kernel32.dll", "ole32.dll", "oleaut32.dll"],
                common_functions=["GetModuleHandleW", "CoInitialize", "SysAllocString"],
            ),
        ]

        self.templates = default_templates
        logger.info("action=default_templates_created count=%d", len(self.templates))

    def find_similar_template(
        self, pe_characteristics: Dict[str, Any], category: Optional[str] = None
    ) -> Optional[BenignTemplate]:
        """Find the most similar benign template for given PE characteristics.

        Args:
            pe_characteristics: PE characteristics to match
            category: Optional category filter (system_utility, web_browser, etc.)

        Returns:
            Most similar BenignTemplate or None if no match found
        """
        if not self.templates:
            logger.warning("action=no_templates_available")
            return None

        # Filter by category if specified
        candidate_templates = self.templates
        if category:
            candidate_templates = [t for t in self.templates if t.category == category]
            if not candidate_templates:
                logger.warning("action=no_templates_in_category category=%s", category)
                candidate_templates = self.templates

        best_template = None
        best_score = 0.0

        for template in candidate_templates:
            score = self._calculate_similarity_score(pe_characteristics, template)
            if score > best_score:
                best_score = score
                best_template = template

        logger.info(
            "action=template_matched template=%s score=%.2f",
            best_template.name if best_template else "none",
            best_score,
        )

        return best_template

    def _calculate_similarity_score(
        self, pe_chars: Dict[str, Any], template: BenignTemplate
    ) -> float:
        """Calculate similarity score between PE characteristics and template.

        Args:
            pe_chars: PE characteristics to compare
            template: Benign template to compare against

        Returns:
            Similarity score between 0.0 and 1.0
        """
        score = 0.0
        total_weight = 0.0

        # Compare header characteristics (weight: 0.4)
        if "header" in pe_chars and "header" in template.characteristics:
            header_score = self._compare_headers(
                pe_chars["header"], template.characteristics["header"]
            )
            score += header_score * 0.4
            total_weight += 0.4

        # Compare sections (weight: 0.3)
        if "sections" in pe_chars and "sections" in template.characteristics:
            section_score = self._compare_sections(
                pe_chars["sections"], template.characteristics["sections"]
            )
            score += section_score * 0.3
            total_weight += 0.3

        # Compare imports (weight: 0.3)
        if "imports" in pe_chars and "imports" in template.characteristics:
            import_score = self._compare_imports(
                pe_chars["imports"], template.characteristics["imports"]
            )
            score += import_score * 0.3
            total_weight += 0.3

        return score / total_weight if total_weight > 0 else 0.0

    def _compare_headers(
        self, pe_header: Dict[str, Any], template_header: Dict[str, Any]
    ) -> float:
        """Compare PE headers for similarity."""
        score = 0.0
        total = 0.0

        for key in ["machine", "subsystem", "dll_characteristics"]:
            if key in pe_header and key in template_header:
                if pe_header[key] == template_header[key]:
                    score += 1.0
                total += 1.0

        return score / total if total > 0 else 0.0

    def _compare_sections(
        self, pe_sections: Dict[str, Any], template_sections: Dict[str, Any]
    ) -> float:
        """Compare PE sections for similarity."""
        pe_section_names = set(pe_sections.keys())
        template_section_names = set(template_sections.keys())

        # Calculate Jaccard similarity
        intersection = pe_section_names.intersection(template_section_names)
        union = pe_section_names.union(template_section_names)

        return len(intersection) / len(union) if union else 0.0

    def _compare_imports(
        self, pe_imports: Dict[str, List[str]], template_imports: Dict[str, List[str]]
    ) -> float:
        """Compare PE imports for similarity."""
        pe_dlls = set(pe_imports.keys())
        template_dlls = set(template_imports.keys())

        # Calculate Jaccard similarity for DLLs
        dll_intersection = pe_dlls.intersection(template_dlls)
        dll_union = pe_dlls.union(template_dlls)
        dll_score = len(dll_intersection) / len(dll_union) if dll_union else 0.0

        return dll_score

    def generate_mimicry_plan(
        self, pe_characteristics: Dict[str, Any], target_category: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate a mimicry plan for making PE look like benign software.

        Args:
            pe_characteristics: Current PE characteristics
            target_category: Target software category to mimic

        Returns:
            Dictionary containing mimicry modifications to apply
        """
        template = self.find_similar_template(pe_characteristics, target_category)
        if not template:
            logger.warning("action=no_mimicry_template_found")
            return {}

        mimicry_plan = {
            "template_name": template.name,
            "template_category": template.category,
            "modifications": {
                "header_changes": {},
                "section_additions": [],
                "import_additions": [],
                "string_additions": [],
            },
        }

        # Plan header modifications
        if "header" in template.characteristics:
            template_header = template.characteristics["header"]
            current_header = pe_characteristics.get("header", {})

            for key, value in template_header.items():
                if current_header.get(key) != value:
                    mimicry_plan["modifications"]["header_changes"][key] = value

        # Plan section additions
        current_sections = set(pe_characteristics.get("sections", {}).keys())
        template_sections = set(template.section_names)

        for section_name in template_sections:
            if section_name not in current_sections:
                mimicry_plan["modifications"]["section_additions"].append(
                    {
                        "name": section_name,
                        "characteristics": template.characteristics["sections"].get(
                            section_name, {}
                        ),
                    }
                )

        # Plan import additions
        current_imports = pe_characteristics.get("imports", {})
        template_imports = template.characteristics.get("imports", {})

        for dll_name, functions in template_imports.items():
            if dll_name not in current_imports:
                mimicry_plan["modifications"]["import_additions"].append(
                    {"dll": dll_name, "functions": functions}
                )

        # Plan string additions
        mimicry_plan["modifications"][
            "string_additions"
        ] = self._generate_benign_strings(template)

        logger.info(
            "action=mimicry_plan_generated template=%s modifications=%d",
            template.name,
            len(mimicry_plan["modifications"]),
        )

        return mimicry_plan

    def _generate_benign_strings(self, template: BenignTemplate) -> List[str]:
        """Generate benign strings based on template category."""
        category_strings = {
            "system_utility": [
                "Windows",
                "System",
                "Utility",
                "Configuration",
                "Settings",
                "Error",
                "Warning",
                "Information",
                "Success",
                "Failed",
            ],
            "web_browser": [
                "Chrome",
                "Browser",
                "Internet",
                "Web",
                "URL",
                "HTTP",
                "HTTPS",
                "Security",
                "Privacy",
                "Settings",
                "Bookmarks",
                "History",
            ],
            "office_app": [
                "Microsoft",
                "Office",
                "Document",
                "Word",
                "Excel",
                "PowerPoint",
                "File",
                "Edit",
                "View",
                "Insert",
                "Format",
                "Tools",
                "Help",
            ],
        }

        base_strings = category_strings.get(
            template.category,
            ["Application", "Program", "Software", "Version", "Copyright"],
        )

        # Add some random benign strings
        additional_strings = [
            "Version 1.0",
            "Copyright 2024",
            "All rights reserved",
            "Microsoft Corporation",
            "Windows",
            "System32",
            "Program Files",
        ]

        return base_strings + additional_strings[:5]  # Limit to 5 additional strings

    def save_templates(self) -> None:
        """Save current templates to database file."""
        try:
            data = {
                "templates": [
                    {
                        "name": template.name,
                        "category": template.category,
                        "characteristics": template.characteristics,
                        "section_names": template.section_names,
                        "import_dlls": template.import_dlls,
                        "common_functions": template.common_functions,
                    }
                    for template in self.templates
                ]
            }

            with open(self.template_db_path, "w") as f:
                json.dump(data, f, indent=2)

            logger.info(
                "action=templates_saved path=%s count=%d",
                self.template_db_path,
                len(self.templates),
            )

        except Exception as e:
            logger.error("action=template_save_failed error=%s", e)

    def add_template_from_pe(self, pe_data: bytes, name: str, category: str) -> bool:
        """Add a new template from a PE file.

        Args:
            pe_data: Raw PE file bytes
            name: Template name
            category: Template category

        Returns:
            True if template was added successfully
        """
        try:
            with PEReader(pe_data) as reader:
                characteristics = reader.get_pe_characteristics()
                sections = reader.get_sections()
                imports = reader.get_imports()

            # Extract section names
            section_names = [section.name for section in sections]

            # Group imports by DLL
            import_dlls = {}
            for imp in imports:
                if imp.dll_name not in import_dlls:
                    import_dlls[imp.dll_name] = []
                import_dlls[imp.dll_name].append(imp.function_name)

            # Create template
            template = BenignTemplate(
                name=name,
                category=category,
                characteristics=characteristics,
                section_names=section_names,
                import_dlls=list(import_dlls.keys()),
                common_functions=[
                    imp.function_name for imp in imports[:20]
                ],  # Limit to 20
            )

            self.templates.append(template)
            logger.info("action=template_added name=%s category=%s", name, category)
            return True

        except Exception as e:
            logger.error("action=template_add_failed name=%s error=%s", name, e)
            return False
