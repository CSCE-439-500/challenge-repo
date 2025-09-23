"""PE import table manipulation module for dead code and import injection.

This module provides capabilities to analyze and modify PE import tables
to inject benign imports and dead code for evasion purposes.
"""

import logging
import os
import secrets
import random
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass

from ..core.guards import require_redteam_mode, guard_can_write
from .reader import PEReader, PESectionInfo

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ImportEntry:
    """Represents a single import entry."""

    dll_name: str
    function_name: str
    ordinal: Optional[int] = None
    is_used: bool = True


@dataclass(frozen=True)
class ImportManipulationConfig:
    """Configuration for import table manipulation."""

    enable_fake_imports: bool = True
    enable_dead_code_injection: bool = True
    max_fake_imports: int = 50
    max_dead_functions: int = 20
    target_categories: List[str] = None
    preserve_original_imports: bool = True


class PEImportManipulator:
    """PE import table manipulator for evasion purposes.

    This class provides capabilities to inject fake imports and dead code
    to make PE files appear more benign while maintaining functionality.
    """

    def __init__(self, config: Optional[ImportManipulationConfig] = None):
        """Initialize import manipulator with configuration.

        Args:
            config: Import manipulation configuration options
        """
        require_redteam_mode()

        self.config = config or ImportManipulationConfig()
        self.benign_apis = self._load_benign_apis()

        logger.info("action=import_manipulator_initialized config=%s", self.config)

    def _load_benign_apis(self) -> Dict[str, List[str]]:
        """Load database of benign Windows API functions.

        Returns:
            Dictionary mapping DLL names to lists of function names
        """
        return {
            "kernel32.dll": [
                "GetCurrentProcess",
                "GetCurrentProcessId",
                "GetCurrentThreadId",
                "GetSystemTime",
                "GetTickCount",
                "GetVersion",
                "GetVersionEx",
                "IsDebuggerPresent",
                "OutputDebugStringA",
                "OutputDebugStringW",
                "Sleep",
                "GetLastError",
                "SetLastError",
                "FormatMessageA",
                "FormatMessageW",
                "GetModuleHandleA",
                "GetModuleHandleW",
                "LoadLibraryA",
                "LoadLibraryW",
                "FreeLibrary",
                "GetProcAddress",
                "CreateFileA",
                "CreateFileW",
                "ReadFile",
                "WriteFile",
                "CloseHandle",
                "CreateDirectoryA",
                "CreateDirectoryW",
                "DeleteFileA",
                "DeleteFileW",
                "FindFirstFileA",
                "FindFirstFileW",
                "FindNextFileA",
                "FindNextFileW",
                "GetFileAttributesA",
                "GetFileAttributesW",
                "SetFileAttributesA",
                "SetFileAttributesW",
                "GetFileSize",
                "GetFileTime",
                "SetFileTime",
                "GetSystemDirectoryA",
                "GetSystemDirectoryW",
                "GetWindowsDirectoryA",
                "GetWindowsDirectoryW",
                "GetTempPathA",
                "GetTempPathW",
                "GetEnvironmentVariableA",
                "GetEnvironmentVariableW",
                "SetEnvironmentVariableA",
                "SetEnvironmentVariableW",
                "GetComputerNameA",
                "GetComputerNameW",
                "GetUserNameA",
                "GetUserNameW",
            ],
            "user32.dll": [
                "GetDesktopWindow",
                "GetWindow",
                "GetParent",
                "GetWindowTextA",
                "GetWindowTextW",
                "SetWindowTextA",
                "SetWindowTextW",
                "GetWindowRect",
                "SetWindowPos",
                "ShowWindow",
                "UpdateWindow",
                "InvalidateRect",
                "InvalidateRgn",
                "RedrawWindow",
                "GetDC",
                "ReleaseDC",
                "GetWindowDC",
                "BeginPaint",
                "EndPaint",
                "GetMessageA",
                "GetMessageW",
                "PeekMessageA",
                "PeekMessageW",
                "TranslateMessage",
                "DispatchMessageA",
                "DispatchMessageW",
                "PostMessageA",
                "PostMessageW",
                "SendMessageA",
                "SendMessageW",
                "RegisterClassA",
                "RegisterClassW",
                "RegisterClassExA",
                "RegisterClassExW",
                "CreateWindowA",
                "CreateWindowW",
                "CreateWindowExA",
                "CreateWindowExW",
                "DestroyWindow",
                "DefWindowProcA",
                "DefWindowProcW",
                "LoadCursorA",
                "LoadCursorW",
                "LoadIconA",
                "LoadIconW",
                "LoadImageA",
                "LoadImageW",
                "GetSystemMetrics",
                "GetCursorPos",
                "SetCursorPos",
                "ShowCursor",
                "SetCursor",
                "LoadCursorFromFileA",
                "LoadCursorFromFileW",
            ],
            "gdi32.dll": [
                "CreateCompatibleDC",
                "CreateCompatibleBitmap",
                "SelectObject",
                "DeleteObject",
                "DeleteDC",
                "BitBlt",
                "StretchBlt",
                "GetPixel",
                "SetPixel",
                "GetDeviceCaps",
                "CreateFontA",
                "CreateFontW",
                "CreateFontIndirectA",
                "CreateFontIndirectW",
                "GetTextExtentPoint32A",
                "GetTextExtentPoint32W",
                "TextOutA",
                "TextOutW",
                "ExtTextOutA",
                "ExtTextOutW",
                "DrawTextA",
                "DrawTextW",
                "GetTextMetricsA",
                "GetTextMetricsW",
                "GetStockObject",
                "GetObjectA",
                "GetObjectW",
                "CreatePen",
                "CreateSolidBrush",
                "CreateHatchBrush",
                "CreatePatternBrush",
                "CreateDIBitmap",
                "CreateDIBSection",
                "GetDIBits",
                "SetDIBits",
            ],
            "advapi32.dll": [
                "RegOpenKeyExA",
                "RegOpenKeyExW",
                "RegCloseKey",
                "RegQueryValueExA",
                "RegQueryValueExW",
                "RegSetValueExA",
                "RegSetValueExW",
                "RegDeleteValueA",
                "RegDeleteValueW",
                "RegEnumKeyExA",
                "RegEnumKeyExW",
                "RegEnumValueA",
                "RegEnumValueW",
                "RegCreateKeyExA",
                "RegCreateKeyExW",
                "RegDeleteKeyA",
                "RegDeleteKeyW",
                "RegFlushKey",
                "RegLoadKeyA",
                "RegLoadKeyW",
                "RegSaveKeyA",
                "RegSaveKeyW",
                "RegRestoreKeyA",
                "RegRestoreKeyW",
                "RegConnectRegistryA",
                "RegConnectRegistryW",
                "RegUnLoadKeyA",
                "RegUnLoadKeyW",
                "OpenSCManagerA",
                "OpenSCManagerW",
                "OpenServiceA",
                "OpenServiceW",
                "StartServiceA",
                "StartServiceW",
                "ControlService",
                "QueryServiceStatus",
                "QueryServiceConfigA",
                "QueryServiceConfigW",
                "ChangeServiceConfigA",
                "ChangeServiceConfigW",
                "CreateServiceA",
                "CreateServiceW",
                "DeleteService",
                "CloseServiceHandle",
                "LookupAccountNameA",
                "LookupAccountNameW",
                "LookupAccountSidA",
                "LookupAccountSidW",
                "ConvertSidToStringSidA",
                "ConvertSidToStringSidW",
                "ConvertStringSidToSidA",
                "ConvertStringSidToSidW",
                "GetTokenInformation",
                "SetTokenInformation",
                "AdjustTokenPrivileges",
                "LookupPrivilegeValueA",
                "LookupPrivilegeValueW",
                "LookupPrivilegeNameA",
                "LookupPrivilegeNameW",
                "OpenProcessToken",
                "OpenThreadToken",
                "GetTokenInformation",
                "SetTokenInformation",
            ],
            "ole32.dll": [
                "CoInitialize",
                "CoUninitialize",
                "CoInitializeEx",
                "CoGetMalloc",
                "CoCreateInstance",
                "CoCreateInstanceEx",
                "CoGetClassObject",
                "CoRegisterClassObject",
                "CoRevokeClassObject",
                "CoGetObject",
                "CoGetInterfaceAndReleaseStream",
                "CoMarshalInterface",
                "CoUnmarshalInterface",
                "CoMarshalHresult",
                "CoUnmarshalHresult",
                "CoGetCallerTID",
                "CoGetCurrentProcess",
                "CoGetCurrentLogicalThreadId",
                "CoGetApartmentType",
                "CoGetContextToken",
                "CoGetDefaultContext",
                "CoGetMalloc",
                "CoGetMarshalSizeMax",
                "CoGetPSClsid",
                "CoGetStandardMarshal",
                "CoGetStdMarshalEx",
                "CoGetTreatAsClass",
                "CoGetUnmarshalClass",
                "CoIsHandlerConnected",
                "CoLockObjectExternal",
                "CoMarshalHresult",
                "CoMarshalInterface",
                "CoMarshalInterThreadInterfaceInStream",
                "CoQueryAuthenticationServices",
                "CoQueryClientBlanket",
                "CoQueryProxyBlanket",
                "CoRegisterChannelHook",
                "CoRegisterClassObject",
                "CoRegisterInitializeSpy",
                "CoRegisterMallocSpy",
                "CoRegisterMessageFilter",
                "CoRegisterPSClsid",
                "CoRegisterSurrogate",
                "CoReleaseMarshalData",
                "CoResumeClassObjects",
                "CoRevertToSelf",
                "CoRevokeClassObject",
                "CoSetCancelObject",
                "CoSetProxyBlanket",
                "CoSuspendClassObjects",
                "CoSwitchCallContext",
                "CoTaskMemAlloc",
                "CoTaskMemFree",
                "CoTaskMemRealloc",
                "CoUninitialize",
                "CoUnmarshalHresult",
                "CoUnmarshalInterface",
                "CoUnmarshalInterThreadInterfaceInStream",
                "CoWaitForMultipleHandles",
                "CoWaitForMultipleObjects",
            ],
            "shell32.dll": [
                "ShellExecuteA",
                "ShellExecuteW",
                "ShellExecuteExA",
                "ShellExecuteExW",
                "FindExecutableA",
                "FindExecutableW",
                "Shell_NotifyIconA",
                "Shell_NotifyIconW",
                "SHGetFileInfoA",
                "SHGetFileInfoW",
                "SHGetPathFromIDListA",
                "SHGetPathFromIDListW",
                "SHGetSpecialFolderPathA",
                "SHGetSpecialFolderPathW",
                "SHGetSpecialFolderLocation",
                "SHGetFolderPathA",
                "SHGetFolderPathW",
                "SHGetFolderLocation",
                "SHGetKnownFolderPath",
                "SHGetKnownFolderIDList",
                "SHGetDesktopFolder",
                "SHGetMalloc",
                "SHGetInstanceExplorer",
                "SHGetDataFromIDListA",
                "SHGetDataFromIDListW",
                "SHGetNewLinkInfoA",
                "SHGetNewLinkInfoW",
                "SHGetSettings",
                "SHSetSettings",
                "SHGetFolderPathAndSubDirA",
                "SHGetFolderPathAndSubDirW",
                "SHGetFolderPathAndSubDir",
                "SHGetFolderPathAndSubDirA",
                "SHGetFolderPathAndSubDirW",
                "SHGetFolderPathAndSubDir",
                "SHGetFolderPathAndSubDirA",
                "SHGetFolderPathAndSubDirW",
            ],
        }

    def analyze_imports(self, pe_data: bytes) -> List[ImportEntry]:
        """Analyze imports in a PE file.

        Args:
            pe_data: Raw PE file bytes

        Returns:
            List of ImportEntry objects representing current imports
        """
        try:
            with PEReader(pe_data) as reader:
                imports = reader.get_imports()

            import_entries = []
            for dll_name, functions in imports.items():
                for func_name in functions:
                    import_entries.append(
                        ImportEntry(
                            dll_name=dll_name, function_name=func_name, is_used=True
                        )
                    )

            logger.info("action=imports_analyzed count=%d", len(import_entries))
            return import_entries

        except Exception as e:
            logger.error("action=import_analysis_failed error=%s", e)
            return []

    def generate_fake_imports(
        self, existing_imports: List[ImportEntry]
    ) -> List[ImportEntry]:
        """Generate fake benign imports for injection.

        Args:
            existing_imports: List of existing imports to avoid duplicates

        Returns:
            List of fake ImportEntry objects
        """
        if not self.config.enable_fake_imports:
            return []

        # Get existing DLL names and function names to avoid duplicates
        existing_dlls = {imp.dll_name.lower() for imp in existing_imports}
        existing_functions = {
            (imp.dll_name.lower(), imp.function_name.lower())
            for imp in existing_imports
        }

        fake_imports = []
        max_imports = min(self.config.max_fake_imports, 100)  # Cap at 100

        # Select random DLLs and functions
        available_dlls = list(self.benign_apis.keys())
        random.shuffle(available_dlls)

        for dll_name in available_dlls:
            if len(fake_imports) >= max_imports:
                break

            if dll_name.lower() in existing_dlls:
                continue  # Skip if DLL already exists

            # Select random functions from this DLL
            functions = self.benign_apis[dll_name]
            num_functions = min(random.randint(3, 8), len(functions))
            selected_functions = random.sample(functions, num_functions)

            for func_name in selected_functions:
                if len(fake_imports) >= max_imports:
                    break

                if (dll_name.lower(), func_name.lower()) not in existing_functions:
                    fake_imports.append(
                        ImportEntry(
                            dll_name=dll_name,
                            function_name=func_name,
                            is_used=False,  # Mark as unused (dead import)
                        )
                    )

        logger.info("action=fake_imports_generated count=%d", len(fake_imports))
        return fake_imports

    def generate_dead_code_functions(self) -> List[str]:
        """Generate dead code function stubs.

        Returns:
            List of dead code function strings
        """
        if not self.config.enable_dead_code_injection:
            return []

        dead_functions = []
        max_functions = min(self.config.max_dead_functions, 30)  # Cap at 30

        # Generate various types of dead functions
        function_templates = [
            "void __deadcode_{}() {{ /* Unused function */ }}",
            "int __unused_{}() {{ return 0; }}",
            "void __helper_{}() {{ /* Helper function */ }}",
            "BOOL __check_{}() {{ return TRUE; }}",
            "DWORD __get_{}() {{ return 0; }}",
            "void __init_{}() {{ /* Initialization */ }}",
            "void __cleanup_{}() {{ /* Cleanup */ }}",
            "int __validate_{}() {{ return 1; }}",
            "void __process_{}() {{ /* Processing */ }}",
            "BOOL __verify_{}() {{ return FALSE; }}",
        ]

        for i in range(max_functions):
            template = random.choice(function_templates)
            func_name = f"func_{secrets.token_hex(4)}"
            dead_functions.append(template.format(func_name))

        logger.info("action=dead_code_generated count=%d", len(dead_functions))
        return dead_functions

    def create_import_manipulation_plan(self, pe_data: bytes) -> Dict[str, Any]:
        """Create a plan for import table manipulation.

        Args:
            pe_data: Raw PE file bytes

        Returns:
            Dictionary containing manipulation plan
        """
        # Analyze existing imports
        existing_imports = self.analyze_imports(pe_data)

        # Generate fake imports
        fake_imports = self.generate_fake_imports(existing_imports)

        # Generate dead code
        dead_code = self.generate_dead_code_functions()

        plan = {
            "existing_imports": existing_imports,
            "fake_imports": fake_imports,
            "dead_code": dead_code,
            "total_imports": len(existing_imports) + len(fake_imports),
            "dead_functions": len(dead_code),
        }

        logger.info(
            "action=import_manipulation_plan_created existing=%d fake=%d dead=%d",
            len(existing_imports),
            len(fake_imports),
            len(dead_code),
        )

        return plan

    def get_manipulation_report(
        self,
        original_imports: List[ImportEntry],
        manipulated_imports: List[ImportEntry],
    ) -> Dict[str, Any]:
        """Generate a report of import manipulation changes.

        Args:
            original_imports: Original import list
            manipulated_imports: Manipulated import list

        Returns:
            Dictionary containing manipulation report
        """
        report = {
            "original_import_count": len(original_imports),
            "manipulated_import_count": len(manipulated_imports),
            "import_increase": len(manipulated_imports) - len(original_imports),
            "fake_imports_added": len(
                [imp for imp in manipulated_imports if not imp.is_used]
            ),
            "dll_diversity": len(set(imp.dll_name for imp in manipulated_imports)),
            "original_dll_diversity": len(
                set(imp.dll_name for imp in original_imports)
            ),
        }

        return report
