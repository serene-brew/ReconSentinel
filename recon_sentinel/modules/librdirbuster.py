"""
librdirbuster.py - Python wrapper for librdirbuster shared library.

Provides a thin ctypes-based interface to run the C++ directory buster
engine and return parsed findings to Python callers.

Usage:
    >>> from recon_sentinel.modules.librdirbuster import run_scan
    >>> findings = run_scan("http://example.com", "./dir-buster/wordlist.txt", threads=20)
    >>> for f in findings:
    ...     print(f["status"], f["url"])

Author: ImonChakraborty, Contributed as part of ReconSentinel project
License: BSD-3-Clause (Copyright (c) 2025 knightsky-cpu)
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import List, Dict

try:
    from importlib.resources import files
except ImportError:
    # Python < 3.9 fallback
    from importlib_resources import files

# Development path fallback
_DEV_LIB_PATH = Path(__file__).resolve().parent.parent.parent / "dir-buster" / "build" / "librdirbuster.so"

# Lazy load the library
_lib = None


def _get_library():
    """Get the library, loading it if necessary."""
    global _lib
    if _lib is not None:
        return _lib
    
    lib_path = _find_library()
    _lib = ctypes.CDLL(str(lib_path))
    _lib.run_dirbuster.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    _lib.run_dirbuster.restype = ctypes.c_char_p
    return _lib


def _find_library() -> Path:
    """
    Find librdirbuster.so in installed package or development paths.
    
    Returns:
        Path to the library
        
    Raises:
        OSError: If library not found
    """
    # Try installed package location first
    try:
        lib_resource = files("recon_sentinel.libs") / "librdirbuster.so"
        # Check if the resource exists (works for both Path and Traversable)
        try:
            # Try as_path() for Traversable objects
            lib_path = lib_resource.as_path()
            if lib_path.is_file():
                return lib_path
        except (AttributeError, TypeError):
            # Fall back to string conversion and file check
            lib_path_str = str(lib_resource)
            if os.path.isfile(lib_path_str):
                return Path(lib_path_str)
    except (ImportError, ModuleNotFoundError, TypeError):
        # importlib.resources might not work in all cases, fall through
        pass
    except Exception:
        # Other errors, fall through
        pass
    
    # Fallback to development path
    if _DEV_LIB_PATH.is_file():
        return _DEV_LIB_PATH
    
    # If not found, raise error
    raise OSError(
        f"librdirbuster.so not found in any of the following locations:\n"
        f"  - recon_sentinel/libs/librdirbuster.so (installed package)\n"
        f"  - {_DEV_LIB_PATH} (development path)\n\n"
        f"Please build the project with:\n"
        f"  cd dir-buster && mkdir -p build && cd build && cmake .. && make\n"
        f"  Or install the package: pip install reconsentinel"
    )


def run_scan(url: str, wordlist_file: str, output_file: str = "", threads: int = 10) -> List[Dict[str, object]]:
    """Run the dirbuster scan and return parsed findings.

    Args:
        url: Base target URL (include scheme, e.g., http://example.com).
        wordlist_file: Path to a newline-delimited wordlist.
        output_file: Optional path for C++ layer to write raw output.
        threads: Worker thread count for the C++ engine.
    Returns:
        List of dictionaries with keys: ``status`` (int) and ``url`` (str).
    """
    lib = _get_library()
    raw = lib.run_dirbuster(
        url.encode(),
        wordlist_file.encode(),
        output_file.encode() if output_file else None,
        int(threads),
    )

    if not raw:
        return []

    lines = raw.decode().strip().splitlines()
    findings: List[Dict[str, object]] = []
    for line in lines:
        if not line.startswith("["):
            continue
        try:
            end_idx = line.index("]")
            status = int(line[1:end_idx])
            found_url = line[end_idx + 2 :]
            findings.append({"status": status, "url": found_url})
        except (ValueError, IndexError):
            continue

    return findings


__all__ = ["run_scan"]
