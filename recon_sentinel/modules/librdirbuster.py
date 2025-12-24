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
from pathlib import Path
from typing import List, Dict

_LIB_PATH = Path(__file__).resolve().parent.parent.parent / "dir-buster" / "build" / "librdirbuster.so"
_lib = ctypes.CDLL(str(_LIB_PATH))

_lib.run_dirbuster.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
_lib.run_dirbuster.restype = ctypes.c_char_p


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
    raw = _lib.run_dirbuster(
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
