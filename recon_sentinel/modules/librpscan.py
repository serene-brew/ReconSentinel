"""
librpscan.py - High-level Python wrapper for librpscan shared library

This module provides convenient classes and functions for scanning targets
using different nmap presets (stealthy, aggressive, comprehensive, etc).

The module handles library loading, result parsing, and automatic memory
management for C library resources.

Usage:
    >>> from librpscan import RpscanClient
    >>> client = RpscanClient()
    >>> result = client.scan_stealthy("example.com")
    >>> client.print_result(result, "Target Scan")

Author: mintRaven-05, Contributed as part of ReconSentinel project
License: BSD-3-Clause (Copyright (c) 2025 knightsky-cpu)
"""

from __future__ import annotations

import os
from ctypes import CDLL, c_void_p, c_char_p, c_int
from dataclasses import dataclass
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

__version__: str = "1.0.0"
__author__: str = "mintRaven-05"
__all__: List[str] = [
    "RpscanClient",
    "ScanResult",
    "ScanPort",
]


@dataclass
class ScanPort:
    """Represents an open port found during scan"""
    port: int
    protocol: str
    service: str
    product: str
    version: str

    def __str__(self) -> str:
        return f"{self.port}/{self.protocol} - {self.service} ({self.product} {self.version})".strip()


@dataclass
class ScanResult:
    """Container for scan results with parsed data"""
    summary: List[str]
    ports: List[ScanPort]
    operating_systems: List[str]
    cpes: List[str]
    service_details: List[str]
    nse_scripts: List[str]
    host_addresses: List[str]
    hostnames: List[str]
    os_matches: List[str]
    os_classes: List[str]
    traceroute: List[str]
    port_details: List[str]

    def __str__(self) -> str:
        return f"ScanResult(ports={len(self.ports)}, os={len(self.operating_systems)}, scripts={len(self.nse_scripts)}, traces={len(self.traceroute)})"


class RpscanClient:
    """
    High-level client for scanning targets using librpscan presets.
    Handles library loading, result parsing, and memory management.
    """

    # Search paths for the library
    DEFAULT_SEARCH_PATHS: List[str] = [
        "./port-scanner/build/lib/librpscan.so",
    ]

    def __init__(self, lib_path: Optional[str] = None):
        """
        Initialize the scanner client.
        
        Automatically searches for librpscan.so in common locations if not specified.
        
        Args:
            lib_path: Path to the compiled librpscan.so shared object.
                     If None, searches in common build output directories.
            
        Raises:
            OSError: If the shared library cannot be found or loaded
        """
        # Determine library path
        if lib_path is None:
            lib_path = self._find_library()
        
        try:
            self.lib = CDLL(lib_path)
            self._setup_ctypes()
            self._lib_path = lib_path
        except OSError as e:
            raise OSError(
                f"Failed to load librpscan.so from {lib_path}. "
                f"Searched paths: {self.DEFAULT_SEARCH_PATHS}. "
                f"Error: {e}"
            )

        self.console = Console()

    @staticmethod
    def _find_library() -> str:
        """
        Search for librpscan.so in common locations.
        
        Returns:
            Path to the found library
            
        Raises:
            OSError: If library not found in any search path
        """
        for path in RpscanClient.DEFAULT_SEARCH_PATHS:
            expanded_path = os.path.expanduser(path)
            if os.path.isfile(expanded_path):
                return expanded_path
        
        # If not found, raise detailed error
        raise OSError(
            f"librpscan.so not found in any of the following locations:\n"
            + "\n".join(f"  - {p}" for p in RpscanClient.DEFAULT_SEARCH_PATHS)
            + "\n\nPlease build the project with:\n"
            + "  mkdir build && cd build && cmake -G Ninja .. && ninja\n"
            + "  cp lib/librpscan.so .."
        )

    def _setup_ctypes(self) -> None:
        """Configure ctypes function signatures for all exported functions"""
        # Define ScanResult as opaque pointer
        ScanResultType = c_void_p

        # Setup all scan functions (now with optional cookies parameter)
        functions = [
            ("scan_target", [c_char_p, c_char_p], ScanResultType),
            ("scan_target_stealthy", [c_char_p, c_char_p], ScanResultType),
            ("scan_target_aggressive", [c_char_p, c_char_p], ScanResultType),
            ("scan_target_comprehensive", [c_char_p, c_char_p], ScanResultType),
            ("scan_target_udp", [c_char_p, c_char_p], ScanResultType),
            ("scan_target_all_ports", [c_char_p, c_char_p], ScanResultType),
            ("scan_target_os_detection", [c_char_p, c_char_p], ScanResultType),
            ("scan_target_custom", [c_char_p, c_char_p, c_char_p], ScanResultType),
        ]

        for func_name, argtypes, restype in functions:
            func = getattr(self.lib, func_name)
            func.argtypes = argtypes
            func.restype = restype

        # Setup accessor functions
        self.lib.get_summary_count.argtypes = [ScanResultType]
        self.lib.get_summary_count.restype = c_int

        self.lib.get_summary_line.argtypes = [ScanResultType, c_int]
        self.lib.get_summary_line.restype = c_char_p

        self.lib.get_port_count.argtypes = [ScanResultType]
        self.lib.get_port_count.restype = c_int

        self.lib.get_port_row.argtypes = [ScanResultType, c_int]
        self.lib.get_port_row.restype = c_char_p

        self.lib.get_serviceinfo_count.argtypes = [ScanResultType]
        self.lib.get_serviceinfo_count.restype = c_int

        self.lib.get_serviceinfo_line.argtypes = [ScanResultType, c_int]
        self.lib.get_serviceinfo_line.restype = c_char_p

        self.lib.get_servicedetails_count.argtypes = [ScanResultType]
        self.lib.get_servicedetails_count.restype = c_int

        self.lib.get_servicedetails_line.argtypes = [ScanResultType, c_int]
        self.lib.get_servicedetails_line.restype = c_char_p

        self.lib.get_osdetection_count.argtypes = [ScanResultType]
        self.lib.get_osdetection_count.restype = c_int

        self.lib.get_osdetection_line.argtypes = [ScanResultType, c_int]
        self.lib.get_osdetection_line.restype = c_char_p

        self.lib.get_scripts_count.argtypes = [ScanResultType]
        self.lib.get_scripts_count.restype = c_int

        self.lib.get_scripts_line.argtypes = [ScanResultType, c_int]
        self.lib.get_scripts_line.restype = c_char_p

        self.lib.get_hostinfo_count.argtypes = [ScanResultType]
        self.lib.get_hostinfo_count.restype = c_int

        self.lib.get_hostinfo_line.argtypes = [ScanResultType, c_int]
        self.lib.get_hostinfo_line.restype = c_char_p

        self.lib.get_hostnames_count.argtypes = [ScanResultType]
        self.lib.get_hostnames_count.restype = c_int

        self.lib.get_hostnames_line.argtypes = [ScanResultType, c_int]
        self.lib.get_hostnames_line.restype = c_char_p

        self.lib.get_osmatches_count.argtypes = [ScanResultType]
        self.lib.get_osmatches_count.restype = c_int

        self.lib.get_osmatches_line.argtypes = [ScanResultType, c_int]
        self.lib.get_osmatches_line.restype = c_char_p

        self.lib.get_osclasses_count.argtypes = [ScanResultType]
        self.lib.get_osclasses_count.restype = c_int

        self.lib.get_osclasses_line.argtypes = [ScanResultType, c_int]
        self.lib.get_osclasses_line.restype = c_char_p

        self.lib.get_traceroute_count.argtypes = [ScanResultType]
        self.lib.get_traceroute_count.restype = c_int

        self.lib.get_traceroute_line.argtypes = [ScanResultType, c_int]
        self.lib.get_traceroute_line.restype = c_char_p

        self.lib.get_portdetails_count.argtypes = [ScanResultType]
        self.lib.get_portdetails_count.restype = c_int

        self.lib.get_portdetails_line.argtypes = [ScanResultType, c_int]
        self.lib.get_portdetails_line.restype = c_char_p

        self.lib.free_scan_result.argtypes = [ScanResultType]
        self.lib.free_scan_result.restype = None

    def _parse_result(self, c_result: c_void_p) -> ScanResult:
        """
        Parse raw C result into a ScanResult object.
        
        Args:
            c_result: Opaque pointer from C library
            
        Returns:
            ScanResult object with parsed data
        """
        # Parse summary
        summary = []
        for i in range(self.lib.get_summary_count(c_result)):
            line = self.lib.get_summary_line(c_result, i).decode()
            summary.append(line)

        # Parse ports
        ports = []
        for i in range(self.lib.get_port_count(c_result)):
            row = self.lib.get_port_row(c_result, i).decode().split("\t")
            if len(row) >= 5:
                port_obj = ScanPort(
                    port=int(row[0]),
                    protocol=row[1],
                    service=row[2],
                    product=row[3],
                    version=row[4],
                )
                ports.append(port_obj)

        # Parse service details
        service_details = []
        for i in range(self.lib.get_servicedetails_count(c_result)):
            line = self.lib.get_servicedetails_line(c_result, i).decode()
            service_details.append(line)

        # Parse service info tree
        operating_systems = []
        cpes = []
        current_section = None

        for i in range(self.lib.get_serviceinfo_count(c_result)):
            line = self.lib.get_serviceinfo_line(c_result, i).decode()
            if not line.startswith("  "):
                current_section = line
            else:
                item = line.strip()
                if current_section == "Operating Systems":
                    operating_systems.append(item)
                elif current_section == "CPEs":
                    cpes.append(item)

        # Parse NSE script output
        nse_scripts = []
        for i in range(self.lib.get_scripts_count(c_result)):
            line = self.lib.get_scripts_line(c_result, i).decode()
            nse_scripts.append(line)

        # Parse host addresses
        host_addresses = []
        for i in range(self.lib.get_hostinfo_count(c_result)):
            line = self.lib.get_hostinfo_line(c_result, i).decode()
            host_addresses.append(line)

        # Parse hostnames
        hostnames = []
        for i in range(self.lib.get_hostnames_count(c_result)):
            line = self.lib.get_hostnames_line(c_result, i).decode()
            hostnames.append(line)

        # Parse OS matches
        os_matches = []
        for i in range(self.lib.get_osmatches_count(c_result)):
            line = self.lib.get_osmatches_line(c_result, i).decode()
            os_matches.append(line)

        # Parse OS classes
        os_classes = []
        for i in range(self.lib.get_osclasses_count(c_result)):
            line = self.lib.get_osclasses_line(c_result, i).decode()
            os_classes.append(line)

        # Parse traceroute data
        traceroute = []
        for i in range(self.lib.get_traceroute_count(c_result)):
            line = self.lib.get_traceroute_line(c_result, i).decode()
            traceroute.append(line)

        # Parse port details
        port_details = []
        for i in range(self.lib.get_portdetails_count(c_result)):
            line = self.lib.get_portdetails_line(c_result, i).decode()
            port_details.append(line)

        return ScanResult(
            summary=summary,
            ports=ports,
            operating_systems=operating_systems,
            cpes=cpes,
            service_details=service_details,
            nse_scripts=nse_scripts,
            host_addresses=host_addresses,
            hostnames=hostnames,
            os_matches=os_matches,
            os_classes=os_classes,
            traceroute=traceroute,
            port_details=port_details,
        )

    def _execute_scan(self, target: str, scan_func_name: str, cookies: Optional[str] = None) -> ScanResult:
        """
        Execute a scan and return parsed result.
        
        Args:
            target: Target hostname or IP address
            scan_func_name: Name of the scan function to call
            cookies: Optional cookies string (e.g., "cookie1; cookie2")
            
        Returns:
            ScanResult object
        """
        scan_func = getattr(self.lib, scan_func_name)
        cookies_ptr = cookies.encode() if cookies else None
        c_result = scan_func(target.encode(), cookies_ptr)
        
        try:
            result = self._parse_result(c_result)
        finally:
            self.lib.free_scan_result(c_result)

        return result

    def scan(self, target: str, cookies: Optional[str] = None) -> ScanResult:
        """
        Default scan: service version detection on top 1000 ports.
        
        Args:
            target: Target hostname or IP address
            cookies: Optional cookies string (e.g., "cookie1; cookie2")
            
        Returns:
            ScanResult object
        """
        return self._execute_scan(target, "scan_target", cookies)

    def scan_stealthy(self, target: str, cookies: Optional[str] = None) -> ScanResult:
        """
        Stealthy scan: Slow (-T1), SYN stealth (-sS), minimal ports (top 100).
        
        WARNING: This scan is slow and may take several minutes.
        
        Args:
            target: Target hostname or IP address
            cookies: Optional cookies string (e.g., "cookie1; cookie2")
            
        Returns:
            ScanResult object
        """
        return self._execute_scan(target, "scan_target_stealthy", cookies)

    def scan_aggressive(self, target: str, cookies: Optional[str] = None) -> ScanResult:
        """
        Aggressive scan: Fast (-T4), OS detection, NSE scripts (-A).
        
        Includes service version, OS detection, and default scripts.
        Requires elevated privileges for some features.
        
        Args:
            target: Target hostname or IP address
            cookies: Optional cookies string (e.g., "cookie1; cookie2")
            
        Returns:
            ScanResult object
        """
        return self._execute_scan(target, "scan_target_aggressive", cookies)

    def scan_comprehensive(self, target: str, cookies: Optional[str] = None) -> ScanResult:
        """
        Comprehensive scan: Version detection, NSE scripts, top 10000 ports.
        
        More thorough than default scan but still relatively fast.
        
        Args:
            target: Target hostname or IP address
            cookies: Optional cookies string (e.g., "cookie1; cookie2")
            
        Returns:
            ScanResult object
        """
        return self._execute_scan(target, "scan_target_comprehensive", cookies)

    def scan_udp(self, target: str, cookies: Optional[str] = None) -> ScanResult:
        """
        UDP scan: Detects UDP services on top 1000 UDP ports.
        
        WARNING: UDP scans are slow by nature.
        
        Args:
            target: Target hostname or IP address
            cookies: Optional cookies string (e.g., "cookie1; cookie2")
            
        Returns:
            ScanResult object
        """
        return self._execute_scan(target, "scan_target_udp", cookies)

    def scan_all_ports(self, target: str, cookies: Optional[str] = None) -> ScanResult:
        """
        All ports scan: Scans all 65535 TCP ports.
        
        WARNING: This scan is VERY slow and may take hours.
        
        Args:
            target: Target hostname or IP address
            cookies: Optional cookies string (e.g., "cookie1; cookie2")
            
        Returns:
            ScanResult object
        """
        return self._execute_scan(target, "scan_target_all_ports", cookies)

    def scan_os_detection(self, target: str, cookies: Optional[str] = None) -> ScanResult:
        """
        OS detection scan: Operating system fingerprinting.
        
        Requires elevated privileges (root/admin).
        
        Args:
            target: Target hostname or IP address
            cookies: Optional cookies string (e.g., "cookie1; cookie2")
            
        Returns:
            ScanResult object
        """
        return self._execute_scan(target, "scan_target_os_detection", cookies)

    def scan_custom(self, target: str, flags: str, cookies: Optional[str] = None) -> ScanResult:
        """
        Custom scan with user-provided nmap flags.
        
        Allows complete control over nmap parameters for specialized scans.
        
        Args:
            target: Target hostname or IP address
            flags: Custom nmap flags (e.g., "-T4 -A -sV --script vuln")
                  See nmap documentation for available options
            cookies: Optional cookies string (e.g., "cookie1; cookie2")
            
        Returns:
            ScanResult object
            
        Examples:
            >>> client = RpscanClient()
            >>> # Scan with version detection and service detection
            >>> result = client.scan_custom("example.com", "-sV -O --top-ports 1000")
            >>> client.print_result(result)
            >>> 
            >>> # Scan with NSE scripts for vulnerability detection
            >>> result = client.scan_custom("example.com", "-sV --script vuln")
            >>> 
            >>> # Stealth syn scan with timing
            >>> result = client.scan_custom("example.com", "-T1 -sS -sV --top-ports 100")
        """
        scan_func = self.lib.scan_target_custom
        cookies_ptr = cookies.encode() if cookies else None
        c_result = scan_func(target.encode(), flags.encode(), cookies_ptr)
        
        try:
            result = self._parse_result(c_result)
        finally:
            self.lib.free_scan_result(c_result)

        return result

    def print_result(self, result: ScanResult, title: str = "Scan Results") -> None:
        """
        Pretty-print scan result using rich formatting.
        
        Args:
            result: ScanResult object to print
            title: Title for the output
        """
        # Summary section
        self.console.rule(f"{title} - Summary")
        for line in result.summary:
            self.console.print(f"  {line}")

        # Host information
        if result.host_addresses or result.hostnames:
            self.console.rule("Host Information")
            if result.host_addresses:
                self.console.print("[bold]Addresses:[/bold]")
                for addr in result.host_addresses:
                    self.console.print(f"  {addr}")
            if result.hostnames:
                self.console.print("[bold]Hostnames:[/bold]")
                for hostname in result.hostnames:
                    self.console.print(f"  {hostname}")

        # Ports table
        if result.ports:
            table = Table(title="Open Ports")
            table.add_column("Port", style="cyan")
            table.add_column("Proto", style="magenta")
            table.add_column("Service", style="green")
            table.add_column("Product", style="yellow")
            table.add_column("Version", style="blue")

            for port in result.ports:
                table.add_row(
                    str(port.port),
                    port.protocol,
                    port.service,
                    port.product,
                    port.version,
                )

            self.console.print(table)
        else:
            self.console.print("[yellow]No open ports found[/yellow]")

        # Port details
        # if result.port_details:
        #     self.console.rule("Port State Details")
        #     for detail in result.port_details:
        #         self.console.print(f"  [dim]{detail}[/dim]")

        # Service details
        # if result.service_details:
        #     self.console.rule("Service Details")
        #     for detail in result.service_details:
        #         self.console.print(f"  [bold cyan]{detail}[/bold cyan]")

        # NSE Script output
        if result.nse_scripts:
            self.console.rule("NSE Script Results")
            for script in result.nse_scripts:
                self.console.print(f"  [yellow]{script}[/yellow]")

        # OS Detection Matches
        if result.os_matches:
            self.console.rule("OS Detection Matches")
            for match in result.os_matches:
                self.console.print(f"  [bold magenta]{match}[/bold magenta]")

        # OS Classes
        if result.os_classes:
            self.console.rule("OS Classification")
            for osclass in result.os_classes:
                self.console.print(f"  [bold green]{osclass}[/bold green]")

        # Traceroute
        if result.traceroute:
            self.console.rule("Traceroute Information")
            for hop in result.traceroute:
                self.console.print(f"  [blue]{hop}[/blue]")

        # Service information tree
        if result.operating_systems or result.cpes:
            tree = Tree("Service Information")

            if result.operating_systems:
                os_node = tree.add("Operating Systems")
                for os in result.operating_systems:
                    os_node.add(os)

            if result.cpes:
                cpe_node = tree.add("CPEs")
                for cpe in result.cpes:
                    cpe_node.add(cpe)

            self.console.print(tree)


# Module-level initialization
if __name__ != "__main__":
    # This ensures the module can be imported cleanly
    pass


__doc__: str = """
librpscan - nmap scanning wrapper

This module provides the following main components:

Classes:
    RpscanClient: Main scanner client for performing various scan types
    ScanResult: Data container for parsed scan results
    ScanPort: Data container for individual port information

Functions:
    None - All functionality provided through classes

Example:
    >>> from librpscan import RpscanClient
    >>> client = RpscanClient()
    >>> result = client.scan_aggressive("scanme.nmap.org")
    >>> client.print_result(result, "Aggressive Scan Results")

Example (for custom librpscan.so path):
    >>> from librpscan import RpscanClient
    >>> client = RpscanClient("/path/to/librpscan.so")
    >>> result = client.scan_aggressive("scanme.nmap.org")
    >>> client.print_result(result, "Aggressive Scan Results")

Dependencies:
    - ctypes (standard library)
    - dataclasses (standard library)
    - rich (external package)
    - librpscan.so (compiled C library) [located inside ReconSentinel/port-scanner/build/lib of the main git repo]
SOURCE: https://github.com/serene-brew/ReconSentinel
"""
