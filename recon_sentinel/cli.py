# ReconSentinel CLI — verbose mode, DNS fast path (opt-in), internal-host skipping (opt-in),
# parallel DNS workers (opt-in), and a comprehensive --help that embeds the full
# "ReconSentinel Command Reference (dev-box edition)".

from __future__ import annotations

import logging
import json
import re
import subprocess
import shutil
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Set, Tuple, Dict, List

import typer
from typer.core import TyperGroup
from rich.console import Console
import sys
import click

from .scope import Scope
from .modules.ct import fetch_ct_domains
from .modules.dns import query_dns
from .modules.librdirbuster import run_scan as run_dirbuster_scan
from .render import render_casefile, write_casefile_html
from .rules_loader import load_rules
from .utils import write_json, read_json

console = Console()


def _check_and_install_tinyxml2():
    """Check if libtinyxml2 libraries exist in /usr/lib and copy if missing."""
    usr_lib = Path("/usr/lib")
    required_libs = ["libtinyxml2.so", "libtinyxml2.so.11", "libtinyxml2.so.11.0.0"]
    missing_libs = []
    
    # Check which libraries are missing
    for lib in required_libs:
        if not (usr_lib / lib).exists():
            missing_libs.append(lib)
    
    # If any libraries are missing, try to copy them
    if missing_libs:
        # Find the package libs directory - try multiple methods
        libs_path = None
        
        # Method 1: Try importlib.resources (for installed package)
        try:
            from importlib.resources import files
            libs_resource = files("recon_sentinel.libs")
            try:
                libs_path = Path(str(libs_resource.as_path()))
            except (AttributeError, TypeError):
                # Try string conversion
                libs_str = str(libs_resource)
                if Path(libs_str).exists():
                    libs_path = Path(libs_str)
        except (ImportError, ModuleNotFoundError, Exception):
            pass
        
        # Method 2: Try relative to this file (for installed package)
        if libs_path is None or not libs_path.exists():
            libs_path = Path(__file__).parent / "libs"
        
        # Method 3: Try development path
        if libs_path is None or not libs_path.exists():
            libs_path = Path(__file__).parent.parent / "recon_sentinel" / "libs"
        
        print(f"\nSome libtinyxml2 libraries are missing in {usr_lib}")
        print(f"  Missing: {', '.join(missing_libs)}")
        
        # Check if source files exist
        all_exist = True
        for lib in missing_libs:
            if not (libs_path / lib).exists():
                print(f"Warning: {lib} not found in {libs_path}, skipping...")
                all_exist = False
        
        if all_exist:
            print(f"  Copying libraries to {usr_lib} (requires sudo)...")
            copy_success = True
            
            for lib in missing_libs:
                source = libs_path / lib
                dest = usr_lib / lib
                
                try:
                    # Use sudo to copy - don't capture output to allow password prompt
                    # Use None for stdin/stdout/stderr to inherit from parent (allows password prompt)
                    result = subprocess.run(
                        ["sudo", "cp", str(source), str(dest)],
                        stdin=None,  # Inherit stdin (allows password prompt)
                        stdout=None,  # Inherit stdout
                        stderr=None,  # Inherit stderr
                        timeout=120  # Longer timeout for password entry
                    )
                    if result.returncode == 0:
                        print(f"  Copied {lib}")
                    else:
                        print(f"  Failed to copy {lib} (exit code: {result.returncode})")
                        copy_success = False
                except subprocess.TimeoutExpired:
                    print(f"  Timeout while copying {lib} (password prompt may have timed out)")
                    copy_success = False
                except (FileNotFoundError, PermissionError) as e:
                    print(f"  Failed to copy {lib}: {e}")
                    copy_success = False
            
            if copy_success:
                # Update library cache if ldconfig exists
                if shutil.which("ldconfig"):
                    print("  Updating library cache...")
                    try:
                        subprocess.run(
                            ["sudo", "ldconfig"],
                            stdin=None,  # Inherit stdin
                            stdout=None,  # Inherit stdout
                            stderr=None,  # Inherit stderr
                            timeout=30
                        )
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        pass
                print("  libtinyxml2 libraries installed\n")
            else:
                print("  Some libraries could not be copied (continuing anyway...)\n")
        else:
            print("  Some libraries could not be copied (continuing anyway...)\n")


def _print_help():
    """Print simple help menu."""
    help_text = """Usage: recon <command> [options]

Commands:
  run     Run passive recon against the defined scope
  diff    Diff two runs to see what's new/removed

Run Command Options:
  --scope PATH          Path to scope.yaml (or use -i/--interactive)
  --out PATH            Output directory base (default: runs)
  --tag STRING          Optional run tag, appended to run folder name
  -i, --interactive     Prompt for scope values interactively
  -v, --verbose         Show detailed progress messages
  --dns-fast            Query only A/AAAA records for faster results
  --skip-internal       Skip internal-looking hosts
  --dns-workers N       Parallel DNS worker threads (default: 0/1 = serial)
  --skip-port-scan      Skip port scanning phase even if configured

Diff Command Options:
  --a PATH              Path to older run dir (required)
  --b PATH              Path to newer run dir (required)
  --out PATH            Output markdown path (default: diff.md)

Global Options:
  --version             Show version information
  -h, --help            Show this help message

Examples:
  recon run -i
  recon run --scope scope.yaml --out runs
  recon diff --a runs/run-20250101-000000Z --b runs/run-20250102-000000Z
"""
    print(help_text)


def _print_run_help():
    """Print help for run command."""
    help_text = """Usage: recon run [OPTIONS]

Run passive recon against the defined scope.

Options:
  --scope PATH          Path to scope.yaml (or use -i/--interactive)
  --out PATH            Output directory base (default: runs)
  --tag STRING          Optional run tag, appended to run folder name
  -i, --interactive     Prompt for scope values interactively
  -v, --verbose         Show detailed progress messages
  --dns-fast            Query only A/AAAA records for faster results
  --skip-internal       Skip internal-looking hosts
  --dns-workers INTEGER Parallel DNS worker threads (default: 0/1 = serial)
  --skip-port-scan      Skip port scanning phase even if configured
  -h, --help            Show this help message
"""
    print(help_text)


def _print_diff_help():
    """Print help for diff command."""
    help_text = """Usage: recon diff [OPTIONS]

Diff two runs to see what's new/removed.

Options:
  --a PATH    Path to older run dir (required)
  --b PATH    Path to newer run dir (required)
  --out PATH  Output markdown path (default: diff.md)
  -h, --help  Show this help message
"""
    print(help_text)

def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")


def _list_runs(out_dir: Path):
    """Return run directories like run-YYYYMMDD-HHMMSSZ (oldest→newest)."""
    return sorted([p for p in out_dir.glob("run-*") if p.is_dir()])


def _load_hosts(artifacts_dir: Path) -> Set[str]:
    """
    Load inventory_hosts.json from a run's artifacts directory.
    Accepts either a list of hosts or a dict with a 'hosts'/'items' list.
    Returns an empty set on any error.
    """
    inv = artifacts_dir / "inventory_hosts.json"
    if not inv.exists():
        return set()
    try:
        data = json.loads(inv.read_text(encoding="utf-8"))
    except Exception:
        return set()

    if isinstance(data, list):
        return set(str(x).strip().lower() for x in data if str(x).strip())
    if isinstance(data, dict):
        for k in ("hosts", "items"):
            v = data.get(k)
            if isinstance(v, list):
                return set(str(x).strip().lower() for x in v if str(x).strip())
    return set()


def _compute_delta(current_artifacts: Path, out_dir: Path):
    """
    Compare the current run's hosts to the previous run in `out_dir`.
    Returns a dict:
      {
        "prev_run": "run-YYYYMMDD-HHMMSSZ[-tag]" | None,
        "counts": {"new": int, "removed": int},
        "new_hosts": [...], "removed_hosts": [...]
      }
    """
    runs = _list_runs(out_dir)
    if not runs or len(runs) < 2:
        return {
            "prev_run": None,
            "counts": {"new": 0, "removed": 0},
            "new_hosts": [],
            "removed_hosts": [],
        }

    prev_run = runs[-2]
    prev_hosts = _load_hosts(prev_run / "artifacts")
    curr_hosts = _load_hosts(current_artifacts)

    new_hosts = sorted(curr_hosts - prev_hosts)
    removed_hosts = sorted(prev_hosts - curr_hosts)

    return {
        "prev_run": prev_run.name,
        "counts": {"new": len(new_hosts), "removed": len(removed_hosts)},
        "new_hosts": new_hosts,
        "removed_hosts": removed_hosts,
    }


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(message)s")


def _looks_internal(host: str) -> bool:
    """
    Heuristic for internal-looking hosts.
    Conservative defaults: match *.corp.* or obvious internal suffixes.
    (Skipped only when --skip-internal is set.)
    """
    h = host.lower()
    if ".corp." in h:
        return True
    if h.endswith(".internal") or h.endswith(".local") or h.endswith(".lan"):
        return True
    return False


def _filter_records_dns_fast(records: Dict[str, list]) -> Dict[str, list]:
    """Keep only A/AAAA when --dns-fast is set (output-only fast path)."""
    return {k: v for k, v in records.items() if k in ("A", "AAAA") and v}


def _dns_worker(host: str, resolvers: List[str]) -> Tuple[str, Dict[str, list]]:
    """Call the existing query_dns for a single host (worker wrapper)."""
    recs = query_dns(host, resolvers)
    return host, recs


def _normalize_url(value: str) -> str:
    """Ensure a URL has a scheme; default to http:// when missing."""
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return f"http://{value}"


# Create the Typer app
app = typer.Typer(
    name="recon",
    add_completion=False,
    no_args_is_help=False,  # We handle help manually
    rich_markup_mode=None,
)

def _print_version():
    """Print version information from VERSION file."""
    version_file = Path(__file__).parent.parent / "VERSION"
    if version_file.exists():
        print(version_file.read_text(encoding="utf-8").strip())
    else:
        print("""
TOOL:    ReconSentinel
VERSION: v1.0.0
LICENSE: BSD-3-CLAUSE
AUTHOR:  Serene-Brew Org. and Members
SOURCE:  https://github.com/serene-brew/ReconSentinel

Copyright (c) 2025, knightsky-cpu
Licensed to Serene-Brew
https://github.com/serene-brew
serene.brew.git@gmail.com
        """)

@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Show version information and exit."),
):
    """Main callback."""
    if version:
        _print_version()
        raise typer.Exit()


@app.command(no_args_is_help=False)
def run(
    scope: Optional[Path] = typer.Option(
        None,
        "--scope",
        exists=False,
        readable=False,
        help="Path to scope.yaml (or use -i/--interactive to enter values).",
    ),
    out: Path = typer.Option(
        Path("runs"),
        "--out",
        help="Output directory base.",
    ),
    tag: str = typer.Option(
        "",
        "--tag",
        help="Optional run tag, appended to run folder name.",
    ),
    interactive: bool = typer.Option(
        False,
        "--interactive",
        "-i",
        help="Prompt for scope values (org, domains, seeds, resolvers).",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed progress messages (spinner + periodic counters).",
    ),
    dns_fast: bool = typer.Option(
        False,
        "--dns-fast",
        help="(Opt-in) Query only A/AAAA records for faster results.",
    ),
    skip_internal: bool = typer.Option(
        False,
        "--skip-internal",
        help="(Opt-in) Skip internal-looking hosts (e.g., *.corp.*, .internal, .local, .lan).",
    ),
    dns_workers: int = typer.Option(
        0,
        "--dns-workers",
        help="(Opt-in) Parallel DNS worker threads (e.g., 10–50). Default 0/1 = serial.",
    ),
    skip_port_scan: bool = typer.Option(
        False,
        "--skip-port-scan",
        help="Skip the port scanning phase even if port_scan_mode is configured.",
    ),
):
    """Run passive recon against the defined scope."""
    _setup_logging(verbose)

    # Build Scope from prompts if interactive; otherwise load from YAML path.
    if interactive:
        org = typer.prompt("Organization", default="Local Lab")

        domains_str = typer.prompt("Domain(s) (comma or space separated)", default="")
        domains = [d.strip().lower() for d in re.split(r"[,\s]+", domains_str) if d.strip()]
        if not domains:
            typer.echo("No domains entered; aborting.")
            raise typer.Exit(1)

        seeds_str = typer.prompt("Seed host(s) (optional, comma/space separated)", default="")
        seeds_hosts = [h.strip().lower() for h in re.split(r"[,\s]+", seeds_str) if h.strip()]

        notes = typer.prompt("Notes (optional)", default="")
        resolvers_str = typer.prompt("Resolvers (comma-separated)", default="1.1.1.1,8.8.8.8")
        resolvers = [r.strip() for r in resolvers_str.split(",") if r.strip()]
        passive = typer.confirm("Passive-only mode?", default=True)

        # Port Scanner Configuration
        console.print("\n[bold cyan]Port Scanner Configuration[/bold cyan]")
        enable_port_scan = typer.confirm("Enable port scanning?", default=False)
        port_scan_mode = []
        port_scan_cookies = None
        
        if enable_port_scan:
            port_mode_options = [
                "default",
                "stealthy",
                "aggressive",
                "comprehensive",
                "udp",
                "all_ports",
                "os_detection",
                "custom"
            ]
            console.print("Available modes: default, stealthy, aggressive, comprehensive, udp, all_ports, os_detection, custom")
            port_mode = typer.prompt("Port scan mode", default="aggressive")
            
            # Validate mode
            if port_mode not in port_mode_options:
                console.print(f"[yellow]Warning: '{port_mode}' is not a recognized mode. Using 'default'.[/yellow]")
                port_mode = "default"
            
            port_scan_mode.append(port_mode)
            
            # If custom mode, ask for flags
            if port_mode == "custom":
                custom_flags = typer.prompt("Custom nmap flags (e.g., '-T4 -A -sV')", default="-T4 -A")
                if custom_flags:
                    port_scan_mode.append(custom_flags)
            
            # Ask for cookies (optional)
            enable_cookies = typer.confirm("Use cookies for port scanning?", default=False)
            if enable_cookies:
                cookies_str = typer.prompt("Cookies (comma or space separated, e.g., '123456789' or 'session_id=abc123')", default="")
                if cookies_str:
                    cookies_list = [c.strip() for c in re.split(r"[,\s]+", cookies_str) if c.strip()]
                    if cookies_list:
                        port_scan_cookies = cookies_list

        # DirBuster Configuration
        console.print("\n[bold cyan]DirBuster Configuration[/bold cyan]")
        enable_dirbuster = typer.confirm("Enable DirBuster scanning?", default=False)
        dirbuster_wordlist = ""
        if enable_dirbuster:
            wordlist_path = typer.prompt("Wordlist file path", default="dir-buster/wordlists/example.txt")
            if wordlist_path:
                dirbuster_wordlist = wordlist_path

        scope_obj = Scope(
            org=org,
            domains=domains,
            policy={"passive_only": passive},
            notes=notes,
            resolvers=resolvers,
            seeds={"hosts": seeds_hosts},
            port_scan_mode=port_scan_mode if enable_port_scan else [],
            port_scan_cookies=port_scan_cookies,
            dirbuster_wordlist=dirbuster_wordlist,
        )
        
        # Show configuration summary
        console.print("\n[bold green]Configuration Summary:[/bold green]")
        console.print(f"  Organization: {org}")
        console.print(f"  Domains: {', '.join(domains)}")
        console.print(f"  Passive mode: {passive}")
        if enable_port_scan:
            console.print(f"  Port scanning: Enabled ({port_scan_mode[0] if port_scan_mode else 'N/A'})")
            if port_scan_cookies:
                console.print(f"  Port scan cookies: {', '.join(port_scan_cookies)}")
        else:
            console.print("  Port scanning: Disabled")
        if enable_dirbuster and dirbuster_wordlist:
            console.print(f"  DirBuster: Enabled (wordlist: {dirbuster_wordlist})")
        else:
            console.print("  DirBuster: Disabled")
        console.print("")
    else:
        if scope is None:
            typer.echo("Provide --scope PATH or use --interactive (-i) to build one.")
            raise typer.Exit(2)
        scope_obj = Scope.load(str(scope))

    run_dir = out / f"run-{_stamp()}{('-' + tag) if tag else ''}"
    artifacts_dir = run_dir / "artifacts"
    run_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    console.print("")
    console.print('[bold cyan]██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗[/bold cyan]') 
    console.print('[bold cyan]██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║[/bold cyan]') 
    console.print('[bold cyan]██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║[/bold cyan]') 
    console.print('[bold cyan]██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║[/bold cyan]') 
    console.print('[bold cyan]██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗[/bold cyan]') 
    console.print('[bold cyan]╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝[/bold cyan]') 
    console.print("")
    console.print("[dim yellow]v1.0.0[/dim yellow]")
    console.print("[dim yellow]Copyright (c) 2025, knightsky-cpu[/dim yellow]")
    console.print("[dim yellow]Licensed to Serene-Brew[/dim yellow]")
    console.print("")
    console.print("")
    console.rule("Passive Reconnaissance")
    console.print(f"[bold]Org:[/] {scope_obj.org}")
    console.print(f"[bold]Domains:[/] {', '.join(scope_obj.domains)}\n")

    # Hint only when user didn't opt-in to any speed-ups
    if not (dns_fast or skip_internal or (dns_workers and dns_workers > 1)):
        console.print("[dim]Tip: for faster results, try --dns-fast, --skip-internal, or --dns-workers N.[/dim]")

    all_hosts: Set[str] = set()

    # 1) CT discovery
    logging.info("CT: starting certificate transparency discovery...")
    for base in scope_obj.domains:
        console.print(f"[cyan]ct:[/] querying crt.sh for {base}...")
        hosts = fetch_ct_domains(base)
        hosts = [h for h in hosts if scope_obj.in_scope_domain(h)]
        console.print(f"  found {len(hosts)} hosts in-scope")
        write_json(artifacts_dir / f"ct_{base}.json", hosts)
        all_hosts.update(hosts)
    logging.info("CT: done.")

    # Include seed hosts from scope (filtered to in-scope)
    seed_hosts = {h.strip().lower() for h in scope_obj.seeds.get("hosts", []) if h.strip()}
    seed_hosts = {h for h in seed_hosts if scope_obj.in_scope_domain(h)}
    all_hosts.update(seed_hosts)
    write_json(artifacts_dir / "seed_hosts.json", sorted(list(seed_hosts)))

    # Optional host filtering (skip internal-looking hosts) — opt-in only
    if skip_internal:
        before = len(all_hosts)
        all_hosts = {h for h in all_hosts if not _looks_internal(h)}
        skipped = before - len(all_hosts)
        logging.info(f"Scope filter: skipped {skipped} internal-looking host(s).")

    all_hosts = sorted(all_hosts)
    write_json(artifacts_dir / "inventory_hosts.json", all_hosts)

    # 2) DNS records
    logging.info("DNS: starting resolution pipeline...")
    inventory: List[Dict[str, object]] = []
    dns_issues: List[Dict[str, object]] = []

    def _process_host(h: str) -> Tuple[str, Dict[str, list], Optional[dict]]:
        recs = query_dns(h, scope_obj.resolvers)
        if dns_fast:
            recs = _filter_records_dns_fast(recs)

        issue = None
        # simple heuristics for potential dangling CNAMEs
        if any(
            v
            for v in recs.get("CNAME", [])
            if any(s in v.lower() for s in ["amazonaws.com", "github.io", "herokuapp.com", "azurewebsites.net"])
        ):
            issue = {"host": h, "type": "dangling_cname_potential", "evidence": recs.get("CNAME", [])}
        return h, recs, issue

    if dns_workers and dns_workers > 1:
        logging.info(f"DNS: parallel mode enabled with {dns_workers} worker(s).")
        with console.status("Resolving DNS (parallel)…", spinner="dots"):
            with ThreadPoolExecutor(max_workers=dns_workers) as ex:
                futures = {ex.submit(_process_host, h): h for h in all_hosts}
                done = 0
                for fut in as_completed(futures):
                    h, recs, issue = fut.result()
                    inventory.append({"host": h, "records": recs})
                    if issue:
                        dns_issues.append(issue)
                    done += 1
                    if verbose and (done % 25 == 0):
                        logging.debug(f"DNS progress: {done}/{len(all_hosts)} hosts")
    else:
        with console.status("Resolving DNS…", spinner="dots"):
            for idx, h in enumerate(all_hosts, 1):
                h, recs, issue = _process_host(h)
                inventory.append({"host": h, "records": recs})
                if issue:
                    dns_issues.append(issue)
                if verbose and (idx % 25 == 0):
                    logging.debug(f"DNS progress: {idx}/{len(all_hosts)} hosts")

    write_json(artifacts_dir / "dns_records.json", inventory)
    write_json(artifacts_dir / "dns_issues.json", dns_issues)
    logging.info("DNS: done.")

    # 2.5) Port Scanning — only if port_scan_mode set and not skipped
    portscan_artifacts = []
    if not skip_port_scan and getattr(scope_obj, 'port_scan_mode', []) and len(scope_obj.port_scan_mode) > 0:
        from .modules.librpscan import RpscanClient
        from dataclasses import asdict
        port_mode = scope_obj.port_scan_mode[0] if isinstance(scope_obj.port_scan_mode, list) and len(scope_obj.port_scan_mode) > 0 else ''
        port_flags = scope_obj.port_scan_mode[1] if isinstance(scope_obj.port_scan_mode, list) and len(scope_obj.port_scan_mode) > 1 and isinstance(scope_obj.port_scan_mode[1], str) else None
        # Extract cookies from scope if available
        port_cookies = None
        if hasattr(scope_obj, 'port_scan_cookies') and scope_obj.port_scan_cookies:
            # Format cookies: if a cookie doesn't contain "=", format it as "cookie=value"
            formatted_cookies = []
            for cookie in scope_obj.port_scan_cookies:
                if "=" in cookie:
                    formatted_cookies.append(cookie)
                else:
                    # If it's just a value, format it as "cookie=value"
                    formatted_cookies.append(f"cookie={cookie}")
            # Join cookies with semicolons for nmap
            port_cookies = "; ".join(formatted_cookies)
        portscan_client = RpscanClient()
        console.print("[bold][cyan]Launching port scanning as per scope.yaml...[/cyan][/bold]")
        if port_cookies:
            console.print(f"[dim]Using cookies: {port_cookies}[/dim]")
        # Only scan the base domains from scope.yaml, not discovered subdomains
        for domain in scope_obj.domains:
            try:
                console.print(f"\n[bold]Scanning {domain}...[/bold]")
                if port_mode == 'stealthy':
                    result = portscan_client.scan_stealthy(domain, port_cookies)
                elif port_mode == 'aggressive':
                    result = portscan_client.scan_aggressive(domain, port_cookies)
                elif port_mode == 'comprehensive':
                    result = portscan_client.scan_comprehensive(domain, port_cookies)
                elif port_mode == 'udp':
                    result = portscan_client.scan_udp(domain, port_cookies)
                elif port_mode == 'all_ports':
                    result = portscan_client.scan_all_ports(domain, port_cookies)
                elif port_mode == 'os_detection':
                    result = portscan_client.scan_os_detection(domain, port_cookies)
                elif port_mode == 'custom' and port_flags:
                    result = portscan_client.scan_custom(domain, port_flags, port_cookies)
                else:
                    result = portscan_client.scan(domain, port_cookies)

                # Print structured output to terminal
                portscan_client.print_result(result, f"Port Scan: {domain}")

                artifact_path = artifacts_dir / f"port_scanner_{domain}.json"
                write_json(artifact_path, asdict(result))
                portscan_artifacts.append({"domain": domain, "artifact_path": str(artifact_path)})
            except Exception as ex:
                console.print(f"[red]Port scan failed for {domain}: {ex}[/red]")
        console.print(f"\n[green][/] Port scan artifacts written for {len(portscan_artifacts)} domains.")
    elif skip_port_scan:
        console.print("[yellow]Skipping port scan phase due to --skip-port-scan\n[/yellow]")
    elif not getattr(scope_obj, 'port_scan_mode', []):
        console.print("[dim]No port_scan_mode found in scope.yaml; skipping port scan phase.[/dim]")

    # 2.6) DirBuster — run against scope domains when wordlist is provided
    dirbuster_results = []
    console.rule("DirBuster Scanning Phase")
    if getattr(scope_obj, "dirbuster_wordlist", ""):
        wordlist_path = Path(scope_obj.dirbuster_wordlist).expanduser()
        if not wordlist_path.exists():
            console.print(f"[yellow]DirBuster skipped: wordlist not found at {wordlist_path}[/yellow]")
        else:
            console.print(f"[bold][cyan]Running DirBuster with wordlist: {wordlist_path}[/cyan][/bold]")
            for domain in scope_obj.domains:
                target_url = _normalize_url(domain)
                safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", domain)
                artifact_json = artifacts_dir / f"dirbuster_{safe_name}.json"
                try:
                    findings = run_dirbuster_scan(target_url, str(wordlist_path), output_file="", threads=10)
                    write_json(artifact_json, findings)
                    dirbuster_results.append({
                        "target": target_url,
                        "findings": findings,
                        "artifact_path": str(artifact_json),
                    })
                    console.print(f"  [green]DirBuster[/green] {target_url} → {len(findings)} finding(s)")
                except Exception as ex:
                    console.print(f"[red]DirBuster failed for {target_url}: {ex}[/red]")
            console.print(f"\n[green][/] DirBuster artifacts written for {len(dirbuster_results)} domain(s).\n")
    else:
        console.print("[dim]No dirbuster_wordlist found in scope.yaml; skipping DirBuster phase.[/dim]")

    # 3) Findings: map to rules/explanations (with safe fallback)
    logging.info("Findings: analyzing artifacts…")
    try:
        rules = load_rules(Path(__file__).parent / "rules" / "recon_rules.yaml")
    except FileNotFoundError:
        rules = {"findings": {}}
    findings = []

    # wildcard exposure hint (naive): if many subdomains for a base
    counts = Counter([h.split(".", maxsplit=1)[1] if "." in h else h for h in all_hosts])
    for base, cnt in counts.items():
        if cnt >= 30 and base in scope_obj.domains:
            rule = rules["findings"].get("wildcard_cert", {})
            findings.append({
                "title": "Potential Wildcard Exposure",
                "asset": base,
                "why": rule.get("why", ""),
                "evidence": f"{cnt} subdomains observed in CT for {base}",
                "next_steps": rule.get("next_steps", [])
            })

    for issue in dns_issues:
        rule = rules["findings"].get("dangling_cname", {})
        findings.append({
            "title": "Potential Dangling CNAME",
            "asset": issue["host"],
            "why": rule.get("why", ""),
            "evidence": ", ".join(issue.get("evidence", [])),
            "next_steps": rule.get("next_steps", [])
        })

    # Inventory summary lines (respect dns_fast output)
    inv_summary = []
    for item in inventory:
        host = item["host"]
        recs = item["records"]
        summary_bits = []
        for rt in ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]:
            if recs.get(rt):
                summary_bits.append(f"{rt}:{len(recs[rt])}")
        inv_summary.append({"host": host, "records_summary": ", ".join(summary_bits) if summary_bits else "(no records)"})

    # 4) Compute simple stats + delta vs previous run
    delta = _compute_delta(artifacts_dir, out)
    write_json(artifacts_dir / "delta.json", delta)

    stats = {
        "total_subdomains": len(all_hosts),
        "new_subdomains": delta["counts"]["new"],
        "dns_issues": dns_issues,
        "dirbuster_findings": sum(len(r.get("findings", [])) for r in dirbuster_results),
    }

    # Load port scan data for reporting
    portscan_data = []
    for artifact_info in portscan_artifacts:
        try:
            artifact_path = Path(artifact_info["artifact_path"])
            if artifact_path.exists():
                scan_data = read_json(artifact_path)
                portscan_data.append({
                    "domain": artifact_info["domain"],
                    "artifact_path": str(artifact_path),
                    "data": scan_data
                })
        except Exception as ex:
            logging.warning(f"Failed to load port scan data from {artifact_info.get('artifact_path', 'unknown')}: {ex}")

    # 5) Render casefile (Markdown + HTML)
    logging.info("Render: generating casefile.md…")
    context = {
        "org": scope_obj.org,
        "run_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scope_domains": scope_obj.domains,
        "stats": stats,
        "findings": findings,
        "inventory": inv_summary,
        "delta": delta,  # so templates can show what's new/removed
        "portscan_artifacts": portscan_artifacts,
        "portscan_data": portscan_data,
        "dirbuster_results": dirbuster_results,
    }

    template_dir = Path(__file__).parent / "templates"
    report_md = render_casefile(template_dir, context)
    with open(run_dir / "casefile.md", "w", encoding="utf-8") as f:
        f.write(report_md)

    logging.info("Render: generating casefile.html…")
    write_casefile_html(run_dir / "casefile.html", template_dir, context)

    console.print(f"\n[green]✔[/] Wrote artifacts → {artifacts_dir}")
    console.print(f"[green]✔[/] Wrote report → {run_dir / 'casefile.md'}")
    console.print(f"[green]✔[/] Wrote HTML → {run_dir / 'casefile.html'}")
    if delta["prev_run"]:
        console.print(
            f"[bold]Δ since {delta['prev_run']}:[/] +{delta['counts']['new']} new, -{delta['counts']['removed']} removed"
        )
    else:
        console.print(f"[bold]Δ:[/] first run — no prior data")


@app.command(no_args_is_help=False)
def diff(
    a: Path = typer.Option(
        ...,
        "--a",
        exists=True,
        help="Path to older run dir.",
    ),
    b: Path = typer.Option(
        ...,
        "--b",
        exists=True,
        help="Path to newer run dir.",
    ),
    out: Path = typer.Option(
        Path("diff.md"),
        "--out",
        help="Output markdown path.",
    ),
):
    """Diff two runs to see what's new/removed."""
    hosts_a = set(read_json(a / "artifacts" / "inventory_hosts.json"))
    hosts_b = set(read_json(b / "artifacts" / "inventory_hosts.json"))
    new = sorted(list(hosts_b - hosts_a))
    gone = sorted(list(hosts_a - hosts_b))

    lines = ["# ReconSentinel Diff\n"]
    lines.append(f"**New hosts:** {len(new)}\n")
    for h in new:
        lines.append(f"- `{h}`\n")
    lines.append("\n")
    lines.append(f"**Removed hosts:** {len(gone)}\n")
    for h in gone:
        lines.append(f"- `{h}`\n")

    with open(out, "w", encoding="utf-8") as f:
        f.writelines(lines)

    console.print(f"[green]✔[/] Wrote diff → {out}")


def _handle_help_and_version():
    """Intercept help and version requests before Typer processes them."""
    # Handle version
    if "--version" in sys.argv:
        _print_version()
        sys.exit(0)
    
    # Handle help requests manually for clean output
    if "--help" in sys.argv or "-h" in sys.argv:
        # Determine which help to show
        if len(sys.argv) == 2:
            # Main help
            _print_help()
            sys.exit(0)
        else:
            # Command-specific help
            cmd_index = None
            for i, arg in enumerate(sys.argv):
                if arg in ("--help", "-h") and i > 0:
                    cmd_index = i - 1
                    break
            
            if cmd_index is not None and cmd_index < len(sys.argv):
                cmd = sys.argv[cmd_index]
                if cmd == "run":
                    _print_run_help()
                elif cmd == "diff":
                    _print_diff_help()
                else:
                    _print_help()
            else:
                _print_help()
            sys.exit(0)
    
    # Handle no arguments
    if len(sys.argv) == 1:
        _print_help()
        sys.exit(0)


def _app_wrapper():
    """Wrapper that intercepts help/version before calling Typer app.
    
    This is used as the entry point when installed via pip.
    """
    # Check and install libtinyxml2 if needed (skip for help/version commands)
    is_help_or_version = "--help" in sys.argv or "-h" in sys.argv or "--version" in sys.argv
    
    if not is_help_or_version:
        _check_and_install_tinyxml2()
    
    _handle_help_and_version()
    app()


if __name__ == "__main__":
    # Handle help/version requests manually for clean output
    _handle_help_and_version()
    # Run the app (only reached if help/version weren't requested)
    app()

