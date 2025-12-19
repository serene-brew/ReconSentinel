# ReconSentinel CLI — verbose mode, DNS fast path (opt-in), internal-host skipping (opt-in),
# parallel DNS workers (opt-in), and a comprehensive --help that embeds the full
# "ReconSentinel Command Reference (dev-box edition)".

from __future__ import annotations

import logging
import json
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Set, Tuple, Dict, List

import typer
from rich.console import Console

from .scope import Scope
from .modules.ct import fetch_ct_domains
from .modules.dns import query_dns
from .render import render_casefile, write_casefile_html
from .rules_loader import load_rules
from .utils import write_json, read_json


APP_HELP = """\
ReconSentinel Command Reference (dev-box edition)

Run from the repo root and use `./recon` in all examples below. Only if you explicitly
make it global (see the end of this help) can you omit the `./` prefix.

──────────────────────────────── Core ────────────────────────────────
• Health check
  ./recon doctor

• Run (interactive prompts)
  ./recon run -i --out runs --tag normal

• Run (from a scope file)
  ./recon run --scope scope.yaml --out runs --tag LABEL

• Diff two runs
  ./recon diff --a runs/run-OLD --b runs/run-NEW --out runs/diff.md

──────────────────── New Opt-In Flags (Speed & Visibility) ────────────────────
• Verbose progress
  -v / --verbose — live spinner + periodic progress (heartbeats).

• DNS fast path (A/AAAA only)
  --dns-fast — only A and AAAA records are stored (faster I/O + less query volume).

• Skip internal-looking hosts
  --skip-internal — ignores internal-looking names (e.g., *.corp.*, .internal, .local, .lan).

• Parallel DNS workers
  --dns-workers N — run DNS lookups in parallel (e.g., 10–50).
  Default behavior is unchanged unless you opt in.

Tip: when you don’t use any speed flags, the CLI hints:
“Tip: for faster results, try --dns-fast, --skip-internal, or --dns-workers N.”

──────────────────────────── Ready-Made Run Recipes ────────────────────────────
• Normal (baseline, comprehensive)
  ./recon run -i --out runs --tag normal

• Normal + visibility (adds heartbeats/spinner only)
  ./recon run -i -v --out runs --tag vis

• DNS fast path + concurrency (keep everything in scope)
  ./recon run -i -v --dns-fast --dns-workers 20 --out runs --tag turbo

• Turbo + skip internal-looking (fastest on large orgs)
  ./recon run -i -v --dns-fast --skip-internal --dns-workers 20 --out runs --tag turbo-skip

• Scoped file + speed flags (skip prompts)
  ./recon run --scope scope.yaml -v --dns-fast --dns-workers 20 --out runs --tag scoped-fast

──────────────────── Opening Reports (Newest or Specific) ──────────────────────
• Open the newest HTML casefile — default browser (preferred)
  xdg-open "$(ls -td runs/* | head -1)/casefile.html"

• Open the newest HTML casefile — Firefox explicitly
  firefox --new-window "$(ls -td runs/* | head -1)/casefile.html"

• Open the newest Markdown casefile
  xdg-open "$(ls -td runs/* | head -1)/casefile.md"
  # or:
  less "$(ls -td runs/* | head -1)/casefile.md"

• Work with a specific run
  RUN="runs/run-YYYYMMDD-HHMMSSZ[-tag]"
  xdg-open "$RUN/casefile.html"
  # artifacts folder:
  ls -lh "$RUN/artifacts"

──────────────────── Helpful “During Run” & Diagnostics ────────────────────────
• Watch newest run’s artifacts appear/grow
  watch -n 1 -d 'ls -lh "$(ls -td runs/* | head -1)"/artifacts'

• Time a run (wall/CPU/RSS)
  /usr/bin/time -f 'Elapsed: %E  CPU: %P  RSS: %M KB' ./recon run -i --out runs --tag bench

• Measure DNS phase duration (newest run)
  RUN="$(ls -td runs/* | head -1)"; \
  CT_TS=$(stat -c %Y $(printf "%s\\n" "$RUN"/artifacts/ct_*.json | head -1)); \
  DNS_TS=$(stat -c %Y "$RUN"/artifacts/dns_records.json); \
  echo "$((DNS_TS-CT_TS)) seconds"

• Diff two runs (what’s new/removed)
  ./recon diff --a runs/run-OLD --b runs/run-NEW --out runs/diff.md
  xdg-open runs/diff.md

────────────────── Make `recon` Globally Available (no ./) ────────────────────
This is optional, but a nice QoL improvement. After this, you can type `recon` from any directory.

• Per-user symlink into ~/.local/bin (recommended)
  mkdir -p ~/.local/bin
  ln -sf "$(pwd)/recon" ~/.local/bin/recon

  # ensure ~/.local/bin is on PATH for your shell:
  grep -q 'export PATH="$HOME/.local/bin:$PATH"' ~/.bashrc || \
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
  source ~/.bashrc
  # now you can run globally:
  recon doctor

  # undo:
  rm -f ~/.local/bin/recon

• Temporary PATH for current shell (session-only)
  export PATH="$(pwd):$PATH"
  recon doctor

Keep the symlink pointing at your dev-box repo. If you move the repo folder, update or recreate the link.

──────────────────────────── Troubleshooting (Fast Answers) ───────────────────────────
• “recon: command not found” → use ./recon from repo root, or add the symlink above.
• “ModuleNotFoundError: typer” → run via the project’s venv (./setup_venv.sh again if needed).
• “Run finished too fast / 0 hosts” → -v will show if crt.sh returned 503. Re-try when:
  curl -s -o /dev/null -w '%{http_code}\n' 'https://crt.sh/?q=%25.google.com&output=json'
  returns 200.
• DNS feels slow → try --dns-workers 20 and/or --dns-fast. Keep default for full coverage runs.

#############################################################
#          __  _____ __ __           __        __     __    #
# __  _  _|__|/ ____\__|  | __ ____ |__| ____ |  |___/  |_  #
# \ \/ \/ /  \   __\|  |  |/ //    \|  |/ ___\|  |  \   __\ #
#  \     /|  ||  |  |  |    <|   |  \  / /_/  >   Y  \  |   #
#   \/\_/ |__||__|  |__|__|_ \___|  /__\___  /|___|  /__|   #
#                           \/    \/  /_____/      \/       #
#              wifiknight created this spell                #
#############################################################

"""


console = Console()

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


app = typer.Typer(
    help=APP_HELP,
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="markdown",
)


@app.command(help="Run passive recon against the defined scope.")
def run(
    scope: Optional[Path] = typer.Option(
        None,
        exists=False,
        readable=False,
        help="Path to scope.yaml (or use -i/--interactive to enter values).",
    ),
    out: Path = typer.Option(Path("runs"), help="Output directory base."),
    tag: str = typer.Option("", help="Optional run tag, appended to run folder name."),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Prompt for scope values (org, domains, seeds, resolvers)."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show detailed progress messages (spinner + periodic counters)."
    ),
    dns_fast: bool = typer.Option(
        False, "--dns-fast", help="(Opt-in) Query only A/AAAA records for faster results."
    ),
    skip_internal: bool = typer.Option(
        False, "--skip-internal", help="(Opt-in) Skip internal-looking hosts (e.g., *.corp.*, .internal, .local, .lan)."
    ),
    dns_workers: int = typer.Option(
        0, "--dns-workers", help="(Opt-in) Parallel DNS worker threads (e.g., 10–50). Default 0/1 = serial."
    ),
):
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

        scope_obj = Scope(
            org=org,
            domains=domains,
            policy={"passive_only": passive},
            notes=notes,
            resolvers=resolvers,
            seeds={"hosts": seeds_hosts},
        )
    else:
        if scope is None:
            typer.echo("Provide --scope PATH or use --interactive (-i) to build one.")
            raise typer.Exit(2)
        scope_obj = Scope.load(str(scope))

    run_dir = out / f"run-{_stamp()}{('-' + tag) if tag else ''}"
    artifacts_dir = run_dir / "artifacts"
    run_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    console.rule("ReconSentinel v0 — Passive run")
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
    }

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


@app.command(help="Diff two runs to see what's new/removed.")
def diff(
    a: Path = typer.Option(..., exists=True, help="Path to older run dir."),
    b: Path = typer.Option(..., exists=True, help="Path to newer run dir."),
    out: Path = typer.Option(Path("diff.md"), help="Output markdown path."),
):
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


if __name__ == "__main__":
    app()

