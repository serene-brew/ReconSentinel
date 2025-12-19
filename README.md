# ReconSentinel v0 — Passive-first Recon Autopilot (Safety-First)

> **Purpose**: Turn mundane recon into a safe, repeatable, *passive-first* workflow that produces a clean **casefile.md** with clear next steps.  
> **Ethics**: For **authorized** use only. Scope is strictly enforced by `scope.yaml`.

## Features (v0)
- **Scope guard**: refuses out-of-scope targets.
- **Passive modules**: CT logs (crt.sh), DNS (A/AAAA/CNAME/MX/TXT/NS) lookups.
- **Explainable findings**: each item includes *why it matters* and suggested, approval-gated **next steps**.
- **Evidence pack**: JSON artifacts + Markdown report.
- **Changefeed**: simple diff between runs.

## Quickstart
```bash
# 1) Create and activate a venv (recommended)
python3 -m venv .venv && source .venv/bin/activate

# 2) Install
pip install -e .

# 3) Copy & edit scope
cp fixtures/scope.example.yaml scope.yaml
# -> edit org/domains, notes; keep it authorized!

# 4) Run (passive-only)
recon-sentinel run --scope scope.yaml --out runs

# 5) Open your casefile
ls runs/*/casefile.md
```
## New Opt-In Flags (Speed & Visibility)

These are **additive** features; defaults remain conservative (full DNS set, serial lookups). The CLI will print a hint, but you must **opt in**.

- **Verbose progress**: `-v, --verbose`  
  Shows a live spinner and periodic progress (heartbeats) during CT/DNS so you can see that the run is healthy.

- **DNS fast path**: `--dns-fast`  
  Resolves and stores only **A/AAAA** records. This reduces I/O and render time for large scopes. Use when you want quicker casefiles and don’t need MX/TXT/NS on first pass.

- **Skip internal-looking hosts**: `--skip-internal`  
  Excludes names that look internal (e.g., `*.corp.*`, `.internal`, `.local`, `.lan`). Good for public-exposure sweeps. (You can run a full pass later.)

- **Parallel DNS workers**: `--dns-workers N`  
  Runs DNS lookups in parallel (e.g., `10–50`). Start with `20` and tune for your network/ISP. Default is `0` (serial), which is slow but maximally conservative.

> Tip: Combine `--dns-fast` + `--dns-workers` for big speedups; add `--skip-internal` for the fastest public-only sweep.

### Ready-Made Recipes

- **Baseline (comprehensive, default behavior)**  
  ```bash
  ./recon run -i --out runs --tag normal



## Safety & Ethics
- **Passive-first**: v0 only queries public data sources and DNS. No active scanning.  
- **Scope.yaml** is the law: domains outside scope are ignored.  
- Logs/artifacts are stored locally by default. You own your data.

## Roadmap
- Weekly scheduled runs + diffs
- Optional **active** checks with explicit `--allow-active` flag and rate limits
- HTTP header/tech fingerprint module
- Integrations: Amass, Nuclei, Shodan/Censys (with user-provided keys)
- HTML/PDF export and SARIF/STIX emitters

## Disclaimer

This project is a **passive-first reconnaissance helper** intended for **lawful security testing, research, and education**.

- **Authorized use only.** Run this tool **only** against systems/domains you own or where you have **explicit written permission** from the owner.  
- **You are responsible for your use.** Misuse may violate laws (e.g., computer misuse / anti-hacking statutes), contracts, or company policies.  
- **No warranty.** This software is provided **“AS IS”** under the MIT License, **without warranties** of any kind. The maintainers and contributors are **not liable** for misuse, data loss, or damage resulting from use of this software.  
- **Compliance.** You agree to comply with all applicable laws, regulations, and organizational policies. Consult your legal counsel for guidance—this is **not legal advice**.  
- **Safety defaults.** v0 is **passive-only** (CT + DNS). Any future **active** features will be **opt-in** and require explicit approval; you must confirm authorization before enabling them.  
- **Evidence handling.** Artifacts are stored locally by default. You are responsible for protecting any collected data and removing it when no longer authorized.

By using this project, you acknowledge and agree to the above.

➡️ **Read the full [DISCLAIMER & Acceptable Use](./DISCLAIMER.md).**

## Community Note from the Maintainer

I’m not a professional programmer or penetration tester—I’m a security-conscious enthusiast who cares about building safer systems. I develop and test ReconSentinel in my own lab on self-hosted, containerized environments, and I do my best to follow sound security practices. v0 is intentionally **passive-only** by default.

This project is an active work-in-progress. I’m sharing it in good faith with the community and I welcome feedback, issues, and PRs. If you spot risks, design flaws, or ways to improve signal-to-noise, please open an issue or propose a change. Let’s build something genuinely useful and safe together.
