<div align=center>
  
# Recon Sentinel
## v1.0.0
</div>
<div align=center>
  
[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)](https://github.com/serene-brew/ReconSentinel)
[![stars](https://img.shields.io/github/stars/serene-brew/ReconSentinel?style=social)](https://github.com/serene-brew/ReconSentinel/stargazers)
[![forks](https://img.shields.io/github/forks/serene-brew/ReconSentinel?style=social)](https://github.com/serene-brew/ReconSentinel/network/members)
[![Issues](https://img.shields.io/github/issues/serene-brew/ReconSentinel.svg?style=social&logo=github)](https://github.com/serene-brew/ReconSentinel/issues)
[![Python](https://img.shields.io/badge/Python-3.13-yellow.svg)](https://python.org)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)
</div>

#### *<div align="right"><sub>// Contributed by the Serene-Brew Team<br>Special thanks to knightsky-cpu</sub></div>*

## Features
- **Scope guard**: refuses out-of-scope targets.
- **Passive modules**: CT logs (crt.sh), DNS (A/AAAA/CNAME/MX/TXT/NS) lookups.
- **Port scanning**: Active port scanning using nmap with multiple scan modes (default, stealthy, aggressive, comprehensive, UDP, all ports, OS detection, custom).
- **DirBuster**: Directory and file brute-forcing to discover hidden web resources.
- **Explainable findings**: each item includes *why it matters* and suggested, approval-gated **next steps**.
- **Evidence pack**: JSON artifacts + Markdown report.
- **Changefeed**: simple diff between runs.

>[!IMPORTANT]
> ## Disclaimer
>This project is a **passive-first and active reconnaissance helper** intended for **lawful security testing, research, and education**.
> - **Authorized use only.** Run this tool **only** against systems/domains you own or where you have **explicit written permission** from the owner.
> - **You are responsible for your use.** Misuse may violate laws (e.g., computer misuse / anti-hacking statutes), contracts, or company policies.
> - **No warranty.** This software is provided **“AS IS”** under the MIT License, **without warranties** of any kind. The maintainers and contributors are **not liable** for misuse, data loss, or damage resulting from use
> of this software.
> - **Compliance.** You agree to comply with all applicable laws, regulations, and organizational policies. Consult your legal counsel for guidance—this is **not legal advice**.
> - **Safety defaults.** v0 is **passive-only by default** (CT + DNS). Active scanning features (port scanning, DirBuster) are **opt-in** and must be explicitly configured in `scope.yaml`; you must confirm authorization
> before enabling them.
> - **Evidence handling.** Artifacts are stored locally by default. You are responsible for protecting any collected data and removing it when no longer authorized.
> By using this project, you acknowledge and agree to the above.
>
> **Read the full [DISCLAIMER & Acceptable Use](./DISCLAIMER.md).**

## Quickstart
```bash
# 1) Install
pip install reconsentinel
# 2) Execute interative run mode 
recon run -i
# 3) Open your casefile
ls runs/*/casefile.md
```

## Smoke Test

Run this to confirm the tool produces a casefile.

```bash
pip install reconsentinel
recon run --scope scope.yaml --out runs
test -f "$(ls -1d runs/* 2>/dev/null | head -n1)/casefile.md" && echo "SMOKE TEST PASS"
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

## Configuration (scope.yaml)

ReconSentinel uses a `scope.yaml` file to define your targets and scanning configuration. Here's an example configuration:

```yaml
org: Example Corp
domains:
  - example.com
  - example.org
policy:
  passive_only: true
notes: >
  Authorized use only. Targets and data access approved by the owner.
resolvers:
  - 1.1.1.1
  - 8.8.8.8

port_scan_mode:
  - custom  # or: default, aggresive, stealthy, comprehensive, udp, all_ports, os_detection
  - -A -T4
  - cookies: # optional for authenticated scans
    - sessionid:abc123
# Optional: Enable DirBuster
dirbuster_wordlist: dir-buster/wordlists/example.txt

# Optional: Seed hosts for discovery
seeds:
  hosts:
    - lab.example.com
```

**Key fields:**
- `org`: Organization name (for documentation)
- `domains`: List of target domains to scan
- `policy.passive_only`: Set to `true` for passive-only scans (default)
- `resolvers`: DNS resolvers to use (defaults to 1.1.1.1 and 8.8.8.8)
- `port_scan_mode`: Optional port scanning configuration (see below)
- `dirbuster_wordlist`: Optional path to wordlist for DirBuster
- `seeds`: Optional seed hosts for discovery

## Active Scanning Features

ReconSentinel includes two active scanning modules that can be enabled via configuration in `scope.yaml`:

### Port Scanner

The port scanner uses `librpscan` (a custom built C++ wrapper around nmap) to perform active port scanning. Configure it in your `scope.yaml`:

```yaml
port_scan_mode:
  - aggressive  # or: default, stealthy, comprehensive, udp, all_ports, os_detection, custom
  # Optional: cookies for authenticated scans (as second element with cookies key)
  - cookies:
    - "session_id=abc123"
    - "auth_token=xyz789"
```

**Available scan modes:**
- `default`: Service version detection on top 1000 ports
- `stealthy`: Slow (-T1), SYN stealth (-sS), minimal ports (top 100)
- `aggressive`: Fast (-T4), OS detection, NSE scripts (-A)
- `comprehensive`: Version detection, NSE scripts, top 10000 ports
- `udp`: UDP scan on top 1000 UDP ports
- `all_ports`: Scans all 65535 TCP ports (very slow)
- `os_detection`: Operating system fingerprinting (requires elevated privileges)
- `custom`: User-provided nmap flags

**Skip port scanning:**
```bash
recon run --scope scope.yaml --out runs --skip-port-scan
```

### DirBuster

The direcotry buster uses `librdirbuster` (a custom built C++ wrapper from scratch) to perform active directory path searcg. Configure it in your `scope.yaml`:

```yaml
dirbuster_wordlist: dir-buster/wordlists/example.txt
```

DirBuster will automatically run against all domains in your scope when a wordlist is provided. It uses concurrent HTTP HEAD/GET probes to discover directories and files with interesting status codes (200, 301, 302, 403).

>[!NOTE]
> **Note**: Both port scanning and DirBuster are **opt-in** features. They only run when explicitly configured in your `scope.yaml`.
> The tool remains passive-only by default.


## Safety & Ethics
- **Passive-first by default**: v0 queries public data sources and DNS. Active scanning (port scanning, DirBuster) is **opt-in** and must be explicitly configured in `scope.yaml`.  
- **Scope.yaml** is the law: domains outside scope are ignored.  
- **Active scanning requires authorization**: Port scanning and DirBuster are active techniques. Only enable them on systems you own or have explicit written permission to test.  
- Logs/artifacts are stored locally by default. You own your data.

## Roadmap
- Weekly scheduled runs + diffs
- HTTP header/tech fingerprint module
- Integrations: Amass, Nuclei, Shodan/Censys (with user-provided keys)
- HTML/PDF export and SARIF/STIX emitters
- Rate limiting and throttling controls for active scans

>[!NOTE]
> ## Community Note from the Maintainer
> I’m not a professional programmer or penetration tester—I’m a security-conscious enthusiast who cares about building safer systems. I develop and test ReconSentinel in my own lab on self-hosted, containerized
> environments, and I do my best to follow sound security practices. v0 is intentionally **passive-only** by default.
>
> This project is an active work-in-progress. I’m sharing it in good faith with the community and I welcome feedback, issues, and PRs. If you spot risks, design flaws, or ways to improve signal-to-noise, please open an
> issue or propose a change. Let’s build something genuinely useful and safe together.
