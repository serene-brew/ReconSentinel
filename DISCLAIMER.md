# DISCLAIMER & ACCEPTABLE USE NOTICE

**Project:** ReconSentinel – Passive-first reconnaissance helper  
**License:** MIT (see `LICENSE`)  
**Status:** v0 is **passive-only** (Certificate Transparency + DNS lookups). No active scanning is performed by default.

---

## Authorized Use Only
Use this software **only** on systems, domains, and assets that you **own** or for which you have **explicit, written permission** from the owner.  
By running this software you represent that you are authorized to do so.

## Prohibited Activities
Do **not** use this software for, or in connection with:
- Unauthorized access, testing, or monitoring of third-party systems
- Any violation of law or regulation (e.g., computer misuse/anti-hacking statutes)
- Circumventing access controls or exploiting vulnerabilities without permission
- Data exfiltration, privacy invasion, or collection of personal data without lawful basis
- Harassment, stalking, or targeting individuals

## Safety Defaults
- v0 runs in **passive-only** mode: it queries public data sources and resolvers.
- Any future **active** features will be **opt-in**, visibly flagged (e.g., `--allow-active`), rate-limited, and intended for environments where you hold authorization.
- You are responsible for verifying authorization before enabling any non-passive feature.

## Evidence Handling & Privacy
- Artifacts (JSON, Markdown reports) are stored **locally by default**.  
- You are responsible for protecting and disposing of collected data in accordance with applicable policies and laws (e.g., data minimization, retention limits, confidentiality).

## Compliance
You agree to comply with all applicable laws, regulations, contracts, and organizational policies (including but not limited to testing rules of engagement, export controls, and notification requirements).  
If you are unsure whether an intended use is permitted, consult your legal counsel. **This is not legal advice.**

## No Warranty
This software is provided **“AS IS”**, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.  
In no event shall the authors or contributors be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

## Third-Party Services
Some features may query third-party services (e.g., public CT logs, DNS resolvers). Those services are subject to their own terms and acceptable-use policies. You are responsible for complying with any such terms.

## Changes
The maintainers may update this notice from time to time. Continued use after an update constitutes acceptance of the revised terms.

---

**By using ReconSentinel, you acknowledge and agree to the terms above.**
