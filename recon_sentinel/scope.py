from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
import yaml


def _normalize_scope_data(data: dict | None) -> dict:
    """Allow both top-level keys and nested under 'scope'."""
    if not isinstance(data, dict):
        return {"org": "", "domains": [], "seeds": {"hosts": []}}
    scope_block = data.get("scope") or {}
    if "dirbuster_wordlist" not in data and isinstance(scope_block, dict):
        db_cfg = scope_block.get("dirbuster") or {}
        if isinstance(db_cfg, dict) and db_cfg.get("wordlist"):
            data["dirbuster_wordlist"] = db_cfg["wordlist"]
    if "domains" not in data and isinstance(scope_block, dict):
        if isinstance(scope_block.get("domains"), list):
            data["domains"] = scope_block["domains"]
    if "seeds" not in data and isinstance(scope_block, dict):
        sb_seeds = scope_block.get("seeds")
        if isinstance(sb_seeds, dict) and "hosts" in sb_seeds:
            data["seeds"] = sb_seeds
    return data


@dataclass
class Scope:
    org: str
    domains: List[str]
    policy: dict = field(default_factory=lambda: {"passive_only": True})
    notes: str = ""
    resolvers: List[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    seeds: dict = field(default_factory=lambda: {"hosts": []})
    port_scan_mode: list = field(default_factory=list)
    port_scan_cookies: Optional[List[str]] = None
    dirbuster_wordlist: str = ""

    @staticmethod
    def load(path: str) -> "Scope":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        data = _normalize_scope_data(data)
        # Normalize port_scan_mode as a list, accepting multiple syntaxes
        _psm = data.get("port_scan_mode", [])
        port_scan_mode = []
        port_scan_cookies = None
        
        if not _psm:
            port_scan_mode = []
        elif isinstance(_psm, list):
            if len(_psm) > 0:
                port_scan_mode.append(_psm[0])  # First element is always the mode
            if len(_psm) > 1:
                # Second element can be flags (string) or cookies dict
                second_elem = _psm[1]
                if isinstance(second_elem, dict) and "cookies" in second_elem:
                    # Extract cookies from dict
                    cookies_list = second_elem.get("cookies", [])
                    if isinstance(cookies_list, list):
                        port_scan_cookies = [str(c) for c in cookies_list if c]
                    elif cookies_list:
                        port_scan_cookies = [str(cookies_list)]
                elif isinstance(second_elem, str):
                    # Backward compatibility: second element is flags
                    port_scan_mode.append(second_elem)
        elif isinstance(_psm, str):
            port_scan_mode = [_psm]
        
        return Scope(
            org=data.get("org", ""),
            domains=data.get("domains", []),
            policy=data.get("policy", {"passive_only": True}),
            notes=data.get("notes", ""),
            resolvers=data.get("resolvers", ["1.1.1.1", "8.8.8.8"]),
            seeds=data.get("seeds", {"hosts": []}),
            port_scan_mode=port_scan_mode,
            port_scan_cookies=port_scan_cookies,
            dirbuster_wordlist=data.get("dirbuster_wordlist", ""),
        )

    def in_scope_domain(self, host: str) -> bool:
        host = host.lower().strip(".")
        return any(host == d or host.endswith("." + d) for d in self.domains)

