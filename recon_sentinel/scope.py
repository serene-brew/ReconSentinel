from __future__ import annotations

from dataclasses import dataclass, field
from typing import List
import yaml


def _normalize_scope_data(data: dict | None) -> dict:
    """Allow both top-level keys and nested under 'scope'."""
    if not isinstance(data, dict):
        return {"org": "", "domains": [], "seeds": {"hosts": []}}
    scope_block = data.get("scope") or {}
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

    @staticmethod
    def load(path: str) -> "Scope":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        data = _normalize_scope_data(data)
        return Scope(
            org=data.get("org", ""),
            domains=data.get("domains", []),
            policy=data.get("policy", {"passive_only": True}),
            notes=data.get("notes", ""),
            resolvers=data.get("resolvers", ["1.1.1.1", "8.8.8.8"]),
            seeds=data.get("seeds", {"hosts": []}),
        )

    def in_scope_domain(self, host: str) -> bool:
        host = host.lower().strip(".")
        return any(host == d or host.endswith("." + d) for d in self.domains)

