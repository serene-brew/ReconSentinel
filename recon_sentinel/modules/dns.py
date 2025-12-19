from typing import Dict, List
import dns.resolver

RECORD_TYPES = ["A","AAAA","CNAME","MX","TXT","NS"]

def query_dns(host: str, resolvers: List[str]) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {}
    resolver = dns.resolver.Resolver(configure=True)
    if resolvers:
        resolver.nameservers = resolvers
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(host, rtype, lifetime=5)
            values = []
            for rr in answers:
                values.append(str(rr.to_text()))
            results[rtype] = sorted(values)
        except Exception:
            continue
    return results
