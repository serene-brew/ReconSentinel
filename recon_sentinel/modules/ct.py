from typing import List, Set
import requests, os, time

# Query for all subdomains of {domain}
CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def fetch_ct_domains(domain: str, delay: float = 1.0) -> List[str]:
    """
    Fetch subdomains from crt.sh for a given base domain.
    Returns a list of unique, lowercased FQDNs.

    Resilience:
      - Retries on timeouts / transient network errors.
      - Treats non-JSON or non-200 responses as empty (keeps the run going).

    Tunables via environment (no code changes needed):
      RECON_CT_TIMEOUT   seconds per request     (default: 30)
      RECON_CT_RETRIES   extra retry attempts    (default: 1)  # total attempts = retries + 1
      RECON_CT_SLEEP     seconds between retries (default: 1.0)
      RECON_CT_UA        User-Agent string       (default: "ReconSentinel/0.2 (+https://example.invalid)")
    """
    timeout = int(os.getenv("RECON_CT_TIMEOUT", "30"))
    retries = int(os.getenv("RECON_CT_RETRIES", "1"))
    sleep_s = float(os.getenv("RECON_CT_SLEEP", "1.0"))
    ua = os.getenv("RECON_CT_UA", "ReconSentinel/0.2 (+https://example.invalid)")

    url = CRT_URL.format(domain=domain)

    for attempt in range(retries + 1):
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": ua})
            if r.status_code != 200:
                return []
            try:
                data = r.json()
            except Exception:
                # crt.sh can serve HTML or broken JSON under load; treat as empty
                return []

            names: Set[str] = set()
            for row in data:
                # both fields can contain names; split lines to flatten
                for key in ("name_value", "common_name"):
                    v = row.get(key, "") or ""
                    for line in str(v).splitlines():
                        s = line.strip().lower()
                        if not s:
                            continue
                        # drop wildcard prefix; skip bare base domain
                        if s.startswith("*."):
                            s = s[2:]
                        if s and s != domain:
                            names.add(s)

            # polite pause between domain queries (not related to retry backoff)
            time.sleep(delay)
            return sorted(names)

        except (
            requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.SSLError,
            requests.exceptions.ChunkedEncodingError,
        ):
            if attempt < retries:
                time.sleep(sleep_s * (attempt + 1))  # simple linear backoff
                continue
            return []

