"""
Subdomain Enumeration Module
--------------------------------
Passive: queries crt.sh certificate-transparency logs (no API key,
no packets sent to the target).
Active (optional): resolves a small common-word wordlist against the
domain via DNS, threaded.

Returns a de-duplicated, sorted list of subdomains. Does NOT check
liveness/HTTP status -- that's handled separately by the httpx probe
module so this stays fast and purely DNS/CT-log based.
"""

import re
import socket
import requests
import concurrent.futures as cf

COMMON_WORDS = [
    "www", "mail", "ftp", "api", "dev", "staging", "stage", "test", "admin",
    "portal", "vpn", "ns1", "ns2", "smtp", "webmail", "blog", "shop", "m",
    "mobile", "app", "cdn", "static", "beta", "demo", "support", "help",
    "docs", "status", "git", "gitlab", "jenkins", "grafana", "kibana",
    "dashboard", "secure", "login", "auth", "sso", "internal", "intranet",
]


def _crtsh_lookup(domain: str, timeout: float = 15.0) -> set:
    subs = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json", timeout=timeout
        )
        if resp.status_code == 200 and resp.text.strip():
            for entry in resp.json():
                name_value = entry.get("name_value", "")
                for line in name_value.split("\n"):
                    line = line.strip().lower()
                    if line.startswith("*."):
                        line = line[2:]
                    if line.endswith(domain) and re.match(
                        r"^[a-z0-9*_.-]+$", line
                    ):
                        subs.add(line)
    except Exception:
        pass  # crt.sh can be flaky/rate-limited; brute force still runs
    return subs


def _resolve(sub: str):
    try:
        ip = socket.gethostbyname(sub)
        return sub, ip
    except socket.gaierror:
        return None


def _bruteforce(domain: str, wordlist: list, max_workers: int = 30) -> set:
    candidates = [f"{w}.{domain}" for w in wordlist]
    found = set()
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for result in ex.map(_resolve, candidates):
            if result:
                found.add(result[0])
    return found


def enumerate_subdomains(domain: str, brute_force: bool = True, wordlist: list = None) -> dict:
    """
    Returns {"subdomains": [sorted list], "count": int, "sources": {...}}
    """
    passive = _crtsh_lookup(domain)
    active = _bruteforce(domain, wordlist or COMMON_WORDS) if brute_force else set()

    all_subs = sorted(passive | active | {domain})

    return {
        "domain": domain,
        "subdomains": all_subs,
        "count": len(all_subs),
        "sources": {"crt.sh": len(passive), "bruteforce": len(active)},
    }
