"""
HTTP Header Collection Module
--------------------------------
Requires: pip install requests
"""

import requests

requests.packages.urllib3.disable_warnings()  # self-signed certs during recon are common


def collect_headers(domain: str, timeout: float = 8.0) -> dict:
    """
    Tries HTTPS first, falls back to HTTP. Returns headers + status + final URL.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = requests.get(
                url, timeout=timeout, verify=False, allow_redirects=True
            )
            return {
                "url": resp.url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body_snippet": resp.text[:500],
                "error": None,
            }
        except requests.exceptions.RequestException:
            continue
    return {"error": "Could not connect over HTTPS or HTTP"}
