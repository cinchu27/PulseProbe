"""
HTTP Liveness Probing Module (httpx)
----------------------------------------
Wraps ProjectDiscovery's `httpx` CLI (https://github.com/projectdiscovery/httpx)
to check which subdomains are actually serving HTTP(S), and pulls back
status code, title, tech-stack hints, and content length for each.

If the `httpx` binary isn't installed, falls back to a pure-Python
threaded prober using `requests` so the feature still works out of the box.
"""

import json
import shutil
import tempfile
import subprocess
import re
import requests
import concurrent.futures as cf

requests.packages.urllib3.disable_warnings()


def _httpx_binary_available() -> bool:
    return shutil.which("httpx") is not None


def probe_with_httpx_binary(subdomains: list, timeout: int = 180) -> list:
    """
    Runs the real `httpx` tool: httpx -l <file> -json -silent -title -status-code -tech-detect
    Returns a list of dicts parsed from its JSON-lines output.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(subdomains))
        list_path = f.name

    args = [
        "httpx", "-l", list_path, "-silent", "-json",
        "-title", "-status-code", "-tech-detect", "-content-length",
    ]
    results = []
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        pass
    return results


def _probe_single(sub: str, timeout: float = 6.0):
    for scheme in ("https", "http"):
        url = f"{scheme}://{sub}"
        try:
            resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
            return {
                "url": resp.url,
                "input": sub,
                "status_code": resp.status_code,
                "title": title_match.group(1).strip()[:150] if title_match else "",
                "webserver": resp.headers.get("Server", ""),
                "content_length": len(resp.content),
            }
        except requests.exceptions.RequestException:
            continue
    return None


def probe_with_python_fallback(subdomains: list, max_workers: int = 20) -> list:
    results = []
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for res in ex.map(_probe_single, subdomains):
            if res:
                results.append(res)
    return results


def probe(subdomains: list) -> dict:
    """
    Main entry point. Returns {"results": [...], "engine": "httpx"|"python-fallback"}
    """
    if _httpx_binary_available():
        results = probe_with_httpx_binary(subdomains)
        engine = "httpx"
        if not results:  # binary present but produced nothing usable -> fall back
            results = probe_with_python_fallback(subdomains)
            engine = "python-fallback"
    else:
        results = probe_with_python_fallback(subdomains)
        engine = "python-fallback"

    return {"results": results, "engine": engine}
