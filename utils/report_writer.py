"""
Report Writer
---------------
Saves recon results (subdomain lists, httpx probe results) to timestamped
files under ./reports/ so users have something to hand off after a scan.
"""

import os
import csv
import json
from datetime import datetime

REPORTS_DIR = "reports"


def _ensure_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def save_subdomain_list(domain: str, subdomains: list) -> str:
    """Plain text, one subdomain per line."""
    _ensure_dir()
    path = os.path.join(REPORTS_DIR, f"subdomains_{domain}_{_timestamp()}.txt")
    with open(path, "w") as f:
        f.write("\n".join(subdomains))
    return path


def save_httpx_results(domain: str, results: list, filtered: bool = False) -> str:
    """
    CSV with url, status_code, title, webserver, content_length.
    filtered=True is reflected in the filename so it's clear whether the
    AI-review pass narrowed the list.
    """
    _ensure_dir()
    tag = "alive_filtered" if filtered else "alive_all"
    path = os.path.join(REPORTS_DIR, f"httpx_{tag}_{domain}_{_timestamp()}.csv")

    fieldnames = ["url", "status_code", "title", "webserver", "content_length"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            row = {
                "url": r.get("url") or r.get("input", ""),
                "status_code": r.get("status_code") or r.get("status-code", ""),
                "title": r.get("title", ""),
                "webserver": r.get("webserver") or r.get("tech", ""),
                "content_length": r.get("content_length") or r.get("content-length", ""),
            }
            writer.writerow(row)
    return path


def save_json(domain: str, data: dict, label: str = "results") -> str:
    _ensure_dir()
    path = os.path.join(REPORTS_DIR, f"{label}_{domain}_{_timestamp()}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return path


def _tech_lines(tech: dict) -> list:
    lines = []
    for category, items in tech.items():
        names = [i["name"] + (f" ({i['version']})" if i.get("version") else "") for i in items]
        lines.append(f"- **{category}:** {', '.join(names)}")
    return lines


def build_markdown_report(target: str, results: dict) -> str:
    """
    Builds a single self-contained Markdown report from a full agent.run()
    results dict -- ports, DNS, WHOIS, TLS, tech/WAF, and the AI analysis.
    """
    ip = results.get("ip", "unresolved")
    lines = [f"# Recon Report: {target}", "", f"**Resolved IP:** {ip}  ", f"**Generated:** {_timestamp()}", ""]

    ports_raw = results.get("port_scan", {}).get("raw", "")
    if ports_raw:
        lines += ["## Port Scan", "```", ports_raw.strip(), "```", ""]

    dns = results.get("dns", {}).get("records", {})
    if dns:
        lines += ["## DNS Records"]
        for rtype, values in dns.items():
            lines.append(f"- **{rtype}:** {', '.join(values)}")
        lines.append("")

    who = results.get("whois", {})
    if who and not who.get("error"):
        lines += [
            "## WHOIS",
            f"- **Registrar:** {who.get('registrar')}",
            f"- **Expiration:** {who.get('expiration_date')}",
            "",
        ]

    ssl = results.get("ssl", {})
    if ssl and not ssl.get("error"):
        lines += [
            "## TLS Certificate",
            f"- **Version:** {ssl.get('tls_version')}",
            f"- **Expires in:** {ssl.get('expires_in_days')} days",
            "",
        ]

    tech = results.get("tech", {})
    if tech:
        lines += ["## Technology Fingerprint"] + _tech_lines(tech) + [""]

    analysis = results.get("ai_analysis")
    if analysis:
        lines += ["## AI Analysis", "", analysis, ""]

    return "\n".join(lines)


def save_markdown_report(target: str, results: dict) -> str:
    _ensure_dir()
    path = os.path.join(REPORTS_DIR, f"report_{target}_{_timestamp()}.md")
    with open(path, "w") as f:
        f.write(build_markdown_report(target, results))
    return path


def save_html_report(target: str, results: dict) -> str:
    """
    Converts the Markdown report to a minimal styled standalone HTML file.
    Uses a tiny hand-rolled renderer (headings/lists/code-blocks/bold)
    rather than pulling in a full Markdown-to-HTML dependency.
    """
    _ensure_dir()
    md = build_markdown_report(target, results)

    html_body = []
    in_code = False
    for line in md.splitlines():
        if line.strip() == "```":
            html_body.append("</pre>" if in_code else "<pre>")
            in_code = not in_code
            continue
        if in_code:
            html_body.append(line.replace("<", "&lt;").replace(">", "&gt;"))
            continue
        if line.startswith("# "):
            html_body.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("## "):
            html_body.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("- "):
            html_body.append(f"<li>{line[2:]}</li>")
        elif line.strip() == "":
            html_body.append("<br>")
        else:
            html_body.append(f"<p>{line}</p>")

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Recon Report: {target}</title>
<style>
body {{ font-family: -apple-system, Segoe UI, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; }}
h1 {{ color: #1e293b; border-bottom: 3px solid #3b82f6; padding-bottom: 8px; }}
h2 {{ color: #334155; margin-top: 28px; }}
pre {{ background: #0f172a; color: #e2e8f0; padding: 14px; border-radius: 6px; overflow-x: auto; }}
li {{ margin: 4px 0; }}
strong {{ color: #1e40af; }}
</style></head>
<body>
{''.join(html_body)}
</body></html>"""

    path = os.path.join(REPORTS_DIR, f"report_{target}_{_timestamp()}.html")
    with open(path, "w") as f:
        f.write(html)
    return path
