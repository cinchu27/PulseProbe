"""
Technology Fingerprinting Module (Wappalyzer / WhatWeb style)
------------------------------------------------------------------
Signature-based detection across categories, matched against:
  - HTTP response headers
  - Set-Cookie names
  - HTML body (meta tags, inline markers, comments)
  - <script src="..."> paths

Each signature can optionally capture a version number via a regex group.
Output is grouped by category, matching the style of WhatWeb/Wappalyzer
reports, e.g.:

    {
      "CMS": [{"name": "WordPress", "version": "6.4"}],
      "Web Server": [{"name": "nginx", "version": "1.18.0"}],
      "JS Framework": [{"name": "React", "version": None}],
      ...
    }

This is a plain-Python signature DB (no external service calls) so it
works offline and is easy to extend -- just add entries to SIGNATURES
below. For deeper/community-maintained coverage you can later swap this
for the `python-Wappalyzer` package or import Wappalyzer's own
technologies.json and adapt the matcher.
"""

import re

# category -> tech name -> match rules.
# Rule keys: "headers" (dict of header_name -> [(pattern, version_group)]),
# "cookies", "html", "meta", "script_src" (each a list of (pattern, version_group)).
SIGNATURES = {
    "Web Server": {
        "nginx": {"headers": {"Server": [(r"nginx/?([\d.]+)?", 1)]}},
        "Apache": {"headers": {"Server": [(r"Apache/?([\d.]+)?", 1)]}},
        "Microsoft IIS": {"headers": {"Server": [(r"Microsoft-IIS/?([\d.]+)?", 1)]}},
        "LiteSpeed": {"headers": {"Server": [(r"LiteSpeed", None)]}},
    },
    "Programming Language": {
        "PHP": {
            "headers": {"X-Powered-By": [(r"PHP/?([\d.]+)?", 1)]},
            "cookies": [(r"PHPSESSID", None)],
        },
        "ASP.NET": {
            "headers": {"X-Powered-By": [(r"ASP\.NET", None)], "X-AspNet-Version": [(r"([\d.]+)", 1)]},
            "cookies": [(r"ASP\.NET_SessionId", None)],
        },
        "Ruby": {"headers": {"X-Powered-By": [(r"Ruby", None)]}},
    },
    "Web Framework": {
        "Express": {"headers": {"X-Powered-By": [(r"Express", None)]}},
        "Django": {"cookies": [(r"csrftoken", None)], "html": [(r"csrfmiddlewaretoken", None)]},
        "Laravel": {"cookies": [(r"laravel_session", None)]},
        "Ruby on Rails": {"headers": {"X-Powered-By": [(r"Phusion Passenger", None)]}, "cookies": [(r"_rails_session|_session_id", None)]},
        "Next.js": {"html": [(r"__NEXT_DATA__|/_next/static", None)]},
        "Nuxt.js": {"html": [(r"__NUXT__", None)]},
    },
    "CMS": {
        "WordPress": {
            "meta": [(r'generator["\']\s*content=["\']WordPress\s*([\d.]+)?', 1)],
            "html": [(r"wp-content|wp-includes", None)],
            "cookies": [(r"wordpress_|wp-settings-", None)],
        },
        "Joomla": {"meta": [(r'generator["\']\s*content=["\']Joomla', None)]},
        "Drupal": {"meta": [(r'generator["\']\s*content=["\']Drupal\s*([\d.]+)?', 1)], "headers": {"X-Generator": [(r"Drupal\s*([\d.]+)?", 1)]}},
        "Shopify": {"html": [(r"cdn\.shopify\.com", None)], "headers": {"X-Shopify-Stage": [(r".*", None)]}},
        "Wix": {"html": [(r"static\.wixstatic\.com|wix\.com", None)]},
        "Squarespace": {"html": [(r"squarespace\.com|static1\.squarespace\.com", None)]},
        "Ghost": {"meta": [(r'generator["\']\s*content=["\']Ghost\s*([\d.]+)?', 1)]},
    },
    "JS Framework": {
        "React": {"html": [(r"react(?:-dom)?[.\-]([\d.]+)?\.js|data-reactroot", 1)]},
        "Angular": {"html": [(r"ng-version=[\"']([\d.]+)[\"']", 1)]},
        "Vue.js": {"html": [(r"vue(?:\.min)?\.js|__vue__", None)]},
        "jQuery": {"script_src": [(r"jquery[-.]([\d.]+)?", 1)]},
        "Svelte": {"html": [(r"svelte", None)]},
    },
    "Analytics": {
        "Google Analytics": {"html": [(r"gtag\(|google-analytics\.com/(?:ga|analytics)\.js|googletagmanager\.com", None)]},
        "Facebook Pixel": {"html": [(r"connect\.facebook\.net.*fbevents\.js", None)]},
        "Hotjar": {"html": [(r"static\.hotjar\.com", None)]},
    },
    "CDN": {
        "Cloudflare": {"headers": {"CF-Cache-Status": [(r".*", None)], "Server": [(r"cloudflare", None)]}},
        "Fastly": {"headers": {"X-Served-By": [(r"cache-.*fastly", None)], "Via": [(r"fastly", None)]}},
        "Akamai": {"headers": {"Server": [(r"AkamaiGHost", None)], "X-Akamai-Transformed": [(r".*", None)]}},
        "Amazon CloudFront": {"headers": {"Via": [(r"CloudFront", None)], "X-Amz-Cf-Id": [(r".*", None)]}},
    },
    "Security": {
        "HSTS Enabled": {"headers": {"Strict-Transport-Security": [(r".*", None)]}},
        "CSP Enabled": {"headers": {"Content-Security-Policy": [(r".*", None)]}},
    },
    # WAF / edge-security signatures, modeled on the public signature style
    # used by tools like wafw00f -- purely passive (headers/cookies/body
    # from the normal response already collected), no attack payloads sent.
    "WAF": {
        "Cloudflare": {
            "headers": {"Server": [(r"cloudflare", None)], "CF-RAY": [(r".*", None)]},
            "cookies": [(r"__cfduid|__cflb|cf_clearance", None)],
        },
        "Akamai (Kona / GHost)": {
            "headers": {"Server": [(r"AkamaiGHost", None)], "X-Akamai-Transformed": [(r".*", None)]},
        },
        "Imperva Incapsula": {
            "headers": {"X-CDN": [(r"Incapsula", None)], "X-Iinfo": [(r".*", None)]},
            "cookies": [(r"incap_ses|visid_incap", None)],
        },
        "Sucuri CloudProxy": {
            "headers": {"Server": [(r"Sucuri", None)], "X-Sucuri-ID": [(r".*", None)], "X-Sucuri-Cache": [(r".*", None)]},
        },
        "AWS WAF": {
            "headers": {"X-Amzn-RequestId": [(r".*", None)], "X-Amz-Cf-Id": [(r".*", None)]},
        },
        "F5 BIG-IP ASM": {
            "cookies": [(r"TS[0-9a-fA-F]{8,}|BIGipServer", None)],
        },
        "Barracuda WAF": {
            "cookies": [(r"barra_counter_session", None)],
        },
        "Fortinet FortiWeb": {
            "headers": {"Server": [(r"FortiWeb", None)]},
            "cookies": [(r"FORTIWAFSID", None)],
        },
        "Citrix NetScaler AppFirewall": {
            "cookies": [(r"citrix_ns_id|NSC_", None)],
        },
        "DDoS-Guard": {
            "headers": {"Server": [(r"ddos-guard", None)]},
        },
        "StackPath": {
            "headers": {"Server": [(r"StackPath", None)]},
        },
        "Wordfence (WordPress WAF)": {
            "headers": {"X-Wordfence": [(r".*", None)]},
        },
        "ModSecurity (generic)": {
            "headers": {"Server": [(r"Mod_Security|NOYB", None)]},
        },
    },
}


def detect_waf(headers: dict, html: str = "") -> list:
    """
    Convenience wrapper: returns just the list of detected WAF/edge-security
    products, e.g. ["Cloudflare"]. Empty list means none of the known
    signatures matched -- NOT proof that no WAF is present (evasive WAFs
    exist that strip identifying headers).
    """
    all_results = fingerprint(headers, html)
    return [t["name"] for t in all_results.get("WAF", [])]


def _match_rules(rules, source_text):
    findings = []
    for pattern, group in rules:
        m = re.search(pattern, source_text, re.IGNORECASE)
        if m:
            version = m.group(group) if group and m.groups() else None
            findings.append(version)
    return findings if findings else None


def fingerprint(headers: dict, html: str = "") -> dict:
    """
    headers: dict of HTTP response headers (case as returned by requests)
    html: raw HTML body
    Returns: {"category": [{"name": tech, "version": str|None}, ...], ...}
    """
    cookie_str = headers.get("Set-Cookie", "")
    script_srcs = " ".join(re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE))
    meta_tags = " ".join(re.findall(r"<meta[^>]+>", html, re.IGNORECASE))

    results = {}

    for category, techs in SIGNATURES.items():
        for tech_name, rules in techs.items():
            matched = False
            version = None

            for header_name, patterns in rules.get("headers", {}).items():
                header_val = headers.get(header_name)
                if header_val:
                    hits = _match_rules(patterns, header_val)
                    if hits is not None:
                        matched = True
                        version = version or next((v for v in hits if v), None)

            if not matched and rules.get("cookies") and cookie_str:
                hits = _match_rules(rules["cookies"], cookie_str)
                if hits is not None:
                    matched = True

            if not matched and rules.get("html") and html:
                hits = _match_rules(rules["html"], html)
                if hits is not None:
                    matched = True
                    version = version or next((v for v in hits if v), None)

            if not matched and rules.get("meta") and meta_tags:
                hits = _match_rules(rules["meta"], meta_tags)
                if hits is not None:
                    matched = True
                    version = version or next((v for v in hits if v), None)

            if not matched and rules.get("script_src") and script_srcs:
                hits = _match_rules(rules["script_src"], script_srcs)
                if hits is not None:
                    matched = True
                    version = version or next((v for v in hits if v), None)

            if matched:
                results.setdefault(category, []).append({"name": tech_name, "version": version})

    return results


def format_report(results: dict) -> str:
    """WhatWeb-style single-line-per-category text report."""
    if not results:
        return "No technologies identified."
    lines = []
    for category, techs in results.items():
        entries = []
        for t in techs:
            entries.append(f"{t['name']}" + (f"[{t['version']}]" if t["version"] else ""))
        lines.append(f"{category}: {', '.join(entries)}")
    return "\n".join(lines)
