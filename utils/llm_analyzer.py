"""
LLM Analyzer
--------------
Uses llama.cpp's chat-completion interface (llm.create_chat_completion)
via a `messages` list, instead of hand-rolled `<|tag|>` prompt strings.

Why this matters after swapping to a bigger/different GGUF model: the old
`<|system|>/<|user|>/<|assistant|>` markers were TinyLlama's specific
chat format. Every model family formats its chat template differently
(Phi-3, Llama-3, Qwen2.5 all differ), and getting it wrong silently
degrades output quality. llama-cpp-python reads the chat template baked
into the GGUF metadata and applies it correctly for whatever model is
loaded, so this code doesn't need to change again if you swap models later.

Key structural choices carried over from the original prompt work:
  1. Fixed OUTPUT FORMAT the model fills in (reduces rambling).
  2. Pre-summarized findings, not raw nmap text (saves context + tokens).
  3. Prioritized, numbered action items with a severity tag.
"""

SYSTEM_PROMPT = (
    "You are a defensive cybersecurity analyst. You explain reconnaissance "
    "findings clearly and give concrete, prioritized remediation steps. "
    "You never suggest exploitation, attack techniques, or offensive actions. "
    "You only comment on what was found -- do not invent services or ports "
    "that are not in the data given to you."
)

ANALYSIS_OUTPUT_FORMAT = """Respond using EXACTLY this format:

SUMMARY:
<2-3 sentence plain-English overview of the exposure>

FINDINGS:
- <finding 1: what was found and why it matters>
- <finding 2>
- <finding 3 (if applicable)>

NEXT STEPS (ordered by priority, most urgent first):
1. [HIGH|MEDIUM|LOW] <specific, actionable step>
2. [HIGH|MEDIUM|LOW] <specific, actionable step>
3. [HIGH|MEDIUM|LOW] <specific, actionable step>"""


def build_summary(scan_results: dict) -> str:
    """
    Converts the raw dict of module outputs into a compact, LLM-friendly
    bullet summary instead of dumping raw tool output. This is the single
    biggest lever for both speed and quality, independent of model choice.
    """
    lines = []

    host = scan_results.get("host_discovery", {})
    if host.get("alive"):
        lines.append("- Host is up.")

    ports = scan_results.get("port_scan", {}).get("raw", "")
    if ports:
        open_lines = [l for l in ports.splitlines() if "/tcp" in l or "/udp" in l]
        if open_lines:
            lines.append("- Open ports/services:")
            lines.extend(f"  {l.strip()}" for l in open_lines[:20])

    dns = scan_results.get("dns", {}).get("records", {})
    if dns:
        lines.append(f"- DNS records present: {', '.join(dns.keys())}")
        if "TXT" in dns:
            lines.append(f"  TXT records (SPF/DKIM/etc may live here): {len(dns['TXT'])} found")

    who = scan_results.get("whois", {})
    if who and not who.get("error"):
        lines.append(f"- Domain registrar: {who.get('registrar')}, expires: {who.get('expiration_date')}")

    headers = scan_results.get("http", {})
    if headers and not headers.get("error"):
        lines.append(f"- HTTP status {headers.get('status_code')} at {headers.get('url')}")
        server = headers.get("headers", {}).get("Server")
        if server:
            lines.append(f"  Server header: {server}")

    cert = scan_results.get("ssl", {})
    if cert and not cert.get("error"):
        lines.append(f"- TLS: {cert.get('tls_version')}, expires in {cert.get('expires_in_days')} days")
        if cert.get("expires_in_days") is not None and cert["expires_in_days"] < 30:
            lines.append("  WARNING: certificate expiring soon")

    tech = scan_results.get("tech", {})
    if tech:
        tech_names = [f"{t['name']}" for cat, items in tech.items() for t in items if cat != "WAF"]
        if tech_names:
            lines.append(f"- Detected technologies: {', '.join(tech_names)}")
        waf_names = [t["name"] for t in tech.get("WAF", [])]
        if waf_names:
            lines.append(f"- WAF/edge protection detected: {', '.join(waf_names)}")

    return "\n".join(lines) if lines else "No significant findings collected."


def _stream_tokens(llm, messages: list, max_tokens: int, temperature: float):
    """
    Shared low-level generator: yields text tokens as they're produced by
    llama.cpp's streaming chat completion. UI-agnostic -- callers decide
    how/whether to display tokens as they arrive (see utils/ui.stream_panel).
    """
    chunks = llm.create_chat_completion(
        messages=messages, max_tokens=max_tokens, temperature=temperature,
        repeat_penalty=1.15, stream=True,
    )
    for chunk in chunks:
        delta = chunk["choices"][0].get("delta", {})
        token = delta.get("content", "")
        if token:
            yield token


def analysis_messages(target: str, scan_results: dict) -> list:
    summary = build_summary(scan_results)
    user_prompt = f"RECON FINDINGS FOR: {target}\n\n{summary}\n\n{ANALYSIS_OUTPUT_FORMAT}"
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]


def stream_analysis(llm, target: str, scan_results: dict, max_tokens: int = 200):
    """
    Generator of tokens for the recon analysis. Intended to be consumed by
    utils/ui.stream_panel() for live display; agent.py owns presentation.
    """
    return _stream_tokens(llm, analysis_messages(target, scan_results), max_tokens, temperature=0.2)


def analyze(llm, target: str, scan_results: dict, max_tokens: int = 200) -> str:
    """
    Non-streaming convenience wrapper (used by callers without a UI, e.g.
    CLI --no-banner/scripted runs). Just concatenates stream_analysis().
    """
    return "".join(stream_analysis(llm, target, scan_results, max_tokens)).strip()


FILTER_SYSTEM_PROMPT = (
    "You are a cybersecurity analyst reviewing HTTP probe results for a list "
    "of subdomains. Some 'alive' results are false positives: wildcard DNS "
    "catch-alls, generic hosting-provider parking pages, or default error "
    "pages that respond identically for every hostname. Your job is to list "
    "ONLY the hosts that look like genuinely distinct, real services."
)


def filter_alive_subdomains(llm, probe_results: list, max_tokens: int = 400) -> list:
    """
    Takes the raw list of dicts from modules.httpx_probe.probe() and asks
    the LLM to drop likely false positives (wildcard catch-alls, parking
    pages, identical default error pages), returning the filtered subset.

    The LLM's free-text response is cross-referenced back against the
    original results (never trusted as ground truth on its own) so a
    hallucinated URL can't silently appear in the output file.
    """
    if not probe_results:
        return []

    rows = []
    for r in probe_results:
        url = r.get("url") or r.get("input", "")
        status = r.get("status_code") or r.get("status-code", "")
        title = r.get("title", "")
        length = r.get("content_length") or r.get("content-length", "")
        rows.append(f"{url} | {status} | {title} | {length}")

    table = "\n".join(rows)
    user_prompt = (
        "Below is one line per probed subdomain: URL | status code | page title | content length.\n\n"
        f"{table}\n\n"
        "Note: if many entries share the exact same title AND content length, "
        "that is a strong signal of a wildcard/parking catch-all -- keep at most "
        "one representative of such a group, not all of them.\n\n"
        "Reply with ONLY the URLs that are genuinely alive distinct services, "
        "one per line, nothing else -- no numbering, no commentary."
    )

    response = llm.create_chat_completion(
        messages=[
            {"role": "system", "content": FILTER_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        max_tokens=max_tokens,
        temperature=0.1,
        repeat_penalty=1.15,
    )

    reply = response["choices"][0]["message"]["content"].strip()
    kept_urls = {line.strip() for line in reply.splitlines() if line.strip()}

    # Cross-reference: only keep entries whose URL the model actually echoed back.
    filtered = [r for r in probe_results if (r.get("url") or r.get("input", "")) in kept_urls]

    # Safety net: if the model returned nothing usable/matched nothing,
    # don't silently produce an empty report -- fall back to unfiltered results.
    return filtered if filtered else probe_results
