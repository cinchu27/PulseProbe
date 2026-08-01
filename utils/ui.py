"""
UI Layer
----------
Centralizes all terminal presentation: colorized output, tables, panels,
a live status dashboard for concurrent module execution, and arrow-key
menu prompts (replacing raw input() y/n, which is what was causing
swallowed-keystroke confusion earlier).

Everything else in the codebase should render through here rather than
calling print()/input() directly, so the look-and-feel stays consistent
and can be changed in one place.
"""

import re
import concurrent.futures as cf

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from rich.markdown import Markdown
import questionary
console = Console()

SEVERITY_STYLES = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold green"}
STATUS_ICONS = {"pending": "⏳", "running": "🔄", "done": "✅", "error": "❌"}


# ----------------------------------------------------------------------
# Banner
# ----------------------------------------------------------------------
def print_banner(ascii_art: str, tagline: str, author: str, version: str):
    console.print(Text(ascii_art, style="bold cyan"))
    console.print(f"        [bold]AI-Powered Reconnaissance Agent[/bold]")
    console.print(f"        [dim]{'-' * 34}[/dim]")
    console.print(f"        Version : {version}")
    console.print(f"        Tagline : [italic]{tagline}[/italic]")
    console.print(f"        Author  : {author}\n")
    console.print(Panel(
        "For educational & authorized testing only.\nUnauthorized scanning is illegal.",
        title="[bold red]⚠ WARNING[/bold red]",
        border_style="red",
        expand=False,
    ))


# ----------------------------------------------------------------------
# Live dashboard for concurrent module execution
# ----------------------------------------------------------------------
def run_modules_with_dashboard(futures: dict) -> dict:
    """
    futures: {module_name: concurrent.futures.Future}
    Renders a live-updating status table while they complete, instead of
    a silent wait. Returns {module_name: result_or_error_dict}.
    """
    statuses = {name: "running" for name in futures}
    results = {}

    def render_table():
        table = Table(title="Recon Module Status", show_edge=True)
        table.add_column("Module", style="cyan")
        table.add_column("Status")
        for name, status in statuses.items():
            icon = STATUS_ICONS.get(status, "")
            table.add_row(name, f"{icon} {status}")
        return table

    pending = dict(futures)
    with Live(render_table(), console=console, refresh_per_second=6) as live:
        while pending:
            done_now = []
            for name, fut in list(pending.items()):
                if fut.done():
                    try:
                        results[name] = fut.result()
                        statuses[name] = "done"
                    except Exception as e:
                        results[name] = {"error": str(e)}
                        statuses[name] = "error"
                    done_now.append(name)
            for name in done_now:
                pending.pop(name)
            live.update(render_table())
            if pending:
                cf.wait(list(pending.values()), timeout=0.2)
    return results


# ----------------------------------------------------------------------
# Result tables / panels
# ----------------------------------------------------------------------
_PORT_LINE_RE = re.compile(r"^(\d+/\w+)\s+(\S+)\s+(\S+)\s*(.*)$")


def render_port_table(nmap_raw: str):
    rows = []
    for line in nmap_raw.splitlines():
        m = _PORT_LINE_RE.match(line.strip())
        if m:
            rows.append(m.groups())
    if not rows:
        console.print("[dim]No open ports parsed from scan output.[/dim]")
        return
    table = Table(title="Port Scan Results")
    table.add_column("Port", style="cyan")
    table.add_column("State")
    table.add_column("Service")
    table.add_column("Version", style="dim")
    for port, state, service, version in rows:
        state_style = "green" if state == "open" else "yellow"
        table.add_row(port, f"[{state_style}]{state}[/{state_style}]", service, version)
    console.print(table)


def render_tech_table(tech: dict):
    if not tech:
        console.print("[dim]No technologies identified.[/dim]")
        return
    table = Table(title="Technology Fingerprint")
    table.add_column("Category", style="cyan")
    table.add_column("Technology")
    table.add_column("Version", style="dim")
    for category, items in tech.items():
        for item in items:
            table.add_row(category, item["name"], item.get("version") or "-")
    console.print(table)


def render_waf_panel(waf_names: list):
    if waf_names:
        console.print(Panel(", ".join(waf_names), title="[bold]WAF Detected[/bold]", border_style="magenta"))
    else:
        console.print("[dim]No known WAF signature matched (not proof none is present).[/dim]")


def render_ai_analysis_panel(target: str, analysis_text: str):
    """
    Colorizes [HIGH]/[MEDIUM]/[LOW] tags inside the AI's NEXT STEPS section
    and wraps the whole thing in a panel.
    """
    colored = analysis_text
    for sev, style in SEVERITY_STYLES.items():
        colored = colored.replace(f"[{sev}]", f"[{style}]{sev}[/{style}]")
    console.print(Panel(colored, title=f"[bold]🤖 AI Analysis — {target}[/bold]", border_style="blue"))


def stream_panel(title: str, token_iter, border_style: str = "blue", colorize_severity: bool = False) -> str:
    """
    Renders tokens live inside a single rich Panel as they arrive (instead
    of printing raw text then showing a separate panel afterward, which
    would duplicate the output). If colorize_severity is set, the final
    frame re-renders with [HIGH]/[MEDIUM]/[LOW] tags colorized in place.
    Returns the full generated text.
    """
    full_text = ""
    with Live(Panel(full_text, title=title, border_style=border_style), console=console, refresh_per_second=10) as live:
        for token in token_iter:
            full_text += token
            live.update(Panel(full_text, title=title, border_style=border_style))

        if colorize_severity:
            colored = full_text
            for sev, style in SEVERITY_STYLES.items():
                colored = colored.replace(f"[{sev}]", f"[{style}]{sev}[/{style}]")
            live.update(Panel(colored, title=title, border_style=border_style))

    return full_text


def render_subdomain_table(subdomains: list):
    table = Table(title=f"Subdomains ({len(subdomains)})")
    table.add_column("Subdomain", style="cyan")
    for s in subdomains:
        table.add_row(s)
    console.print(table)


def render_httpx_table(results: list):
    if not results:
        console.print("[dim]No hosts responded.[/dim]")
        return
    table = Table(title="Alive Subdomains (httpx)")
    table.add_column("URL", style="cyan")
    table.add_column("Status")
    table.add_column("Title")
    table.add_column("Server", style="dim")
    for r in results:
        url = r.get("url") or r.get("input", "")
        status = str(r.get("status_code") or r.get("status-code", ""))
        status_style = "green" if status.startswith("2") else "yellow"
        title = r.get("title", "")
        server = r.get("webserver") or ""
        table.add_row(url, f"[{status_style}]{status}[/{status_style}]", title, server)
    console.print(table)


# ----------------------------------------------------------------------
# Prompts (arrow-key menus via questionary, replaces raw input() y/n)
# ----------------------------------------------------------------------
def confirm(prompt: str, default: bool = False) -> bool:
    """
    Arrow-key/Enter confirm prompt. Returns default if the user hits
    Ctrl+C or the prompt is cancelled, instead of raising.
    """
    answer = questionary.confirm(prompt, default=default).ask()
    return default if answer is None else answer


def select(prompt: str, choices: list) -> str:
    """
    Arrow-key select menu. choices: list of display strings.
    Returns the chosen string, or the first choice if cancelled.
    """
    answer = questionary.select(prompt, choices=choices).ask()
    return answer if answer is not None else choices[0]


def print_markdown(md_text: str):
    console.print(Markdown(md_text))
