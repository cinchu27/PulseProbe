import os
import socket
import concurrent.futures as cf

from llama_cpp import Llama

from modules import (
    host_discovery,
    dns_enum,
    whois_lookup,
    port_scanner,
    http_headers,
    ssl_inspector,
    tech_fingerprint,
    subdomain_enum,
    httpx_probe,
)
from utils import llm_analyzer, report_writer, ui

# Named model profiles instead of a hardcoded checkpoint. Pick a profile
# with the `profile=` constructor arg or the RECON_MODEL_PROFILE env var,
# without touching code -- useful since this repo may run on very
# different hardware (demo/portfolio machine vs. someone else's laptop
# vs. a RAM-constrained pentest VM).
MODEL_PROFILES = {
    "phi3-mini": {  # default: best instruction-following, ~2.4GB, wants ~4GB free RAM
        "repo_id": "microsoft/Phi-3-mini-4k-instruct-gguf",
        "filename": "Phi-3-mini-4k-instruct-q4.gguf",
    },
    "qwen2.5-1.5b": {  # lightweight: ~1GB, wants ~1.5-2GB free RAM, fits constrained VMs
        "repo_id": "Qwen/Qwen2.5-1.5B-Instruct-GGUF",
        "filename": "qwen2.5-1.5b-instruct-q4_k_m.gguf",
    },
    "tinyllama": {  # smallest fallback: ~700MB, minimal quality but always fits
        "repo_id": "TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF",
        "filename": "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    },
}
DEFAULT_PROFILE = "phi3-mini"


class ReconAgent:
    """
    LLM backend: quantized GGUF model served via llama.cpp (llama-cpp-python)
    instead of a full-precision transformers pipeline. This is what actually
    gives the CPU speedup -- 4-bit quantization + llama.cpp's optimized
    C++ inference kernels, not just the model choice itself.

    Model selection is profile-based (see MODEL_PROFILES above) rather
    than hardcoded, so this can run comfortably on very different
    machines without a code change -- pass profile=, or set
    RECON_MODEL_PROFILE=qwen2.5-1.5b (etc.) as an environment variable.

    All terminal output goes through utils/ui.py (rich tables/panels/
    live dashboard) and questionary menus instead of raw print()/input().
    """

    def __init__(
        self,
        load_llm: bool = True,
        profile: str = None,
        n_ctx: int = 2048,
        n_threads: int = None,
    ):
        self.llm = None
        if load_llm:
            profile = profile or os.environ.get("RECON_MODEL_PROFILE", DEFAULT_PROFILE)
            if profile not in MODEL_PROFILES:
                raise ValueError(f"Unknown model profile '{profile}'. Options: {list(MODEL_PROFILES.keys())}")
            repo_id = MODEL_PROFILES[profile]["repo_id"]
            filename = MODEL_PROFILES[profile]["filename"]

            threads = n_threads or os.cpu_count() or 4
            ui.console.print(f"[dim]\\[*] Model profile: {profile}  ({repo_id} / {filename})[/dim]")
            with ui.console.status(f"[bold cyan]Loading quantized LLM with {threads} threads..."):
                self.llm = Llama.from_pretrained(
                    repo_id=repo_id,
                    filename=filename,
                    n_ctx=n_ctx,
                    n_threads=threads,
                    verbose=False,
                )
            ui.console.print("[bold green]✓ LLM loaded successfully.[/bold green]")

    def _resolve_ip(self, target: str):
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None

    def _is_bare_ip(self, target: str) -> bool:
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False

    # ------------------------------------------------------------------
    # Core recon pass
    # ------------------------------------------------------------------
    def run(self, target: str, port_preset: str = "version", export_report: bool = True) -> dict:
        ui.console.rule(f"[bold cyan]Reconnaissance: {target}[/bold cyan]")
        results = {"target": target}

        ip = self._resolve_ip(target)
        results["ip"] = ip
        if not ip:
            ui.console.print(f"[yellow]⚠ Could not resolve {target}, skipping network-level checks where not applicable.[/yellow]")

        with cf.ThreadPoolExecutor(max_workers=6) as ex:
            futures = {}
            if ip:
                futures["host_discovery"] = ex.submit(host_discovery.discover_host, ip)
                futures["port_scan"] = ex.submit(port_scanner.scan_ports, ip, port_preset)
            futures["dns"] = ex.submit(dns_enum.enumerate_dns, target)
            futures["whois"] = ex.submit(whois_lookup.lookup_whois, target)
            futures["http"] = ex.submit(http_headers.collect_headers, target)
            futures["ssl"] = ex.submit(ssl_inspector.inspect_certificate, target)

            module_results = ui.run_modules_with_dashboard(futures)
            results.update(module_results)

        http_res = results.get("http", {})
        results["tech"] = tech_fingerprint.fingerprint(
            http_res.get("headers", {}), http_res.get("body_snippet", "")
        )

        self._print_summary(results)

        if self.llm:
            ui.console.print()
            analysis = ui.stream_panel(
                f"[bold]🤖 AI Analysis — {target}[/bold]",
                llm_analyzer.stream_analysis(self.llm, target, results),
                colorize_severity=True,
            )
            results["ai_analysis"] = analysis.strip()

        ui.console.print("[bold green]✓ Recon completed.[/bold green]")

        if export_report:
            md_path = report_writer.save_markdown_report(target, results)
            html_path = report_writer.save_html_report(target, results)
            ui.console.print(f"[dim]Report saved: {md_path}  |  {html_path}[/dim]")

        # -------------------------------------------------------------
        # Post-analysis: offer subdomain enumeration (domains only)
        # -------------------------------------------------------------
        if not self._is_bare_ip(target):
            self._offer_subdomain_enum(target)

        return results

    def _print_summary(self, results: dict):
        if "port_scan" in results and results["port_scan"].get("raw"):
            ui.render_port_table(results["port_scan"]["raw"])
        if "port_scan" in results and results["port_scan"].get("error"):
            ui.console.print(f"[red]✗ Port scan error: {results['port_scan']['error']}[/red]")

        if results.get("dns", {}).get("records"):
            ui.console.print(f"[cyan]DNS:[/cyan] {results['dns']['records']}")
        if results.get("whois") and not results["whois"].get("error"):
            ui.console.print(f"[cyan]WHOIS registrar:[/cyan] {results['whois'].get('registrar')}")
        if results.get("ssl") and not results["ssl"].get("error"):
            ui.console.print(
                f"[cyan]TLS:[/cyan] {results['ssl'].get('tls_version')} "
                f"| expires in {results['ssl'].get('expires_in_days')} days"
            )

        tech = results.get("tech", {})
        ui.render_tech_table(tech)
        waf = [t["name"] for t in tech.get("WAF", [])]
        ui.render_waf_panel(waf)

    # ------------------------------------------------------------------
    # Subdomain enumeration -> optional httpx probing -> optional AI filter
    # ------------------------------------------------------------------
    def _offer_subdomain_enum(self, domain: str):
        if not ui.confirm(f"Run subdomain enumeration on {domain}?", default=False):
            ui.console.print("[dim]Skipping subdomain enumeration.[/dim]")
            return

        with ui.console.status(f"[bold cyan]Enumerating subdomains for {domain} (crt.sh + wordlist brute force)..."):
            sub_results = subdomain_enum.enumerate_subdomains(domain)
        subs = sub_results["subdomains"]
        ui.console.print(
            f"[bold green]✓[/bold green] Found {len(subs)} subdomains "
            f"(crt.sh: {sub_results['sources']['crt.sh']}, bruteforce: {sub_results['sources']['bruteforce']})"
        )
        ui.render_subdomain_table(subs)

        choice = ui.select(
            "What next?",
            choices=[
                "Run httpx to check which subdomains are alive",
                "Just save the raw subdomain list to a file",
            ],
        )

        if choice.startswith("Just save"):
            path = report_writer.save_subdomain_list(domain, subs)
            ui.console.print(f"[bold green]✓[/bold green] Subdomain list saved to: {path}")
            return

        with ui.console.status(f"[bold cyan]Probing {len(subs)} subdomains with httpx..."):
            probe_out = httpx_probe.probe(subs)
        probe_results = probe_out["results"]
        ui.console.print(
            f"[bold green]✓[/bold green] {len(probe_results)} hosts responded "
            f"(engine: {probe_out['engine']})"
        )

        if not probe_results:
            ui.console.print("[yellow]⚠ No hosts responded to HTTP probing.[/yellow]")
            return

        if self.llm:
            with ui.console.status("[bold cyan]Asking AI model to filter out wildcard/parking false positives..."):
                filtered = llm_analyzer.filter_alive_subdomains(self.llm, probe_results)
            ui.console.print(
                f"[bold green]✓[/bold green] AI kept {len(filtered)} of {len(probe_results)} "
                f"as genuinely alive/distinct."
            )
            ui.render_httpx_table(filtered)
            path = report_writer.save_httpx_results(domain, filtered, filtered=True)
        else:
            ui.render_httpx_table(probe_results)
            path = report_writer.save_httpx_results(domain, probe_results, filtered=False)

        ui.console.print(f"[bold green]✓[/bold green] Alive-subdomains report saved to: {path}")
