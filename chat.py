import os
import sys
import argparse

from agent import ReconAgent, MODEL_PROFILES
from utils.input_parser import resolve_targets
from utils import ui

ASCII_ART = r""" ____  _   _ _     ____  _____ ____  ____   ___  ____  _____ 
|  _ \| | | | |   / ___|| ____|  _ \|  _ \ / _ \| __ )| ____|
| |_) | | | | |   \___ \|  _| | |_) | |_) | | | |  _ \|  _|  
|  __/| |_| | |___ ___) | |___|  __/|  _ <| |_| | |_) | |___ 
|_|    \___/|_____|____/|_____|_|   |_| \_\\___/|____/|_____|"""

VERSION = "3.0"
AUTHOR = "Cinchana S"
TAGLINE = "Pings. Probes. Profiles what's alive."


def clear_screen():
    os.system("clear")


def parse_args():
    parser = argparse.ArgumentParser(
        prog="pulseprobe",
        description="PulseProbe -- AI-powered reconnaissance agent.",
    )
    parser.add_argument("--target", help="Single target domain/IP (skips the interactive prompt).")
    parser.add_argument("--file", help="Path to a .txt/.csv/.pdf file with multiple targets.")
    parser.add_argument(
        "--preset", default="version",
        help="nmap scan preset: quick, full_tcp, version, syn_stealth, udp, "
             "os_detection, aggressive, default_scripts, vuln_scripts, no_ping, fragment. Default: version",
    )
    parser.add_argument(
        "--profile", default=None, choices=list(MODEL_PROFILES.keys()),
        help="LLM model profile. Default: phi3-mini (or $RECON_MODEL_PROFILE).",
    )
    parser.add_argument("--no-llm", action="store_true", help="Skip AI analysis (faster, no model load).")
    parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner (useful for scripts/CI).")
    parser.add_argument("--no-report", action="store_true", help="Skip Markdown/HTML report export.")
    return parser.parse_args()


def startup(args) -> ReconAgent:
    if not args.no_banner:
        clear_screen()
        ui.print_banner(ASCII_ART, TAGLINE, AUTHOR, VERSION)
    agent = ReconAgent(load_llm=not args.no_llm, profile=args.profile)
    return agent


def run_targets(agent: ReconAgent, targets: list, args):
    for t in targets:
        agent.run(t, port_preset=args.preset, export_report=not args.no_report)


def main():
    args = parse_args()
    agent = startup(args)

    # ------------------------------------------------------------------
    # Non-interactive mode: --target / --file provided on the command line
    # ------------------------------------------------------------------
    if args.target or args.file:
        source = args.target or args.file
        try:
            targets = resolve_targets(source)
        except Exception as e:
            ui.console.print(f"[red]✗ Could not parse input: {e}[/red]")
            sys.exit(1)
        if not targets:
            ui.console.print("[red]✗ No valid targets found.[/red]")
            sys.exit(1)
        run_targets(agent, targets, args)
        return

    # ------------------------------------------------------------------
    # Interactive REPL
    # ------------------------------------------------------------------
    ui.console.print("[bold]🤖 PulseProbe[/bold]")
    ui.console.print("👉 Enter a single domain/IP (example.com / 127.0.0.1)")
    ui.console.print("👉 OR a path to a .txt / .csv / .pdf file containing multiple targets")
    ui.console.print("👉 Type 'exit' to quit\n")

    while True:
        user_input = ui.console.input("[bold cyan]TARGET >[/bold cyan] ").strip()
        if user_input.lower() in ["exit", "quit"]:
            ui.console.print("\n[bold]Exiting PulseProbe. Stay safe 👋[/bold]")
            break
        if not user_input:
            continue

        try:
            targets = resolve_targets(user_input)
        except Exception as e:
            ui.console.print(f"[red]✗ Could not parse input: {e}[/red]")
            continue

        if not targets:
            ui.console.print("[red]✗ No valid targets found in that input.[/red]")
            continue

        if len(targets) > 1:
            preview = ", ".join(targets[:10]) + (" ..." if len(targets) > 10 else "")
            ui.console.print(f"[dim]Parsed {len(targets)} targets from file: {preview}[/dim]")
            if not ui.confirm(f"Proceed with scanning all {len(targets)} targets?", default=False):
                ui.console.print("[dim]Skipping.[/dim]")
                continue

        run_targets(agent, targets, args)


if __name__ == "__main__":
    main()
