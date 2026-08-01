"""
Port Scanning Module
-----------------------
Wraps nmap with full flag coverage instead of hardcoding just -F/-sV.
Exposes named presets for the common cases, plus a generic `scan()`
that accepts any list of nmap flags for advanced/custom runs.

Note: subprocess.run is called with a list (never shell=True), so there
is no shell-injection risk even when flags originate from user selection.

Some scan types require root/CAP_NET_RAW privileges to work (SYN scan,
OS detection, UDP scan with raw sockets) -- nmap will fall back or error
if the process isn't privileged; the error is surfaced in the "error" key.
"""

import subprocess

# Named presets -> nmap flags. These mirror nmap's own documented options;
# nothing here is custom exploit code, just flag combinations.
PRESETS = {
    "quick": ["-F", "-T4"],                          # top 100 ports, fast timing
    "full_tcp": ["-p-", "-T4"],                       # all 65535 TCP ports
    "version": ["-sV", "-T4"],                        # service/version detection
    "syn_stealth": ["-sS", "-T4"],                    # SYN scan (needs root)
    "udp": ["-sU", "--top-ports", "50", "-T4"],       # top UDP ports (slow by nature)
    "os_detection": ["-O", "-T4"],                    # OS fingerprinting (needs root)
    "aggressive": ["-A", "-T4"],                      # -sV + -O + script + traceroute
    "default_scripts": ["-sV", "-sC", "-T4"],         # version + default safe NSE scripts
    "vuln_scripts": ["-sV", "--script=vuln", "-T4"],  # NSE vuln-category scripts (informational)
    "no_ping": ["-Pn", "-sV", "-T4"],                 # skip host-alive check (firewalled hosts)
    "fragment": ["-f", "-sV", "-T4"],                 # fragment packets (IDS-evasion testing)
}

# Only allow flags nmap actually documents -- guards against a caller
# accidentally/maliciously passing something that isn't a real nmap option.
_ALLOWED_FLAG_PREFIXES = (
    "-p", "-sS", "-sT", "-sU", "-sV", "-sC", "-sN", "-sF", "-sX", "-sA", "-sW",
    "-O", "-A", "-T", "-Pn", "-PS", "-PA", "-PU", "-PE", "-f", "-F", "--top-ports",
    "--script", "-oN", "-oX", "-oG", "-v", "-vv", "--reason", "--open",
    "--min-rate", "--max-retries", "--host-timeout", "-6", "--traceroute",
)


def _validate_flags(flags: list) -> list:
    clean = []
    for flag in flags:
        base = flag.split("=")[0]
        if base.startswith("--") or base.startswith("-"):
            if not any(base.startswith(p) for p in _ALLOWED_FLAG_PREFIXES):
                raise ValueError(f"Refusing unrecognized nmap flag: {flag}")
        clean.append(flag)
    return clean


def scan(target: str, flags: list, timeout: int = 300) -> dict:
    """
    Run nmap against `target` with an arbitrary (validated) flag list.
    """
    flags = _validate_flags(flags)
    args = ["nmap"] + flags + [target]

    result = {"raw": "", "command": " ".join(args), "error": None}
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        result["raw"] = proc.stdout
        if proc.returncode != 0 and not proc.stdout:
            result["error"] = proc.stderr.strip()
    except subprocess.TimeoutExpired:
        result["error"] = "Port scan timed out"
    except FileNotFoundError:
        result["error"] = "nmap not found on this system"
    except Exception as e:
        result["error"] = str(e)
    return result


def scan_ports(target: str, preset: str = "version", timeout: int = 300) -> dict:
    """
    Convenience wrapper around scan() using a named preset.
    Available presets: quick, full_tcp, version, syn_stealth, udp,
    os_detection, aggressive, default_scripts, vuln_scripts, no_ping, fragment.
    """
    if preset not in PRESETS:
        raise ValueError(f"Unknown preset '{preset}'. Options: {list(PRESETS.keys())}")
    return scan(target, PRESETS[preset], timeout=timeout)


def list_presets() -> dict:
    return PRESETS
