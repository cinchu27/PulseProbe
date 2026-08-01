"""
Host Discovery Module
----------------------
Determines whether a target is alive before spending time on deeper scans.
Uses nmap -sn (no port scan, just ICMP/ARP/TCP ping-style discovery).
"""

import subprocess


def discover_host(target: str) -> dict:
    """
    Run a host-discovery-only nmap scan.
    Returns a dict: {"alive": bool, "raw": str, "error": str|None}
    """
    result = {"alive": False, "raw": "", "error": None}
    try:
        proc = subprocess.run(
            ["nmap", "-sn", "-T4", target],
            capture_output=True,
            text=True,
            timeout=30,
        )
        result["raw"] = proc.stdout
        result["alive"] = "Host is up" in proc.stdout
    except subprocess.TimeoutExpired:
        result["error"] = "Host discovery timed out"
    except FileNotFoundError:
        result["error"] = "nmap not found on this system"
    except Exception as e:
        result["error"] = str(e)
    return result
