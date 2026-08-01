"""
Input Parser
--------------
Accepts a single domain/IP string OR a path to .txt / .csv / .pdf and
returns a clean, de-duplicated list of targets.

.txt  -> one target per line (blank lines / comments starting with # skipped)
.csv  -> scans every cell, extracts anything matching a domain/IP pattern
.pdf  -> extracts text, then extracts anything matching a domain/IP pattern

Requires for .pdf support: pip install pypdf
"""

import os
import re
import csv

DOMAIN_RE = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63})\b"
)
IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)


def _extract_targets_from_text(text: str) -> set:
    found = set()
    found.update(IP_RE.findall(text))
    found.update(m.group(1) for m in DOMAIN_RE.finditer(text))
    return found


def _parse_txt(path: str) -> set:
    targets = set()
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.update(_extract_targets_from_text(line))
    return targets


def _parse_csv(path: str) -> set:
    targets = set()
    with open(path, "r", errors="ignore", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            for cell in row:
                targets.update(_extract_targets_from_text(cell))
    return targets


def _parse_pdf(path: str) -> set:
    try:
        from pypdf import PdfReader
    except ImportError:
        raise RuntimeError("pypdf is required for .pdf input: pip install pypdf")

    targets = set()
    reader = PdfReader(path)
    for page in reader.pages:
        text = page.extract_text() or ""
        targets.update(_extract_targets_from_text(text))
    return targets


def resolve_targets(user_input: str) -> list:
    """
    Main entry point. If user_input is an existing file path, parse it
    based on extension. Otherwise, treat user_input itself as a single target.
    """
    if os.path.isfile(user_input):
        ext = os.path.splitext(user_input)[1].lower()
        if ext == ".txt":
            targets = _parse_txt(user_input)
        elif ext == ".csv":
            targets = _parse_csv(user_input)
        elif ext == ".pdf":
            targets = _parse_pdf(user_input)
        else:
            raise ValueError(f"Unsupported file type: {ext}")
        # Drop obviously-junk matches like version numbers "1.0.0.exe" etc.
        return sorted(t for t in targets if _looks_valid(t))
    else:
        target = user_input.strip()
        return [target] if target else []


def _looks_valid(target: str) -> bool:
    # crude sanity filter: must have a dot, and not be a lone number sequence
    if target.count(".") == 0:
        return False
    if re.fullmatch(r"[\d.]+", target) and not IP_RE.fullmatch(target):
        return False  # things like "3.14.159" version-looking noise
    return True
