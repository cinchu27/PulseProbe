"""
WHOIS Lookup Module
---------------------
Requires: pip install python-whois
"""

import whois as whois_lib


def lookup_whois(domain: str) -> dict:
    """
    Returns key WHOIS fields, or an error message.
    """
    try:
        w = whois_lib.whois(domain)
        return {
            "registrar": w.get("registrar"),
            "creation_date": str(w.get("creation_date")),
            "expiration_date": str(w.get("expiration_date")),
            "name_servers": w.get("name_servers"),
            "org": w.get("org"),
            "country": w.get("country"),
            "emails": w.get("emails"),
            "status": w.get("status"),
            "error": None,
        }
    except Exception as e:
        return {"error": str(e)}
