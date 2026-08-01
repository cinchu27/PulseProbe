"""
DNS Enumeration Module
------------------------
Pulls common DNS record types for a domain. Requires dnspython:
    pip install dnspython
"""

import dns.resolver

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def enumerate_dns(domain: str, timeout: float = 5.0) -> dict:
    """
    Query common record types for a domain.
    Returns {"records": {type: [values]}, "errors": {type: str}}
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    records = {}
    errors = {}

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(r.to_text()) for r in answers]
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            errors["NXDOMAIN"] = f"{domain} does not exist"
            break
        except Exception as e:
            errors[rtype] = str(e)

    return {"records": records, "errors": errors}
