"""
SSL/TLS Certificate Inspection Module
----------------------------------------
Pure standard library (ssl + socket) - no extra dependency.
"""

import ssl
import socket
import datetime


def inspect_certificate(domain: str, port: int = 443, timeout: float = 6.0) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want to inspect even self-signed/expired certs

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        not_after = cert.get("notAfter")
        expires_in_days = None
        if not_after:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expires_in_days = (expiry - datetime.datetime.utcnow()).days

        return {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "valid_from": cert.get("notBefore"),
            "valid_until": not_after,
            "expires_in_days": expires_in_days,
            "san": cert.get("subjectAltName"),
            "tls_version": version,
            "cipher_suite": cipher[0] if cipher else None,
            "error": None,
        }
    except Exception as e:
        return {"error": str(e)}
