"""
https_ssl.py
Checks: HTTPS enforcement, SSL certificate validity, TLS version, HSTS header.

Each check returns the same dict shape as url_structure.py:
{ "check": ..., "passed": ..., "impact": ..., "detail": ... }
"""

import ssl
import socket
import datetime
from urllib.parse import urlparse
import requests
import certifi


def get_ssl_context() -> ssl.SSLContext:
    """
    Uses certifi's CA bundle instead of the OS default.
    On Windows especially, Python's default certificate store is often
    incomplete/outdated, which causes false 'unable to get local issuer
    certificate' failures on perfectly valid sites. certifi ships a
    current, complete root CA bundle so verification is accurate.
    """
    return ssl.create_default_context(cafile=certifi.where())


def get_domain(url: str) -> str:
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path  # handles bare domains without scheme
    return domain.split(":")[0].split("/")[0]


def check_https_enforced(url: str) -> dict:
    """Checks if the site loads over HTTPS, or HTTP redirects to HTTPS."""
    domain = get_domain(url)
    try:
        # Try HTTPS directly first
        https_url = f"https://{domain}"
        resp = requests.get(https_url, timeout=8,
                             headers={"User-Agent": "Mozilla/5.0 (SecurityChecker/1.0)"})
        if resp.url.startswith("https://"):
            return {"check": "HTTPS Enforced", "passed": True, "impact": 0,
                    "detail": "Site loads over HTTPS."}
    except requests.exceptions.RequestException:
        pass  # fall through to check HTTP redirect behavior

    try:
        http_url = f"http://{domain}"
        resp = requests.get(http_url, timeout=8, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 (SecurityChecker/1.0)"})
        if resp.url.startswith("https://"):
            return {"check": "HTTPS Enforced", "passed": True, "impact": -3,
                    "detail": "Site works over HTTP but redirects to HTTPS (minor deduction: HTTPS should be the default)."}
        return {"check": "HTTPS Enforced", "passed": False, "impact": -20,
                "detail": "Site does not use HTTPS at all — connection is unencrypted."}
    except requests.exceptions.RequestException as e:
        return {"check": "HTTPS Enforced", "passed": False, "impact": -20,
                "detail": f"Could not verify HTTPS support: {e}"}


def check_ssl_certificate(url: str) -> dict:
    """Connects via TLS and inspects the certificate's validity dates and domain match."""
    domain = get_domain(url)
    try:
        context = get_ssl_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.datetime.utcnow()).days

        if days_left < 0:
            return {"check": "SSL Certificate Validity", "passed": False, "impact": -25,
                    "detail": f"Certificate expired {abs(days_left)} day(s) ago."}
        elif days_left < 14:
            return {"check": "SSL Certificate Validity", "passed": False, "impact": -10,
                    "detail": f"Certificate expires very soon ({days_left} day(s) left)."}
        return {"check": "SSL Certificate Validity", "passed": True, "impact": 0,
                "detail": f"Certificate valid, expires in {days_left} day(s)."}

    except ssl.SSLCertVerificationError as e:
        return {"check": "SSL Certificate Validity", "passed": False, "impact": -25,
                "detail": f"Certificate verification failed (possibly self-signed or domain mismatch): {e}"}
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        return {"check": "SSL Certificate Validity", "passed": False, "impact": -20,
                "detail": f"Could not establish SSL connection: {e}"}
    except Exception as e:
        return {"check": "SSL Certificate Validity", "passed": False, "impact": -15,
                "detail": f"Unexpected error checking certificate: {e}"}


def check_tls_version(url: str) -> dict:
    """Checks which TLS version the server negotiates; flags outdated protocols."""
    domain = get_domain(url)
    try:
        context = get_ssl_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                version = ssock.version()

        if version in ("TLSv1.2", "TLSv1.3"):
            return {"check": "TLS Version", "passed": True, "impact": 0,
                    "detail": f"Server negotiated {version} — modern and secure."}
        else:
            return {"check": "TLS Version", "passed": False, "impact": -20,
                    "detail": f"Server negotiated outdated protocol: {version}."}
    except Exception as e:
        return {"check": "TLS Version", "passed": False, "impact": -10,
                "detail": f"Could not determine TLS version: {e}"}


def check_hsts_header(url: str) -> dict:
    """Checks for the Strict-Transport-Security header."""
    domain = get_domain(url)
    try:
        resp = requests.get(f"https://{domain}", timeout=8,
                             headers={"User-Agent": "Mozilla/5.0 (SecurityChecker/1.0)"})
        if "Strict-Transport-Security" in resp.headers:
            return {"check": "HSTS Header", "passed": True, "impact": 0,
                    "detail": "Strict-Transport-Security header is present."}
        return {"check": "HSTS Header", "passed": False, "impact": -5,
                "detail": "Strict-Transport-Security header is missing."}
    except requests.exceptions.RequestException as e:
        return {"check": "HSTS Header", "passed": False, "impact": -5,
                "detail": f"Could not check headers: {e}"}


def run_all_https_ssl_checks(raw_url: str) -> dict:
    """Runs every check in this module and returns a combined result."""
    findings = [
        check_https_enforced(raw_url),
        check_ssl_certificate(raw_url),
        check_tls_version(raw_url),
        check_hsts_header(raw_url),
    ]

    total_impact = sum(f["impact"] for f in findings)

    return {
        "domain": get_domain(raw_url),
        "findings": findings,
        "total_impact": total_impact,
    }


# Quick manual test — run this file directly: python checks/https_ssl.py
if __name__ == "__main__":
    test_url = input("Enter a URL to test: ").strip()
    result = run_all_https_ssl_checks(test_url)

    print(f"\nDomain: {result['domain']}")
    print(f"Total impact from this module: {result['total_impact']} points\n")

    for f in result["findings"]:
        status = "PASS" if f["passed"] else "FAIL"
        print(f"[{status}] {f['check']} ({f['impact']:+d}) — {f['detail']}")