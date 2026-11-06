"""
url_structure.py
Checks: URL length, subdomain count, special characters, IP-as-domain,
redirect chain, suspicious TLDs.

Each check returns a dict:
{
    "check": "name",
    "passed": True/False,
    "impact": <points, negative or 0>,
    "detail": "human readable explanation"
}
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse
import requests

SUSPICIOUS_TLDS = {".tk", ".top", ".xyz", ".click", ".work", ".gq", ".ml", ".cf"}


def normalize_url(raw_url: str) -> str:
    """Ensure the URL has a scheme so urlparse/requests work correctly."""
    raw_url = raw_url.strip()
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        raw_url = "http://" + raw_url
    return raw_url


def is_valid_domain_format(url: str) -> bool:
    """
    Checks that the domain portion looks like a real, resolvable domain
    (at least one dot + valid TLD) OR a valid IPv4 address (IP-based URLs
    are syntactically valid and should be scanned/flagged by
    check_ip_as_domain, not rejected outright).
    Rejects bare words like 'amazone' that have no TLD and aren't an IP.
    """
    domain = urlparse(url).netloc.split(":")[0]

    try:
        if isinstance(ipaddress.ip_address(domain), ipaddress.IPv4Address):
            return True
    except ValueError:
        pass

    domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(domain_pattern, domain))


def check_url_length(url: str) -> dict:
    length = len(url)
    if length > 100:
        return {"check": "URL Length", "passed": False, "impact": -15,
                "detail": f"URL is {length} characters — unusually long (>100)."}
    elif length > 75:
        return {"check": "URL Length", "passed": False, "impact": -5,
                "detail": f"URL is {length} characters — longer than typical (>75)."}
    return {"check": "URL Length", "passed": True, "impact": 0,
            "detail": f"URL length ({length} chars) is normal."}


def check_special_characters(url: str) -> dict:
    """
    Checks for the '@' symbol in a URL — a documented browser-parsing
    exploit (everything before '@' is treated as userinfo and ignored,
    so 'https://real-bank.com@attacker.com' actually navigates to
    attacker.com). This is a factual detection of a known technique,
    not a subjective pattern guess.
    """
    if "@" in url:
        return {"check": "'@' Symbol Check", "passed": False, "impact": -15,
                "detail": "'@' symbol present — this is a known technique to hide the "
                          "real destination domain from users (everything before '@' is ignored)."}
    return {"check": "'@' Symbol Check", "passed": True, "impact": 0,
            "detail": "No '@' symbol found in URL."}


def check_ip_as_domain(url: str) -> dict:
    domain = urlparse(url).netloc.split(":")[0]
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(domain):
        return {"check": "IP Address as Domain", "passed": False, "impact": -20,
                "detail": f"URL uses a raw IP address ({domain}) instead of a domain name."}
    return {"check": "IP Address as Domain", "passed": True, "impact": 0,
            "detail": "URL uses a proper domain name, not a raw IP."}


def check_suspicious_tld(url: str) -> dict:
    domain = urlparse(url).netloc.split(":")[0]
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return {"check": "Suspicious TLD", "passed": False, "impact": -10,
                    "detail": f"Domain uses '{tld}', a TLD associated with higher phishing rates."}
    return {"check": "Suspicious TLD", "passed": True, "impact": 0,
            "detail": "Domain TLD is not on the high-risk list."}


def check_redirect_chain(url: str) -> dict:
    """Follows redirects and flags if the final domain differs or there are too many hops."""
    try:
        response = requests.get(url, timeout=8, allow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0 (SecurityChecker/1.0)"})
        history = response.history
        final_url = response.url
        hops = len(history)

        original_domain = urlparse(url).netloc.split(":")[0].replace("www.", "")
        final_domain = urlparse(final_url).netloc.split(":")[0].replace("www.", "")

        if hops > 2:
            return {"check": "Redirect Chain", "passed": False, "impact": -10,
                    "detail": f"{hops} redirects before reaching final destination — excessive.",
                    "final_url": final_url}
        if original_domain != final_domain:
            return {"check": "Redirect Chain", "passed": False, "impact": -15,
                    "detail": f"Redirects to a different domain ('{original_domain}' -> '{final_domain}').",
                    "final_url": final_url}
        return {"check": "Redirect Chain", "passed": True, "impact": 0,
                "detail": f"{hops} redirect(s), same domain throughout." if hops else "No redirects.",
                "final_url": final_url}
    except requests.exceptions.RequestException as e:
        return {"check": "Redirect Chain", "passed": False, "impact": -5,
                "detail": f"Could not resolve/connect to URL: {e}",
                "final_url": url}


def run_all_url_structure_checks(raw_url: str) -> dict:
    """Runs every check in this module and returns a combined result."""
    url = normalize_url(raw_url)

    findings = [
        check_url_length(url),
        check_special_characters(url),
        check_ip_as_domain(url),
        check_suspicious_tld(url),
    ]

    redirect_result = check_redirect_chain(url)
    final_url = redirect_result.pop("final_url", url)
    findings.append(redirect_result)

    total_impact = sum(f["impact"] for f in findings)

    return {
        "submitted_url": url,
        "final_url": final_url,
        "findings": findings,
        "total_impact": total_impact,
    }


# Quick manual test — run this file directly: python checks/url_structure.py
if __name__ == "__main__":
    test_url = input("Enter a URL to test: ").strip()
    result = run_all_url_structure_checks(test_url)

    print(f"\nSubmitted: {result['submitted_url']}")
    print(f"Final URL: {result['final_url']}")
    print(f"Total impact from this module: {result['total_impact']} points\n")

    for f in result["findings"]:
        status = "PASS" if f["passed"] else "FAIL"
        print(f"[{status}] {f['check']} ({f['impact']:+d}) — {f['detail']}")