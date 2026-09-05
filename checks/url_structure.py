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
from urllib.parse import urlparse
import requests

SUSPICIOUS_TLDS = {".tk", ".top", ".xyz", ".click", ".work", ".gq", ".ml", ".cf"}


def normalize_url(raw_url: str) -> str:
    """Ensure the URL has a scheme so urlparse/requests work correctly."""
    raw_url = raw_url.strip()
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        raw_url = "http://" + raw_url
    return raw_url


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


def check_subdomain_count(url: str) -> dict:
    domain = urlparse(url).netloc.split(":")[0]  # strip port if present
    parts = domain.split(".")
    # e.g. "login.secure.account.example.com" -> 5 parts -> 3 subdomains before "example.com"
    subdomain_count = max(0, len(parts) - 2)
    if subdomain_count > 3:
        return {"check": "Subdomain Count", "passed": False, "impact": -10,
                "detail": f"{subdomain_count} subdomains detected — excessive nesting is a phishing red flag."}
    elif subdomain_count > 2:
        return {"check": "Subdomain Count", "passed": False, "impact": -5,
                "detail": f"{subdomain_count} subdomains detected — more than typical."}
    return {"check": "Subdomain Count", "passed": True, "impact": 0,
            "detail": f"{subdomain_count} subdomain(s) — within normal range."}


def check_special_characters(url: str) -> dict:
    domain = urlparse(url).netloc
    issues = []
    impact = 0

    if "@" in url:
        issues.append("'@' symbol present (can hide the real destination)")
        impact -= 15

    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        issues.append(f"{hyphen_count} hyphens in domain — unusually high")
        impact -= 10
    elif hyphen_count >= 1:
        issues.append(f"{hyphen_count} hyphen(s) in domain")
        impact -= 3

    digit_count = sum(c.isdigit() for c in domain)
    if digit_count >= 4:
        issues.append(f"{digit_count} digits in domain — unusually high")
        impact -= 10

    if issues:
        return {"check": "Special Characters", "passed": False, "impact": impact,
                "detail": "; ".join(issues)}
    return {"check": "Special Characters", "passed": True, "impact": 0,
            "detail": "No suspicious special-character patterns found."}


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
        check_subdomain_count(url),
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