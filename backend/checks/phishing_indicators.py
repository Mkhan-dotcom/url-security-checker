"""
phishing_indicators.py
Checks: known URL-shortener usage.

This module previously included keyword pattern-matching and brand
impersonation (typosquat) detection via hardcoded heuristics. Both were
removed deliberately: they represented subjective pattern-guessing rather
than verifiable facts, carried real false-positive risk (e.g. flagging
legitimate institutional subdomains or missing brands outside a small
hardcoded list), and their scoring weights were not derived from any
calibrated dataset. The remaining check below is a factual, deterministic
match against a list of real, known URL-shortening services — not a guess.

Each check returns the same dict shape used across the project:
{ "check": ..., "passed": ..., "impact": ..., "detail": ... }
"""

from urllib.parse import urlparse

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}


def get_domain(url: str) -> str:
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    return domain.split(":")[0].split("/")[0].lower()


def check_url_shortener(url: str) -> dict:
    domain = get_domain(url)
    if domain in KNOWN_SHORTENERS:
        return {"check": "URL Shortener", "passed": False, "impact": -5,
                "detail": f"'{domain}' is a known URL shortener — destination is hidden until visited."}
    return {"check": "URL Shortener", "passed": True, "impact": 0,
            "detail": "Not a known URL shortener."}


def run_all_phishing_checks(raw_url: str) -> dict:
    findings = [
        check_url_shortener(raw_url),
    ]

    total_impact = sum(f["impact"] for f in findings)

    return {
        "domain": get_domain(raw_url),
        "findings": findings,
        "total_impact": total_impact,
    }


# Quick manual test — run this file directly: python checks/phishing_indicators.py
if __name__ == "__main__":
    test_url = input("Enter a URL to test: ").strip()
    result = run_all_phishing_checks(test_url)

    print(f"\nDomain: {result['domain']}")
    print(f"Total impact from this module: {result['total_impact']} points\n")

    for f in result["findings"]:
        status = "PASS" if f["passed"] else "FAIL"
        print(f"[{status}] {f['check']} ({f['impact']:+d}) — {f['detail']}")