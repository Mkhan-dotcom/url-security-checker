"""
phishing_indicators.py
Checks: suspicious keywords in the URL, brand impersonation / typosquatting,
and known URL-shortener usage.

Each check returns the same dict shape used across the project:
{ "check": ..., "passed": ..., "impact": ..., "detail": ... }
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "verify", "secure", "account-update", "login-confirm", "update-account",
    "confirm-identity", "signin-secure", "webscr", "banking-alert",
    "password-reset", "unlock-account", "suspended", "urgent-action",
]

# A short list of frequently-impersonated brands for typosquat comparison.
# In production this would be a much larger, regularly-updated list.
POPULAR_BRANDS = [
    "google", "amazon", "paypal", "microsoft", "apple", "facebook",
    "netflix", "instagram", "linkedin", "bankofamerica", "chase",
    "wellsfargo", "ebay", "twitter", "whatsapp", "dropbox",
]

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}


def get_domain(url: str) -> str:
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    return domain.split(":")[0].split("/")[0].lower()


def levenshtein_distance(a: str, b: str) -> int:
    """Standard edit-distance calculation, no external dependency needed."""
    if len(a) < len(b):
        return levenshtein_distance(b, a)
    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def check_suspicious_keywords(url: str) -> dict:
    url_lower = url.lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]

    if found:
        impact = -5 * len(found)
        impact = max(impact, -20)  # cap so one URL doesn't get destroyed by keyword stuffing alone
        return {"check": "Suspicious Keywords", "passed": False, "impact": impact,
                "detail": f"Found suspicious keyword(s): {', '.join(found)}."}
    return {"check": "Suspicious Keywords", "passed": True, "impact": 0,
            "detail": "No suspicious keywords found in URL."}


def check_brand_impersonation(url: str) -> dict:
    domain = get_domain(url)
    no_www = re.sub(r"^www\.", "", domain)

    # Strip the TLD generically (works for ANY TLD, not just a fixed list —
    # e.g. .tk, .top, .xyz — by dropping the last dot-separated segment).
    labels = no_www.split(".")
    core_domain = labels[0] if len(labels) > 1 else no_www

    # Split the remaining label into tokens on hyphens/digits-as-letters so
    # "paypa1-login-verify" is compared token-by-token, not as one long string.
    tokens = re.split(r"[-_]", core_domain)
    tokens.append(core_domain)  # also compare the whole label, not just parts

    for brand in POPULAR_BRANDS:
        if core_domain == brand:
            continue  # it IS the real brand domain, not impersonation

        for token in tokens:
            if not token:
                continue
            distance = levenshtein_distance(token, brand)

            # Very close spelling (1-2 edits) to a real brand = likely typosquat
            if 0 < distance <= 2 and len(token) >= len(brand) - 2:
                return {"check": "Brand Impersonation", "passed": False, "impact": -25,
                        "detail": f"Domain '{domain}' contains '{token}', which closely resembles "
                                  f"'{brand}' (edit distance {distance}) — possible typosquatting."}

            # Brand name embedded in a longer token that isn't the real one
            if brand in token and token != brand:
                return {"check": "Brand Impersonation", "passed": False, "impact": -20,
                        "detail": f"Domain '{domain}' contains brand name '{brand}' "
                                  f"but is not the official domain."}

    return {"check": "Brand Impersonation", "passed": True, "impact": 0,
            "detail": "No brand impersonation patterns detected."}


def check_url_shortener(url: str) -> dict:
    domain = get_domain(url)
    if domain in KNOWN_SHORTENERS:
        return {"check": "URL Shortener", "passed": False, "impact": -5,
                "detail": f"'{domain}' is a known URL shortener — destination is hidden until visited."}
    return {"check": "URL Shortener", "passed": True, "impact": 0,
            "detail": "Not a known URL shortener."}


def run_all_phishing_checks(raw_url: str) -> dict:
    findings = [
        check_suspicious_keywords(raw_url),
        check_brand_impersonation(raw_url),
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