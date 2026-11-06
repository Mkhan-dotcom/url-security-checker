"""
domain_reputation.py
Checks: domain age via WHOIS, and known-malicious status via Google
Safe Browsing API.

Requires a .env file in the project root containing:
    GOOGLE_SAFE_BROWSING_API_KEY=your_key_here

Each check returns the same dict shape used across the project:
{ "check": ..., "passed": ..., "impact": ..., "detail": ... }
"""

import os
import datetime
from urllib.parse import urlparse

import requests
import whois
from dotenv import load_dotenv

# Loads variables from a .env file in the project root into os.environ
load_dotenv()

SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def get_domain(url: str) -> str:
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    return domain.split(":")[0].split("/")[0]


def check_domain_age(url: str) -> dict:
    """Looks up WHOIS registration data and flags very recently registered domains."""
    domain = get_domain(url)
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        # python-whois sometimes returns a list of dates instead of one
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return {"check": "Domain Age", "passed": False, "impact": -5,
                    "detail": "Could not determine domain registration date from WHOIS."}

        # Normalize to timezone-naive so subtraction always works, regardless
        # of whether the WHOIS server returned an aware or naive datetime.
        if creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)

        age_days = (datetime.datetime.now() - creation_date).days

        if age_days < 30:
            return {"check": "Domain Age", "passed": False, "impact": -20,
                    "detail": f"Domain registered only {age_days} day(s) ago — very new domains are higher risk."}
        elif age_days < 180:
            return {"check": "Domain Age", "passed": False, "impact": -10,
                    "detail": f"Domain registered {age_days} day(s) ago — relatively new."}
        else:
            years = age_days // 365
            return {"check": "Domain Age", "passed": True, "impact": 0,
                    "detail": f"Domain registered approximately {years} year(s) ago — established."}

    except Exception as e:
        return {"check": "Domain Age", "passed": False, "impact": -5,
                "detail": f"WHOIS lookup failed: {e}"}


def check_google_safe_browsing(url: str) -> dict:
    """Queries Google Safe Browsing for known malware/phishing/unwanted-software matches."""
    if not SAFE_BROWSING_API_KEY:
        return {"check": "Google Safe Browsing", "passed": True, "impact": 0,
                "detail": "Skipped — no API key configured (set GOOGLE_SAFE_BROWSING_API_KEY in .env).",
                "flagged": False}

    payload = {
        "client": {"clientId": "url-security-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(
            SAFE_BROWSING_URL,
            params={"key": SAFE_BROWSING_API_KEY},
            json=payload,
            timeout=8,
        )
        resp.raise_for_status()
        data = resp.json()

        if "matches" in data and data["matches"]:
            threat_types = ", ".join(sorted({m["threatType"] for m in data["matches"]}))
            return {"check": "Google Safe Browsing", "passed": False, "impact": -40,
                    "detail": f"URL flagged by Google Safe Browsing as: {threat_types}.",
                    "flagged": True}

        return {"check": "Google Safe Browsing", "passed": True, "impact": 0,
                "detail": "No known threats found in Google Safe Browsing database.",
                "flagged": False}

    except requests.exceptions.HTTPError as e:
        return {"check": "Google Safe Browsing", "passed": True, "impact": 0,
                "detail": f"Safe Browsing API error (check your API key/quota): {e}",
                "flagged": False}
    except requests.exceptions.RequestException as e:
        return {"check": "Google Safe Browsing", "passed": True, "impact": 0,
                "detail": f"Could not reach Safe Browsing API: {e}",
                "flagged": False}


def run_all_domain_reputation_checks(raw_url: str) -> dict:
    """Runs every check in this module and returns a combined result."""
    age_result = check_domain_age(raw_url)
    safe_browsing_result = check_google_safe_browsing(raw_url)

    flagged = safe_browsing_result.pop("flagged", False)
    findings = [age_result, safe_browsing_result]
    total_impact = sum(f["impact"] for f in findings)

    return {
        "domain": get_domain(raw_url),
        "findings": findings,
        "total_impact": total_impact,
        "safe_browsing_flagged": flagged,
    }


# Quick manual test — run this file directly: python checks/domain_reputation.py
if __name__ == "__main__":
    test_url = input("Enter a URL to test: ").strip()
    result = run_all_domain_reputation_checks(test_url)

    print(f"\nDomain: {result['domain']}")
    print(f"Total impact from this module: {result['total_impact']} points")
    print(f"Safe Browsing flagged: {result['safe_browsing_flagged']}\n")

    for f in result["findings"]:
        status = "PASS" if f["passed"] else "FAIL"
        print(f"[{status}] {f['check']} ({f['impact']:+d}) — {f['detail']}")