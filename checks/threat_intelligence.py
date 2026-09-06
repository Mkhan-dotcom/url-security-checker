"""
threat_intelligence.py
Adds two genuinely real, non-heuristic data sources:

1. URLhaus (abuse.ch) - a live, actively-maintained database of URLs
   confirmed to be distributing malware. Free, no API key required.
   https://urlhaus-api.abuse.ch/

2. Certificate Transparency logs (crt.sh) - a public, legally-mandated
   record of every SSL certificate ever issued for a domain (RFC 6962).
   Used here to check how long a domain has had a publicly logged
   certificate history. Phishing domains are very often first seen in
   CT logs only hours or days before an attack, since attackers request
   free instant certificates right before launching a campaign.
   Free, no API key required — BUT crt.sh has no official API contract:
   it is an unofficial, undocumented interface (per Sectigo/Rob Stradling),
   informally rate-limited to roughly 5 requests/minute per IP, and can
   return empty results or timeouts under load. This is handled gracefully
   below (failures are skipped, not treated as a negative finding), but
   is a genuine limitation worth documenting in the report.

Both checks return the same dict shape used across the project:
{ "check": ..., "passed": ..., "impact": ..., "detail": ... }
"""

import os
import datetime
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
CRTSH_API = "https://crt.sh/"
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")


def get_domain(url: str) -> str:
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    return domain.split(":")[0].split("/")[0]


def check_urlhaus(url: str) -> dict:
    """
    Queries URLhaus for confirmed active malware-distribution URLs.
    Requires a free Auth-Key (abuse.ch made authentication mandatory as of
    June 30, 2025). Sign up free at https://auth.abuse.ch/ and generate a
    key, then set URLHAUS_AUTH_KEY in your .env file.
    """
    if not URLHAUS_AUTH_KEY:
        return {"check": "URLhaus Malware Database", "passed": True, "impact": 0,
                "detail": "Skipped — no Auth-Key configured (set URLHAUS_AUTH_KEY in .env). "
                          "Free key available at https://auth.abuse.ch/",
                "flagged": False}

    try:
        resp = requests.post(
            URLHAUS_API,
            data={"url": url},
            headers={"Auth-Key": URLHAUS_AUTH_KEY},
            timeout=8,
        )
        data = resp.json()

        if data.get("query_status") == "ok":
            threat_type = data.get("threat", "malware")
            tags = data.get("tags") or []
            status = data.get("url_status", "unknown")
            tag_str = f" (tags: {', '.join(tags)})" if tags else ""
            return {"check": "URLhaus Malware Database", "passed": False, "impact": -40,
                    "detail": f"URL is a confirmed {threat_type} distribution site "
                              f"(status: {status}){tag_str}.",
                    "flagged": True}

        return {"check": "URLhaus Malware Database", "passed": True, "impact": 0,
                "detail": "Not found in the URLhaus active malware database.",
                "flagged": False}

    except requests.exceptions.RequestException as e:
        return {"check": "URLhaus Malware Database", "passed": True, "impact": 0,
                "detail": f"Could not reach URLhaus: {e}",
                "flagged": False}
    except ValueError:
        return {"check": "URLhaus Malware Database", "passed": True, "impact": 0,
                "detail": "URLhaus returned an unexpected response; skipped.",
                "flagged": False}


def check_certificate_transparency(url: str) -> dict:
    """
    Looks up how long this domain has had a publicly logged SSL certificate
    via Certificate Transparency logs. A domain with no CT history, or one
    whose earliest logged certificate is very recent, is a real (not
    heuristic) signal often seen with newly-spun-up phishing infrastructure.
    """
    domain = get_domain(url)
    try:
        resp = requests.get(CRTSH_API, params={"q": domain, "output": "json"}, timeout=12)
        if resp.status_code != 200 or not resp.text.strip():
            return {"check": "Certificate Transparency History", "passed": True, "impact": 0,
                    "detail": "Certificate Transparency lookup returned no data; skipped.",
                    "flagged": False}

        entries = resp.json()
        if not entries:
            return {"check": "Certificate Transparency History", "passed": False, "impact": -15,
                    "detail": "No Certificate Transparency history found for this domain — "
                              "unusual for an established site.",
                    "flagged": False}

        earliest = None
        for entry in entries:
            not_before_str = entry.get("not_before")
            if not not_before_str:
                continue
            try:
                not_before = datetime.datetime.strptime(not_before_str, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                continue
            if earliest is None or not_before < earliest:
                earliest = not_before

        if earliest is None:
            return {"check": "Certificate Transparency History", "passed": True, "impact": 0,
                    "detail": "Certificate Transparency data was present but unparsable; skipped.",
                    "flagged": False}

        age_days = (datetime.datetime.utcnow() - earliest).days

        if age_days < 7:
            return {"check": "Certificate Transparency History", "passed": False, "impact": -15,
                    "detail": f"Earliest publicly logged certificate is only {age_days} day(s) old — "
                              f"very recently established HTTPS presence."}
        elif age_days < 30:
            return {"check": "Certificate Transparency History", "passed": False, "impact": -5,
                    "detail": f"Earliest publicly logged certificate is {age_days} day(s) old."}

        years = age_days // 365
        detail = (f"Certificate history spans ~{years} year(s)" if years >= 1
                  else f"Certificate history spans {age_days} day(s)")
        return {"check": "Certificate Transparency History", "passed": True, "impact": 0,
                "detail": f"{detail} — established HTTPS presence."}

    except requests.exceptions.RequestException as e:
        return {"check": "Certificate Transparency History", "passed": True, "impact": 0,
                "detail": f"Could not reach crt.sh: {e}",
                "flagged": False}
    except ValueError:
        return {"check": "Certificate Transparency History", "passed": True, "impact": 0,
                "detail": "crt.sh returned an unexpected response; skipped.",
                "flagged": False}


def run_all_threat_intelligence_checks(raw_url: str) -> dict:
    """Runs every check in this module and returns a combined result."""
    urlhaus_result = check_urlhaus(raw_url)
    ct_result = check_certificate_transparency(raw_url)

    urlhaus_flagged = urlhaus_result.pop("flagged", False)
    ct_result.pop("flagged", None)

    findings = [urlhaus_result, ct_result]
    total_impact = sum(f["impact"] for f in findings)

    return {
        "domain": get_domain(raw_url),
        "findings": findings,
        "total_impact": total_impact,
        "urlhaus_flagged": urlhaus_flagged,
    }


# Quick manual test — run this file directly: python checks/threat_intelligence.py
if __name__ == "__main__":
    test_url = input("Enter a URL to test: ").strip()
    result = run_all_threat_intelligence_checks(test_url)

    print(f"\nDomain: {result['domain']}")
    print(f"Total impact from this module: {result['total_impact']} points")
    print(f"URLhaus flagged: {result['urlhaus_flagged']}\n")

    for f in result["findings"]:
        status = "PASS" if f["passed"] else "FAIL"
        print(f"[{status}] {f['check']} ({f['impact']:+d}) — {f['detail']}")