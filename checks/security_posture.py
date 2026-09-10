"""
security_posture.py

Checks the *content and configuration* the target site itself serves —
not whether the URL looks like phishing, but whether the site's own
security hygiene is sound. This mirrors what tools like Mozilla
Observatory or securityheaders.com check:

  - Security response headers (CSP, X-Frame-Options, etc.)
  - Cookie flags (Secure / HttpOnly / SameSite)
  - Mixed content (HTTP resources loaded on an HTTPS page)
  - Server/technology version disclosure
  - Accidentally exposed sensitive files (.env, .git/config, etc.)

Works both as part of the 'checks' package and standalone:
    python checks/security_posture.py
"""

import re
import requests

REQUEST_TIMEOUT = 8
USER_AGENT = "url-security-checker/1.0 (+educational FYP security scanner)"

HEADERS_TO_CHECK = [
    ("Content-Security-Policy", "CSP header missing — no defense against injected scripts/styles."),
    ("X-Content-Type-Options", "X-Content-Type-Options missing — browser may MIME-sniff responses."),
    ("X-Frame-Options", "X-Frame-Options missing — page can be embedded in a clickjacking iframe."),
    ("Referrer-Policy", "Referrer-Policy missing — full URLs may leak to third parties via referrer."),
    ("Permissions-Policy", "Permissions-Policy missing — no restriction on camera/mic/geolocation APIs."),
]

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/wp-config.php.bak",
    "/config.php.bak",
    "/.DS_Store",
]


def _finding(check, passed, impact, detail):
    return {"check": check, "passed": passed, "impact": impact if not passed else 0, "detail": detail}


def _safe_get(url, **kwargs):
    try:
        return requests.get(
            url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT}, **kwargs
        )
    except requests.RequestException:
        return None


def check_security_headers(response) -> list:
    findings = []
    if response is None:
        return findings
    headers = response.headers
    for header_name, fail_detail in HEADERS_TO_CHECK:
        present = header_name in headers
        findings.append(
            _finding(
                f"Header: {header_name}",
                present,
                -5,
                f"{header_name} is present." if present else fail_detail,
            )
        )
    return findings


def check_cookie_flags(response) -> list:
    findings = []
    if response is None:
        return findings

    raw_cookies = response.raw.headers.get_all("Set-Cookie") if hasattr(response.raw, "headers") else None
    if not raw_cookies:
        findings.append(_finding("Cookie Security Flags", True, 0, "No cookies set by this response."))
        return findings

    for cookie in raw_cookies:
        name = cookie.split("=", 1)[0].strip()
        lower = cookie.lower()
        missing = []
        if "secure" not in lower:
            missing.append("Secure")
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite" not in lower:
            missing.append("SameSite")

        if missing:
            findings.append(
                _finding(
                    f"Cookie Flags: {name}",
                    False,
                    -8,
                    f"Cookie '{name}' is missing: {', '.join(missing)}.",
                )
            )
        else:
            findings.append(
                _finding(f"Cookie Flags: {name}", True, 0, f"Cookie '{name}' sets Secure, HttpOnly, and SameSite.")
            )
    return findings


def check_mixed_content(response, final_url: str) -> list:
    if response is None or not final_url.startswith("https://"):
        return []

    html = response.text
    http_refs = re.findall(r'(?:src|href)=["\']http://[^"\']+["\']', html, re.IGNORECASE)

    if http_refs:
        example = http_refs[0].split("=", 1)[1].strip("\"'")
        return [
            _finding(
                "Mixed Content",
                False,
                -10,
                f"Page loads over HTTPS but references {len(http_refs)} insecure http:// resource(s), e.g. {example}",
            )
        ]
    return [_finding("Mixed Content", True, 0, "No insecure http:// resources found on an HTTPS page.")]


def check_server_disclosure(response) -> list:
    findings = []
    if response is None:
        return findings

    for header_name in ("Server", "X-Powered-By"):
        value = response.headers.get(header_name)
        if value and re.search(r"\d+\.\d+", value):
            findings.append(
                _finding(
                    f"{header_name} Disclosure",
                    False,
                    -5,
                    f"{header_name} header discloses version info: '{value}'.",
                )
            )
        elif value:
            findings.append(
                _finding(f"{header_name} Disclosure", True, 0, f"{header_name} present but no version disclosed.")
            )
    return findings


def check_exposed_files(base_url: str) -> list:
    findings = []
    origin_match = re.match(r"(https?://[^/]+)", base_url)
    if not origin_match:
        return findings
    origin = origin_match.group(1)

    baseline = _safe_get(f"{origin}/__nonexistent_probe_a1b2c3/")
    baseline_status = baseline.status_code if baseline else None
    baseline_length = len(baseline.content) if baseline else None

    any_exposed = False
    for path in SENSITIVE_PATHS:
        resp = _safe_get(f"{origin}{path}")
        if resp is None:
            continue

        looks_real = resp.status_code == 200 and (
            baseline_status != 200 or len(resp.content) != baseline_length
        )

        if looks_real:
            any_exposed = True
            findings.append(
                _finding(
                    f"Exposed File: {path}",
                    False,
                    -25,
                    f"{path} returned HTTP 200 with distinct content — may be publicly accessible.",
                )
            )

    if not any_exposed:
        findings.append(
            _finding("Exposed Sensitive Files", True, 0, "None of the common sensitive file paths were exposed.")
        )
    return findings


def run_all_security_posture_checks(final_url: str) -> dict:
    response = _safe_get(final_url)

    findings = []
    findings += check_security_headers(response)
    findings += check_cookie_flags(response)
    findings += check_mixed_content(response, final_url)
    findings += check_server_disclosure(response)
    findings += check_exposed_files(final_url)

    total_impact = sum(f["impact"] for f in findings)

    return {"findings": findings, "total_impact": total_impact}


if __name__ == "__main__":
    test_url = input("Enter a URL to test: ").strip()
    if not test_url.startswith("http"):
        test_url = "https://" + test_url

    result = run_all_security_posture_checks(test_url)
    print(f"\nTotal impact: {result['total_impact']}\n")
    for f in result["findings"]:
        status = "PASS" if f["passed"] else "FAIL"
        print(f"[{status}] {f['check']} ({f['impact']:+d}) — {f['detail']}")