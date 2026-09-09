"""
scoring.py
Combines results from url_structure, https_ssl, and phishing_indicators
into a single 0-100 score, A-F grade, and Safe/Suspicious/High Risk
classification.

Works both as part of the 'checks' package (imported from main.py) and
as a standalone script (python checks/scoring.py) for manual testing.
"""

try:
    from . import url_structure, https_ssl, phishing_indicators, domain_reputation, threat_intelligence, ml_classifier
except ImportError:
    import url_structure
    import https_ssl
    import phishing_indicators
    import domain_reputation
    import threat_intelligence
    import ml_classifier




def calculate_grade(score: int) -> tuple:
    """Maps a 0-100 score to a letter grade and risk classification."""
    if score >= 90:
        return "A", "Safe"
    elif score >= 80:
        return "B", "Safe"
    elif score >= 60:
        return "C", "Suspicious"
    elif score >= 40:
        return "D", "Suspicious"
    else:
        return "F", "High Risk"


def run_full_scan(raw_url: str) -> dict:
    """
    Runs every check module and produces the final combined report.
    Google Safe Browsing results (from domain_reputation.py) can force a
    hard override to High Risk regardless of other points — a known-
    malicious site shouldn't be rescued by good SSL config.
    """
    structure_result = url_structure.run_all_url_structure_checks(raw_url)
    ssl_result = https_ssl.run_all_https_ssl_checks(structure_result["final_url"])
    phishing_result = phishing_indicators.run_all_phishing_checks(structure_result["final_url"])
    reputation_result = domain_reputation.run_all_domain_reputation_checks(structure_result["final_url"])

    # intel_result = threat_intelligence.run_all_threat_intelligence_checks(structure_result["final_url"])
    intel_result = threat_intelligence.run_all_threat_intelligence_checks(structure_result["final_url"])
    ml_result = ml_classifier.run_all_ml_checks(structure_result["final_url"])


    all_findings = (
        structure_result["findings"]
        + ssl_result["findings"]
        + phishing_result["findings"]
        + reputation_result["findings"]
        + intel_result["findings"]
        + ml_result["findings"]   
    )


    total_deductions = (
        structure_result["total_impact"]
        + ssl_result["total_impact"]
        + phishing_result["total_impact"]
        + reputation_result["total_impact"]
        + intel_result["total_impact"]
    )

    score = max(0, min(100, 100 + total_deductions))
    grade, classification = calculate_grade(score)

    if reputation_result["safe_browsing_flagged"] or intel_result["urlhaus_flagged"]:
        score = min(score, 20)
        grade = "F"
        classification = "High Risk"

    return {
        "submitted_url": structure_result["submitted_url"],
        "final_url": structure_result["final_url"],
        "score": score,
        "grade": grade,
        "classification": classification,
        "checks_performed": len(all_findings),
        "findings": all_findings,
    }


# Quick manual test — run this file directly: python checks/scoring.py
if __name__ == "__main__":
    test_url = input("Enter a URL to test: ").strip()
    report = run_full_scan(test_url)

    print(f"\nSubmitted: {report['submitted_url']}")
    print(f"Final URL: {report['final_url']}")
    print(f"\nSECURITY SCORE: {report['score']} / 100")
    print(f"GRADE: {report['grade']}")
    print(f"CLASSIFICATION: {report['classification']}")
    print(f"Checks performed: {report['checks_performed']}\n")

    for f in report["findings"]:
        status = "PASS" if f["passed"] else "FAIL"
        print(f"[{status}] {f['check']} ({f['impact']:+d}) — {f['detail']}")