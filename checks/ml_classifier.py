"""
ml_classifier.py
Loads the trained Random Forest phishing classifier and scores a URL
using ONLY features computable from the URL string itself (no network
calls), so this check runs instantly.

Model trained on: Hannousse & Yahiouche (2021) phishing URL dataset,
11,430 URLs, balanced 50/50. Test-set performance (30% holdout,
20 URL-string features only, no page-content/traffic features):
    Accuracy:  0.891
    Precision: 0.890
    Recall:    0.893
    F1 Score:  0.891

Feature extraction below deliberately mirrors the exact definitions used
in the original dataset's extraction pipeline (verified against the
reference implementation) to avoid train/serve skew — a common and
otherwise easy-to-miss source of silently degraded ML accuracy in
production.

See train_model.py for the training script and full evaluation output.
"""

import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
import tldextract

MODEL_PATH = Path(__file__).parent / "phishing_rf_model.joblib"

# Forces tldextract to use its bundled offline snapshot of the public
# suffix list instead of fetching it live from publicsuffix.org. This
# keeps this module's "no network calls" guarantee genuinely true, and
# avoids failures if that external site is ever unreachable.
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

FEATURE_COLUMNS = [
    "length_url", "length_hostname", "ip", "nb_dots", "nb_hyphens",
    "nb_at", "nb_qm", "nb_and", "nb_eq", "nb_underscore", "nb_slash",
    "nb_www", "https_token", "ratio_digits_url", "ratio_digits_host",
    "nb_subdomains", "prefix_suffix", "shortening_service",
    "suspicious_tld", "phish_hints",
]

HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images',
         'js', 'alibaba', 'css', 'myaccount', 'dropbox', 'themes',
         'plugins', 'signin', 'view']

SUSPICIOUS_TLDS = {
    'fit', 'tk', 'gp', 'ga', 'work', 'ml', 'date', 'wang', 'men', 'icu',
    'online', 'click', 'country', 'stream', 'download', 'xin', 'racing',
    'jetzt', 'ren', 'mom', 'party', 'review', 'trade', 'accountants',
    'science', 'ninja', 'xyz', 'faith', 'zip', 'cricket', 'win',
    'accountant', 'realtor', 'top', 'christmas', 'gdn', 'link', 'asia',
    'club', 'la', 'ae', 'exposed', 'pe', 'website', 'bj', 'mx', 'media',
}

SHORTENER_PATTERN = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|"
    r"tr\.im|is\.gd|cli\.gs|tiny\.cc|url4\.eu|su\.pr|snipurl\.com|"
    r"short\.to|bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|cur\.lv|bc\.vc|"
    r"u\.to|j\.mp|buzurl\.com|cutt\.us|v\.gd|link\.zip\.net"
)

_model = None


def _get_model():
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    return _model


def _having_ip_address(url: str) -> int:
    pattern = (
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
        r'([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])/)|'
        r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})/)'
    )
    return 1 if re.search(pattern, url) else 0


def _ratio_digits(s: str) -> float:
    if not s:
        return 0.0
    digits = len(re.sub(r"[^0-9]", "", s))
    return digits / len(s)


def _count_subdomain(url: str) -> int:
    dot_count = len(re.findall(r"\.", url))
    if dot_count == 1:
        return 1
    elif dot_count == 2:
        return 2
    return 3


def _prefix_suffix(url: str) -> int:
    return 1 if re.findall(r"https?://[^\-]+-[^\-]+/", url) else 0


def _phish_hints(url: str) -> int:
    url_lower = url.lower()
    return sum(url_lower.count(hint) for hint in HINTS)


def extract_features(raw_url: str) -> list:
    """Extracts the 20 URL-string features in the exact order the model was trained on."""
    url = raw_url if re.match(r"^https?://", raw_url, re.IGNORECASE) else "http://" + raw_url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    extracted = _tld_extractor(url)
    tld = extracted.suffix

    words_raw = re.split(r"[\-\.\/\?\=\@\&\%\:\_]", url.lower())
    nb_www = sum(1 for w in words_raw if 'www' in w)

    features = {
        "length_url": len(url),
        "length_hostname": len(hostname),
        "ip": _having_ip_address(url),
        "nb_dots": url.count("."),
        "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"),
        "nb_qm": url.count("?"),
        "nb_and": url.count("&"),
        "nb_eq": url.count("="),
        "nb_underscore": url.count("_"),
        "nb_slash": url.count("/"),
        "nb_www": nb_www,
        "https_token": 0 if parsed.scheme == "https" else 1,
        "ratio_digits_url": _ratio_digits(url),
        "ratio_digits_host": _ratio_digits(hostname),
        "nb_subdomains": _count_subdomain(url),
        "prefix_suffix": _prefix_suffix(url),
        "shortening_service": 1 if SHORTENER_PATTERN.search(url) else 0,
        "suspicious_tld": 1 if tld in SUSPICIOUS_TLDS else 0,
        "phish_hints": _phish_hints(url),
    }

    return [features[col] for col in FEATURE_COLUMNS]


def check_ml_classifier(url: str) -> dict:
    """
    Scores a URL with the trained Random Forest model and returns a
    finding scaled by the model's predicted confidence, not just a
    binary label.
    """
    try:
        model = _get_model()
        feature_vector = pd.DataFrame([extract_features(url)], columns=FEATURE_COLUMNS)
        probabilities = model.predict_proba(feature_vector)[0]
        phishing_probability = probabilities[1]  # class 1 = phishing

        if phishing_probability >= 0.75:
            return {"check": "ML Phishing Classifier", "passed": False, "impact": -30,
                    "detail": f"Random Forest model (trained on 11,430 labeled URLs) predicts "
                              f"phishing with {phishing_probability:.0%} confidence."}
        elif phishing_probability >= 0.5:
            return {"check": "ML Phishing Classifier", "passed": False, "impact": -15,
                    "detail": f"Random Forest model predicts phishing with moderate confidence "
                              f"({phishing_probability:.0%})."}
        elif phishing_probability >= 0.3:
            return {"check": "ML Phishing Classifier", "passed": True, "impact": 0,
                    "detail": f"Random Forest model predicts legitimate, but with some uncertainty "
                              f"({phishing_probability:.0%} phishing probability)."}
        else:
            return {"check": "ML Phishing Classifier", "passed": True, "impact": 0,
                    "detail": f"Random Forest model predicts legitimate with high confidence "
                              f"({phishing_probability:.0%} phishing probability)."}

    except Exception as e:
        return {"check": "ML Phishing Classifier", "passed": True, "impact": 0,
                "detail": f"ML classifier unavailable: {e}"}


def run_all_ml_checks(raw_url: str) -> dict:
    findings = [check_ml_classifier(raw_url)]
    total_impact = sum(f["impact"] for f in findings)
    return {"findings": findings, "total_impact": total_impact}


# Quick manual test — run this file directly: python checks/ml_classifier.py
if __name__ == "__main__":
    test_url = input("Enter a URL to test: ").strip()
    result = check_ml_classifier(test_url)
    status = "PASS" if result["passed"] else "FAIL"
    print(f"\n[{status}] {result['check']} ({result['impact']:+d}) — {result['detail']}")