# Sus or not: URL Security Checker

Paste a link, get a security score, a letter grade, and the receipts.

This web app runs a URL through 20+ checks (URL structure, SSL/TLS, domain reputation, threat-intelligence feeds, security headers, and a phishing classifier trained on real data) and explains every result in plain English. It was originally built for a university assignment on URL security analysis.

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-backend-009688?logo=fastapi&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.9.0-F7931E?logo=scikitlearn&logoColor=white)
![Postgres](https://img.shields.io/badge/Postgres-Neon-4169E1?logo=postgresql&logoColor=white)
![Vercel](https://img.shields.io/badge/Hosted%20on-Vercel-000000?logo=vercel&logoColor=white)

**Live demo:** https://url-security-checker.vercel.app

## What you get

- A **0-100 score**, an **A-F grade**, and a **Safe / Suspicious / High Risk** classification
- A findings list showing every check, whether it passed, how many points it cost, and why
- **Scan history**: past scans are saved and can be reopened as full reports
- A scan animation (radar sweep with a progress ring) and an animated score gauge for the result

## What it checks

| Module | Checks |
|---|---|
| `url_structure.py` | URL length, `@` trick, raw IP as domain, suspicious TLDs, redirect chain |
| `https_ssl.py` | HTTPS enforcement, certificate validity and expiry, TLS version, HSTS |
| `phishing_indicators.py` | Known URL shorteners |
| `domain_reputation.py` | Domain age (WHOIS), Google Safe Browsing |
| `threat_intelligence.py` | URLhaus malware database, Certificate Transparency history (crt.sh) |
| `ml_classifier.py` | Random Forest phishing probability from URL features |
| `security_posture.py` | Security headers (CSP, X-Frame-Options, and more), cookie flags, mixed content, server version disclosure, exposed sensitive files |
| `scoring.py` | Combines everything into the score, grade, and classification |

### How scoring works

Every check returns `passed`, an `impact` (0, or a negative number if it failed), and a plain-English `detail`. The score starts at 100 and the impacts of the scored checks are added to it.

- If Google Safe Browsing or URLhaus flags the URL, the result is forced to **High Risk** no matter what else passed.
- The URL-shape rules (length, `@`, IP, TLD) and the shortener list are shown in the report but are not scored. Only the redirect-chain result from the structure checks counts.
- The ML prediction is scored as a separate statistical signal next to the live checks.

When a check can't reach its data source (a timeout, for example), it usually says so in its detail text instead of reporting a pass.

## How it works

```
Browser (static site, Vercel)
        |  POST /scan
        v
FastAPI backend (Vercel, Python) ----> Neon Postgres (scan history)
        |
        |-- checks/*  (SSL, WHOIS, headers, cookies, redirects, ...)
        |-- Google Safe Browsing, URLhaus, crt.sh
        '-- Random Forest model (joblib)
```

## The ML classifier

- **Data:** the web page phishing dataset by Hannousse & Yahiouche (2021): 11,430 URLs, balanced 50/50 between phishing and legitimate
- **Features:** 20 features computed from the URL string alone, with no page fetching, so a scan stays fast
- **Model:** Random Forest, evaluated on a held-out 30% test set
- **Results:** 89.1% accuracy, 88.9% precision, 89.3% recall, 89.1% F1
- **Output:** a phishing probability, turned into a score deduction and an explanation in the report

The model file lives at `backend/checks/phishing_rf_model.joblib`. It was trained with scikit-learn 1.8.0 and is loaded with the pinned 1.9.0, which prints a version-mismatch warning. Predictions behaved correctly in testing.

Because it only sees the URL, the classifier can be wrong, and legitimate sites with unusual-looking addresses sometimes get flagged. That's why it is one signal among many, not the verdict.

## Project structure

```
url-security-checker/
├── README.md
├── index.html            # frontend
├── style.css
├── script.js
├── vercel.json           # frontend project config
├── .vercelignore         # keeps backend/ out of the public site
├── .gitignore
└── backend/
    ├── main.py           # FastAPI app and endpoints
    ├── database.py       # Postgres (or local SQLite) scan history
    ├── requirements.txt
    ├── vercel.json       # backend project config
    ├── .vercelignore
    └── checks/
        ├── url_structure.py
        ├── https_ssl.py
        ├── phishing_indicators.py
        ├── domain_reputation.py
        ├── threat_intelligence.py
        ├── ml_classifier.py
        ├── security_posture.py
        ├── scoring.py
        └── phishing_rf_model.joblib
```

## API

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/scan` | Run a full scan on `{"url": "..."}`, save it, return the report |
| `GET` | `/history?limit=50` | Summary list of past scans, newest first |
| `GET` | `/report/{id}` | Full report for one past scan |
| `DELETE` | `/history/{id}` | Delete a past scan |

Example:

```bash
curl -X POST https://url-security-checker-api.vercel.app/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "github.com"}'
```

A trimmed response:

```json
{
  "id": 7,
  "submitted_url": "http://github.com",
  "final_url": "https://github.com/",
  "score": 87,
  "grade": "A",
  "classification": "Safe",
  "checks_performed": 26,
  "findings": [
    { "check": "HSTS Header", "passed": true, "impact": 0,
      "detail": "Strict-Transport-Security header is present." },
    { "check": "Header: Permissions-Policy", "passed": false, "impact": -5,
      "detail": "Permissions-Policy missing — no restriction on camera/mic/geolocation APIs." }
  ]
}
```

The interactive API docs (`/docs`) are available when you run the backend locally. They are switched off in production.

## Run it locally

You need Python 3.12 and two free API keys:
a [Google Safe Browsing](https://developers.google.com/safe-browsing) key and a [URLhaus](https://urlhaus.abuse.ch/) Auth-Key.

```bash
git clone https://github.com/Mkhan-dotcom/url-security-checker.git
cd url-security-checker

python -m venv venv
# Windows:      venv\Scripts\activate
# macOS/Linux:  source venv/bin/activate

pip install -r backend/requirements.txt
```

Create `backend/.env`:

```
GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
URLHAUS_AUTH_KEY=your_key_here
ENABLE_DOCS=true

# Optional. Without it, history is stored in a local SQLite file (scans.db).
# DATABASE_URL=postgresql://user:password@host/dbname
```

Start the backend:

```bash
cd backend
uvicorn main:app --reload --port 8000
```

Then open `http://127.0.0.1:8000/docs` to try the API.

To use the website against your local backend, set `API_BASE` in `script.js` to `http://127.0.0.1:8000` and open `index.html` directly in your browser. The backend's CORS list allows local `file://` pages and the production site. Set `API_BASE` back before you push.

## Deployment

- **Frontend:** a Vercel project built from the repo root. It's a static site; `.vercelignore` keeps `backend/` out of what gets published.
- **Backend:** a second Vercel project from the same repo with **Root Directory** set to `backend`, running on the Python runtime (`backend/vercel.json` routes all requests to `main.py`).
- **Environment variables** (backend project): `GOOGLE_SAFE_BROWSING_API_KEY`, `URLHAUS_AUTH_KEY`, `DATABASE_URL`, and `ENABLE_DOCS=false`.
- **Database:** a Neon Postgres database. Vercel functions have no persistent disk, so the local SQLite file can't be used in production.

After deploying the backend, put its address in `API_BASE` in `script.js`.

## How I checked that it works

- **Security headers** were compared against [securityheaders.com](https://securityheaders.com) on the same sites, with matching results.
- **Cookie flags** were compared against Chrome DevTools' Application tab.
- **Mixed content** findings were traced to the real HTML with `view-source:`.
- **The ML classifier** was tested on known-good and known-bad URLs, and evaluated on a held-out test set.

Testing also turned up real bugs that were fixed along the way: a failed check that was silently reported as "safe", a posture check missing from the score, and a mixed-content false positive on a malformed `tel:` link.

## Limitations

- The page checks are **static**: the tool reads the HTML and headers a site returns, but doesn't run JavaScript, so anything injected after page load isn't seen.
- If a site doesn't answer the main page request, the header, cookie and mixed-content checks are left out of the report instead of being marked as unverified.
- The ML model only sees the URL, not the page content.
- A clean result is not a guarantee that a site is safe, and a low score isn't proof that it's malicious. Treat it as a second opinion.
- Free-tier hosting means the first scan after a quiet period can take a few extra seconds.

## Roadmap

- A practical recommendation next to each failed finding ("what to do about it")
- Access control and rate limiting on the write endpoints
- Headless-browser analysis of page content (fake login forms, hidden iframes)
- Typosquatting and homograph (punycode) detection
- A shareable result card

## Responsible use

A scan sends real requests to the target site, including a small fixed set of requests for common sensitive paths such as `/.env` and `/.git/config`. Response bodies are not stored. Only scan sites you own or have permission to test.

## Credits

- Dataset: Hannousse, A., & Yahiouche, S. (2021). *Towards benchmark datasets for machine learning based website phishing detection: An experimental study.* Engineering Applications of Artificial Intelligence, 104, 104347.
- Particle-network background adapted from a CodeFronts canvas demo.
- Fonts: Space Grotesk and JetBrains Mono (Google Fonts).

Built by [Mkhan-dotcom](https://github.com/Mkhan-dotcom).