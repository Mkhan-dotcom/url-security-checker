"""
main.py
FastAPI backend for the URL Security & Phishing Detection System.

Endpoints:
    POST /scan            -> run a full scan on a URL, save it, return the report
    GET  /history          -> list past scans (summary view)
    GET  /report/{scan_id} -> full detail for one past scan
    DELETE /history/{scan_id} -> delete a past scan

Run locally with:
    uvicorn main:app --reload
Then open http://127.0.0.1:8000/docs to test it interactively.
"""

import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel

from checks import scoring
from checks.url_structure import normalize_url, is_valid_domain_format
import database

logger = logging.getLogger(__name__)

app = FastAPI(
    title="URL Security & Phishing Detection System",
    description="Scans a URL for structural, SSL, phishing, and reputation risk signals.",
    version="1.0.0",
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds the same security headers this tool checks OTHER sites for —
    practicing what it inspects. Includes a Content-Security-Policy,
    X-Content-Type-Options, X-Frame-Options, and Referrer-Policy.
    """
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "script-src 'self'; "
            "connect-src 'self' https://url-security-checker-production.up.railway.app;"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


app.add_middleware(SecurityHeadersMiddleware)

# Restricted from the earlier wildcard ("*") to only the origins this app
# actually needs to serve:
#   - the real production frontend on Vercel
#   - "null", because opening index.html directly via file:// (as used
#     throughout local development/testing) sends Origin: null, not a
#     normal http:// origin — browsers do this specifically for local
#     files, so it must be explicitly allowed for local testing to work.
# A wildcard was fine for early development but is unnecessarily permissive
# for a deployed API with real API keys behind it.
ALLOWED_ORIGINS = [
    "https://url-security-checker.vercel.app",
    "null",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str


@app.on_event("startup")
def on_startup():
    database.init_db()


@app.post("/scan")
def scan_url(request: ScanRequest):
    """Runs the full detection pipeline on a URL, stores the result, and returns it."""
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=400, detail="URL must not be empty.")

    normalized = normalize_url(request.url)
    if not is_valid_domain_format(normalized):
        raise HTTPException(
            status_code=400,
            detail=f"'{request.url.strip()}' is not a valid domain (missing a valid TLD, e.g. .com, .org)."
        )

    try:
        report = scoring.run_full_scan(request.url.strip())
    except Exception:
        logger.exception("Scan failed for submitted URL")
        raise HTTPException(status_code=500, detail="Scan failed. Please try again later.")

    scan_id = database.save_scan(report)
    report["id"] = scan_id
    return report


@app.get("/history")
def get_history(limit: int = 50):
    """Returns a summary list of past scans, most recent first."""
    return database.get_history(limit=limit)


@app.get("/report/{scan_id}")
def get_report(scan_id: int):
    """Returns the full detailed report for one past scan."""
    result = database.get_scan_by_id(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan with id {scan_id} not found.")
    return result


@app.delete("/history/{scan_id}")
def delete_scan(scan_id: int):
    """Deletes a past scan record."""
    deleted = database.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Scan with id {scan_id} not found.")
    return {"deleted": True, "id": scan_id}


@app.get("/")
def root():
    return {"message": "URL Security & Phishing Detection System API is running. Visit /docs to test it."}