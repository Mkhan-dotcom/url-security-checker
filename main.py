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

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from checks import scoring
import database

app = FastAPI(
    title="URL Security & Phishing Detection System",
    description="Scans a URL for structural, SSL, phishing, and reputation risk signals.",
    version="1.0.0",
)

# Allows a browser-based frontend (running on a different port/domain) to call this API.
# Restrict allow_origins to your actual frontend URL once deployed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

    try:
        report = scoring.run_full_scan(request.url.strip())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")

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