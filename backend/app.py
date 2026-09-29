"""
FastAPI REST API Server for Protocol Archaeology Tool
Provides endpoints for PCAP parsing, narrative flow reconstruction,
pre-loaded scenarios, and serves the visual interactive dashboard.
"""

import os
import shutil
import tempfile
from typing import Optional, List
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from backend.engine.pcap_parser import parse_pcap_file
from backend.engine.story_engine import generate_story_and_analysis
from backend.engine.sample_generator import generate_all_samples, SAMPLES_DIR

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")

app = FastAPI(
    title="Protocol Archaeology Tool",
    description="Translates raw network packet captures (.pcap) into visual, step-by-step narrative stories.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure sample PCAPs exist at startup
generate_all_samples()

SAMPLE_METADATA = [
    {
        "id": "web_browsing_full.pcap",
        "title": "Full Web Browsing Session (DNS + TLS 1.3 + HTTPS)",
        "badge": "DNS + TLS + TCP",
        "badgeColor": "emerald",
        "description": "Demonstrates complete network workflow: ARP address discovery, DNS query for example.com, TCP 3-way handshake, TLS 1.3 Client & Server Hello cipher negotiation, Encrypted Application payload, and graceful FIN-ACK teardown.",
        "difficulty": "Comprehensive"
    },
    {
        "id": "cleartext_http_audit.pcap",
        "title": "Cleartext HTTP & Credential Leakage Audit",
        "badge": "Security Alert",
        "badgeColor": "rose",
        "description": "Demonstrates security risks of unencrypted traffic: HTTP POST login credentials transmitted in plaintext, session cookie assignment, and unencrypted account balance JSON payload.",
        "difficulty": "Security Forensics"
    },
    {
        "id": "tcp_reset_anomaly.pcap",
        "title": "TCP Connection Anomaly & Reset (RST)",
        "badge": "Anomaly / Port Closed",
        "badgeColor": "amber",
        "description": "Demonstrates network troubleshooting: Client attempts TCP connection to closed port 8080, receiving immediate TCP RST (Reset) packets from the remote host with retransmission attempt.",
        "difficulty": "Troubleshooting"
    }
]


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serves the interactive single-page React frontend dashboard."""
    index_path = os.path.join(TEMPLATES_DIR, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="Dashboard index.html not found.")
    with open(index_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/health")
async def health_check():
    """API health and status check."""
    return {"status": "ok", "service": "Protocol Archaeology Backend", "version": "1.0.0"}


@app.get("/api/samples")
async def list_samples():
    """Lists available pre-loaded sample captures with descriptions."""
    return {"samples": SAMPLE_METADATA}


@app.get("/api/samples/{filename}")
async def analyze_sample(filename: str):
    """Parses and analyzes a pre-loaded synthetic sample PCAP."""
    # Sanitize filename
    safe_name = os.path.basename(filename)
    filepath = os.path.join(SAMPLES_DIR, safe_name)
    
    if not os.path.exists(filepath):
        # Regenerate if missing
        generate_all_samples()
        if not os.path.exists(filepath):
            raise HTTPException(status_code=404, detail=f"Sample file {safe_name} not found.")

    try:
        packets = parse_pcap_file(filepath)
        story_data = generate_story_and_analysis(packets)
        
        return {
            "success": True,
            "filename": safe_name,
            "packets": packets,
            **story_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing sample capture: {str(e)}")


@app.post("/api/analyze")
async def upload_and_analyze_pcap(file: UploadFile = File(...)):
    """Uploads a user PCAP/PCAPNG file, parses layers, and generates narrative chapters."""
    if not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(
            status_code=400,
            detail="Invalid file format. Please upload a valid .pcap, .pcapng, or .cap file."
        )

    # Write to a temporary file
    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, file.filename)

    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        packets = parse_pcap_file(temp_path)
        story_data = generate_story_and_analysis(packets)

        return {
            "success": True,
            "filename": file.filename,
            "packets": packets,
            **story_data
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse and dissect PCAP: {str(e)}"
        )
    finally:
        # Clean up temporary file
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass
