from typing import Optional
import os
import sys
import pathlib
import traceback
import re

# ensure repository root on sys.path
repo_root = pathlib.Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import time
import collections
from starlette.requests import Request
from starlette.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

import pandas as pd

try:
    from infosecwriteups.database_enhanced import EnhancedThreatDatabase
    from infosecwriteups.api_integrations import ThreatIntelAPI
except Exception:
    # fallback if running from different cwd
    for parent in pathlib.Path(__file__).resolve().parents:
        if (parent / 'infosecwriteups').is_dir():
            sys.path.insert(0, str(parent))
            break
    from infosecwriteups.database_enhanced import EnhancedThreatDatabase
    from infosecwriteups.api_integrations import ThreatIntelAPI

# Load environment variables
load_dotenv()

app = FastAPI(
    title="Advanced Threat Intelligence API",
    description="Multi-source threat intelligence with MITRE ATT&CK mapping and connection graphs",
    version="2.0.0"
)


# --- Basic API key middleware (optional, enabled if API_KEY set) -----------------
API_KEY = os.getenv('API_KEY', '')


class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # If no API key is configured, skip enforcement
        if not API_KEY:
            return await call_next(request)

        # Allow health and root endpoints without API key
        if request.url.path in ['/', '/health']:
            return await call_next(request)

        header_key = request.headers.get('x-api-key') or request.headers.get('X-API-KEY')
        if not header_key or header_key != API_KEY:
            return Response(status_code=401, content='{"detail":"Unauthorized - missing/invalid API key"}', media_type='application/json')

        return await call_next(request)


# --- Simple in-memory per-IP rate limiter -------------------------------------
RATE_LIMIT_REQUESTS = int(os.getenv('RATE_LIMIT_REQUESTS', '60'))
RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW_SECONDS', '60'))

# { ip: deque([timestamps]) }
_ip_buckets = collections.defaultdict(collections.deque)


class SimpleRateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Exempt root and health
        if request.url.path in ['/', '/health']:
            return await call_next(request)

        ip = request.client.host if request.client else 'unknown'
        now = time.time()
        dq = _ip_buckets[ip]

        # Remove timestamps older than window
        while dq and dq[0] <= now - RATE_LIMIT_WINDOW:
            dq.popleft()

        if len(dq) >= RATE_LIMIT_REQUESTS:
            return Response(status_code=429, content='{"detail":"Too Many Requests"}', media_type='application/json')

        dq.append(now)
        return await call_next(request)


# Register middlewares
app.add_middleware(SimpleRateLimitMiddleware)
app.add_middleware(APIKeyMiddleware)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "https://threat-intel-integrator.vercel.app",
        "https://threat-intel-integrator-git-feat-quick-verdict-soham-s-projects-237fa4b2.vercel.app",
        "https://*.vercel.app",  # Allow all Vercel preview deployments
        "*"  # Allow all origins for now (can restrict later)
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database and API client
db = EnhancedThreatDatabase()

# Get API keys from environment
api_client = ThreatIntelAPI(
    abuse_key=os.getenv('ABUSEIPDB_KEY', ''),
    vt_key=os.getenv('VIRUSTOTAL_KEY', ''),
    otx_key=os.getenv('OTX_KEY', ''),
    shodan_key=os.getenv('SHODAN_KEY', ''),
    urlscan_key=os.getenv('URLSCAN_KEY', ''),
    hybrid_key=os.getenv('HYBRID_ANALYSIS_KEY', '')
)


class AnalysisRequest(BaseModel):
    indicator: str
    indicator_type: Optional[str] = None  # ip, url, domain, hash


class SearchRequest(BaseModel):
    query: Optional[str] = ""
    classification: Optional[str] = None
    ioc_type: Optional[str] = None
    min_score: Optional[float] = None


def detect_indicator_type(indicator: str) -> str:
    """Automatically detect the type of indicator"""
    indicator = indicator.strip()
    
    # Check if it's an IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, indicator):
        return 'ip'
    
    # Check if it's a hash (MD5, SHA1, SHA256)
    if re.match(r'^[a-fA-F0-9]{32}$', indicator):  # MD5
        return 'hash'
    elif re.match(r'^[a-fA-F0-9]{40}$', indicator):  # SHA1
        return 'hash'
    elif re.match(r'^[a-fA-F0-9]{64}$', indicator):  # SHA256
        return 'hash'
    
    # Check if it's a URL
    if indicator.startswith('http://') or indicator.startswith('https://'):
        return 'url'
    
    # Check if it's a domain
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(domain_pattern, indicator):
        return 'domain'
    
    # Default to IP if uncertain
    return 'ip'


@app.get("/")
def root():
    """API root endpoint"""
    return {
        "service": "Advanced Threat Intelligence API",
        "version": "2.0.0",
        "features": [
            "Multi-source threat intelligence",
            "MITRE ATT&CK mapping",
            "IOC classification",
            "Connection graph generation",
            "Comprehensive scoring"
        ],
        "endpoints": {
            "analyze": "/analyze",
            "search": "/search",
            "indicator": "/indicator/{indicator}",
            "graph": "/graph/{indicator}",
            "mitre_stats": "/mitre/statistics",
            "indicators": "/indicators"
        }
    }


@app.post("/analyze")
async def analyze_indicator(request: AnalysisRequest, background_tasks: BackgroundTasks):
    """
    Perform comprehensive threat analysis on an indicator
    Queries all available sources and returns:
    - Multi-source scorecard
    - IOC classification with MITRE ATT&CK mapping
    - Related IOCs
    - Connection graph
    """
    try:
        indicator = request.indicator.strip()
        
        # Auto-detect indicator type if not provided
        if not request.indicator_type:
            indicator_type = detect_indicator_type(indicator)
        else:
            indicator_type = request.indicator_type
        
        # Check if we have cached analysis
        cached = db.get_indicator_analysis(indicator)
        if cached:
            return {
                "status": "success",
                "cached": True,
                "data": cached
            }
        
        # Perform comprehensive analysis
        analysis = api_client.comprehensive_analysis(indicator, indicator_type)
        
        # Store in database (in background to speed up response)
        background_tasks.add_task(db.insert_comprehensive_analysis, analysis)
        
        return {
            "status": "success",
            "cached": False,
            "data": analysis
        }
    
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/indicator/{indicator}")
async def get_indicator(indicator: str):
    """Get stored analysis for a specific indicator"""
    try:
        result = db.get_indicator_analysis(indicator)
        
        if not result:
            return {
                "status": "not_found",
                "message": "Indicator not in database. Use /analyze to analyze it."
            }
        
        return {
            "status": "success",
            "data": result
        }
    
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/search")
async def search_indicators(request: SearchRequest):
    """
    Search indicators with filters
    Supports filtering by:
    - Text query (matches indicator or tags)
    - Classification (Malicious, Suspicious, Benign)
    - IOC type (phishing, c2, malware, etc.)
    - Minimum threat score
    """
    try:
        results = db.search_indicators(
            query=request.query,
            classification=request.classification,
            ioc_type=request.ioc_type,
            min_score=request.min_score
        )
        
        return {
            "status": "success",
            "count": len(results),
            "results": results
        }
    
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/indicators")
async def get_all_indicators(limit: int = 100, offset: int = 0):
    """Get all indicators with pagination"""
    try:
        results = db.get_all_indicators(limit=limit, offset=offset)
        
        return {
            "status": "success",
            "count": len(results),
            "limit": limit,
            "offset": offset,
            "results": results
        }
    
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/graph/{indicator}")
async def get_connection_graph(indicator: str, depth: int = 2):
    """
    Get connection graph for an indicator
    Shows relationships to other IOCs, malware families, and campaigns
    """
    try:
        graph = db.get_connection_graph(indicator, depth=depth)
        
        return {
            "status": "success",
            "indicator": indicator,
            "depth": depth,
            "graph": graph
        }
    
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/mitre/statistics")
async def get_mitre_statistics():
    """
    Get statistics on observed MITRE ATT&CK techniques
    Shows which tactics and techniques are most prevalent
    """
    try:
        stats = db.get_mitre_statistics()
        
        return {
            "status": "success",
            "data": stats
        }
    
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/sources")
async def get_available_sources():
    """List available threat intelligence sources and their status"""
    sources = {
        "VirusTotal": {"enabled": bool(api_client.vt_key), "weight": 0.20},
        "AbuseIPDB": {"enabled": bool(api_client.abuse_key), "weight": 0.15},
        "AlienVault OTX": {"enabled": bool(api_client.otx_key), "weight": 0.15},
        "Shodan": {"enabled": bool(api_client.shodan_key), "weight": 0.10},
        "URLScan": {"enabled": bool(api_client.urlscan_key), "weight": 0.15},
        "Hybrid Analysis": {"enabled": bool(api_client.hybrid_key), "weight": 0.10},
        "URLhaus": {"enabled": True, "weight": 0.10},
        "ThreatFox": {"enabled": True, "weight": 0.05},
        "WHOIS": {"enabled": True, "weight": 0.05}
    }
    
    enabled_count = sum(1 for s in sources.values() if s["enabled"])
    
    return {
        "status": "success",
        "total_sources": len(sources),
        "enabled_sources": enabled_count,
        "sources": sources
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Threat Intelligence API",
        "version": "2.0.0"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
