from typing import Optional
import os
import sys
import pathlib
import traceback

# ensure repository root on sys.path
repo_root = pathlib.Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

import pandas as pd

try:
    from infosecwriteups.database import ThreatDatabase
    from infosecwriteups.api_integrations import ThreatIntelAPI
    from infosecwriteups.processor import ThreatProcessor
except Exception:
    # fallback if running from different cwd
    for parent in pathlib.Path(__file__).resolve().parents:
        if (parent / 'infosecwriteups').is_dir():
            sys.path.insert(0, str(parent))
            break
    from infosecwriteups.database import ThreatDatabase
    from infosecwriteups.api_integrations import ThreatIntelAPI
    from infosecwriteups.processor import ThreatProcessor

app = FastAPI(title="Threat Intel API")

# Add CORS middleware to allow frontend to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LookupRequest(BaseModel):
    indicator: str
    analyze: Optional[bool] = True


def infer_indicator_type(txt: str):
    if not txt:
        return None
    s = txt.strip()
    try:
        import ipaddress as _ip
        _ip.ip_address(s)
        return 'IP'
    except Exception:
        pass
    email_re = __import__('re').compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    if email_re.match(s):
        return 'Email'
    dom_re = __import__('re').compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
    if dom_re.match(s.lower()):
        return 'Domain'
    return None


@app.get('/search')
def search(q: Optional[str] = '', type: Optional[str] = 'Any', limit: int = 50):
    """Search the local DB for indicators or free text. Returns matches and (if exact) a quick verdict."""
    try:
        db = ThreatDatabase()
        data = db.get_all_threats()
        if not data:
            return {'count': 0, 'items': []}
        df = pd.DataFrame(data)

        # If no query, return all records
        if not q or not q.strip():
            results = df.head(limit)
            items = []
            for _, r in results.iterrows():
                rec = r.to_dict()
                for k, v in rec.items():
                    try:
                        if hasattr(v, 'item'):
                            rec[k] = v.item()
                    except Exception:
                        pass
                items.append(rec)
            return {'count': len(items), 'items': items}

        q_raw = q.strip()
        q_low = q_raw.lower()
        inferred = infer_indicator_type(q_raw) if type == 'Any' else type

        # exact match (most recent)
        items = []
        exact = df[df['indicator'].astype(str).str.lower().str.strip() == q_low]
        if not exact.empty:
            row = exact.sort_values('timestamp', ascending=False).iloc[0]
            rec = row.to_dict()
            # convert numpy types to native Python
            for k, v in rec.items():
                try:
                    if hasattr(v, 'item'):
                        rec[k] = v.item()
                except Exception:
                    pass
            items.append(rec)

        # broader substring search
        mask = df['indicator'].astype(str).str.lower().str.contains(q_low, na=False)
        for c in ['country', 'isp', 'classification', 'category']:
            if c in df.columns:
                mask = mask | df[c].astype(str).str.lower().str.contains(q_low, na=False)
        results = df[mask].head(limit)
        for _, r in results.iterrows():
            rec = r.to_dict()
            for k, v in rec.items():
                try:
                    if hasattr(v, 'item'):
                        rec[k] = v.item()
                except Exception:
                    pass
            items.append(rec)

        return {'count': len(items), 'items': items}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/lookup')
def lookup(req: LookupRequest):
    """Lookup an indicator using external APIs if keys are present, otherwise a heuristic fallback. Does not save to DB.

    Request: {"indicator": "a@b.com", "analyze": true}
    """
    ind = req.indicator
    if not ind:
        raise HTTPException(status_code=400, detail='indicator required')

    try:
        load_dotenv()
        has_api_keys = any([os.getenv('VIRUSTOTAL_KEY'), os.getenv('OTX_KEY'), os.getenv('ABUSEIPDB_KEY')])
        processor = ThreatProcessor()

        if req.analyze and has_api_keys:
            api = ThreatIntelAPI(
                abuse_key=os.getenv('ABUSEIPDB_KEY'),
                vt_key=os.getenv('VIRUSTOTAL_KEY'),
                otx_key=os.getenv('OTX_KEY')
            )
            results = api.fetch_all_sources(ind)
            analysis = processor.calculate_consensus(results)
            enriched = processor.enrich_data(ind, analysis)
            enriched['saved'] = False
            return enriched

        # Heuristic fallback
        # Simple scoring logic (mirrors dashboard heuristics)
        try:
            import socket
            domain = ind.split('@')[1] if '@' in ind else None
            username = ind.split('@')[0] if '@' in ind else ind
            resolved = False
            mx_found = False
            domain_ip = None
            if domain:
                try:
                    domain_ip = socket.gethostbyname(domain)
                    resolved = True
                except Exception:
                    resolved = False
                try:
                    import importlib
                    if importlib.util.find_spec('dns') is not None:
                        dns_resolver = importlib.import_module('dns.resolver')
                        answers = dns_resolver.resolve(domain, 'MX', lifetime=5)
                        mx_found = len(answers) > 0
                except Exception:
                    mx_found = False

            disposable = {'mailinator.com','10minutemail.com','sharklasers.com','guerrillamail.com','tempmail.com','dispostable.com','yopmail.com'}
            is_disposable = domain.lower() in disposable if domain else False

            suspicious_tokens = ['spam','phish','scam','malware','promo','noreply','admin','support']
            token_score = 0
            for t in suspicious_tokens:
                if t in username.lower():
                    token_score += 25

            score = 10
            if resolved:
                score += 30
            if mx_found:
                score += 20
            score += token_score
            if is_disposable:
                score = max(0, score - 60)
            score = max(0, min(100, score))

            if score >= 70:
                classification = 'Malicious'
            elif score >= 40:
                classification = 'Suspicious'
            else:
                classification = 'Benign'

            return {
                'indicator': ind,
                'domain_resolves': resolved,
                'domain_ip': domain_ip,
                'mx': mx_found,
                'is_disposable': is_disposable,
                'heuristic_score': score,
                'classification': classification,
                'saved': False
            }
        except Exception as e:
            return {'error': str(e)}

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
