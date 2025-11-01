#!/usr/bin/env python3
"""
Bulk import indicators (IP, domain, email) into threat_intel.db.

Features:
- Reads a newline-delimited text file or CSV (column: indicator)
- Optional: live analyze IPs via AbuseIPDB/VirusTotal/OTX using .env keys
- Heuristics for emails and domains when skipping live analysis

Usage examples:
  .venv/bin/python scripts/bulk_import_iocs.py --file samples/sample_iocs.txt --assume-email-phishing
  .venv/bin/python scripts/bulk_import_iocs.py --file my.csv --format csv --analyze-ips

"""
import argparse
import csv
import os
import re
from typing import Iterable, List, Dict

from dotenv import load_dotenv

try:
    # absolute import when executed as script from repo root
    from infosecwriteups.database import ThreatDatabase
    from infosecwriteups.processor import ThreatProcessor
    from infosecwriteups.api_integrations import ThreatIntelAPI
except Exception:
    # fallback for different cwd
    import sys, pathlib
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from infosecwriteups.database import ThreatDatabase
    from infosecwriteups.processor import ThreatProcessor
    from infosecwriteups.api_integrations import ThreatIntelAPI


def is_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def is_email(value: str) -> bool:
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value or "") is not None


def is_domain(value: str) -> bool:
    if not value or value.startswith(('http://', 'https://')):
        return False
    return re.match(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$", value.lower()) is not None


def read_indicators(path: str, fmt: str) -> Iterable[str]:
    if fmt == 'csv':
        with open(path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            field = None
            # choose likely column name
            for cand in ('indicator', 'ioc', 'value'):
                if cand in reader.fieldnames:
                    field = cand
                    break
            if not field:
                raise ValueError("CSV must have a column named 'indicator' (or 'ioc'/'value').")
            for row in reader:
                v = (row.get(field) or '').strip()
                if v:
                    yield v
    else:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                v = line.strip()
                if v and not v.startswith('#'):
                    yield v


def heuristic_results(indicator: str, assume_email_phishing: bool, default_score: float) -> List[Dict]:
    """Return a list of pseudo-source results for processor.calculate_consensus.
    We keep this simple and transparent.
    """
    src = []
    if is_email(indicator):
        score = 80.0 if assume_email_phishing else default_score
        tags = 'email,phishing' if assume_email_phishing else 'email'
        src.append({'source': 'Heuristic', 'score': score, 'tags': tags})
    elif is_domain(indicator):
        low = indicator.lower()
        suspicious_terms = ['login', 'verify', 'secure', 'update', 'account', 'wallet', 'bank', 'paypal']
        has_term = any(t in low for t in suspicious_terms)
        score = 60.0 if has_term else default_score
        tags = 'domain,phishing' if has_term else 'domain'
        src.append({'source': 'Heuristic', 'score': score, 'tags': tags})
    else:
        # Unknown type → use default
        src.append({'source': 'Heuristic', 'score': default_score, 'tags': 'generic'})
    return src


def main():
    p = argparse.ArgumentParser(description='Bulk import indicators into threat_intel.db')
    p.add_argument('--file', required=True, help='Path to IOC file (txt or csv)')
    p.add_argument('--format', choices=['txt', 'csv'], help='Input format; auto from extension if omitted')
    p.add_argument('--analyze-ips', action='store_true', help='Call live APIs for IPs using .env keys')
    p.add_argument('--assume-email-phishing', action='store_true', help='Treat emails as phishing with higher score')
    p.add_argument('--default-score', type=float, default=40.0, help='Default heuristic score for non-analyzed entries')
    args = p.parse_args()

    path = args.file
    if not os.path.exists(path):
        raise SystemExit(f"File not found: {path}")

    fmt = args.format
    if not fmt:
        fmt = 'csv' if path.lower().endswith('.csv') else 'txt'

    load_dotenv()

    db = ThreatDatabase()
    processor = ThreatProcessor()

    api = None
    if args.analyze_ips:
        api = ThreatIntelAPI(
            abuse_key=os.getenv('ABUSEIPDB_KEY'),
            vt_key=os.getenv('VIRUSTOTAL_KEY'),
            otx_key=os.getenv('OTX_KEY')
        )

    total = 0
    inserted = 0
    for indicator in read_indicators(path, fmt):
        total += 1
        indicator = indicator.strip()
        try:
            if api and is_ip(indicator):
                results = api.fetch_all_sources(indicator)
            else:
                results = heuristic_results(indicator, args.assume_email_phishing, args.default_score)

            analysis = processor.calculate_consensus(results)
            enriched = processor.enrich_data(indicator, analysis)
            db.insert_threat(enriched)
            inserted += 1
            print(f"Imported: {indicator} -> class={enriched.get('classification')} score={enriched.get('threat_score')}")
        except Exception as e:
            print(f"Failed: {indicator}: {e}")

    print(f"Done. Read {total}, inserted {inserted}.")


if __name__ == '__main__':
    main()
