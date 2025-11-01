#!/usr/bin/env python3
"""
Backfill script to map existing threat_indicators rows into new classification fields.
Priority: VirusTotal -> OTX -> AbuseIPDB

This script updates `category`, `confidence`, and `severity` for each row.
Run from repo root using the project's venv, e.g.:
.venv/bin/python scripts/backfill_mappings.py
"""
import sqlite3
from typing import Tuple

DB = 'threat_intel.db'


def map_from_row(row: dict) -> Tuple[str, str, str]:
    """Return (category, confidence, severity) derived from the row.

    Priority: VirusTotal, OTX, AbuseIPDB.
    Simple heuristics:
      - If indicator contains '@' => Phishing
      - If virustotal_score >= 50 => Malware
      - Else if otx_score >= 20 => Malicious Infrastructure
      - Else if abuseipdb_score >= 50 => Malware
      - Else if threat_score >= 70 => Malware
      - Else if threat_score >= 40 => Suspicious -> map to Malware/Suspicious but for category use 'Malware' or 'Scanning'
      - Else: Unknown/Benign

    Confidence/Severity derived from threat_score
    """
    indicator = (row.get('indicator') or '')
    vt = float(row.get('virustotal_score') or 0)
    otx = float(row.get('otx_score') or 0)
    abuse = float(row.get('abuseipdb_score') or 0)
    score = float(row.get('threat_score') or 0)

    # Category (use canonical lowercase taxonomy)
    # phishing, credential_harvest, typosquatting, scam, spam,
    # malware, ransomware, c2, botnet, exploit, privacy_leak, suspicious, unknown
    if '@' in indicator:
        category = 'phishing'
    elif vt >= 50:
        category = 'malware'
    elif otx >= 20:
        category = 'malicious_infrastructure'
    elif abuse >= 50:
        category = 'malware'
    elif score >= 70:
        category = 'malware'
    elif score >= 40:
        category = 'suspicious'
    elif score > 0:
        category = 'benign'
    else:
        category = 'unknown'

    # Confidence
    if score >= 75:
        confidence = 'High'
    elif score >= 40:
        confidence = 'Medium'
    else:
        confidence = 'Low'

    # Severity
    if score >= 90:
        severity = 'Critical'
    elif score >= 70:
        severity = 'High'
    elif score >= 40:
        severity = 'Medium'
    else:
        severity = 'Low'

    return category, confidence, severity


def row_to_dict(cursor, row):
    # Not used when using Row factory, but keep compatibility
    if cursor.description:
        return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}
    return dict(row)


def main():
    conn = sqlite3.connect(DB)
    # Use Row factory to make rows accessible as dict-like objects
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM threat_indicators')
    rows = cursor.fetchall()
    total = len(rows)
    if total == 0:
        print('No rows to backfill.')
        return

    updated = 0
    for r in rows:
        # r is a sqlite3.Row which behaves like a mapping
        row = dict(r)
        # compute mapping
        category, confidence, severity = map_from_row(row)

        # Only update if different
        old_cat = (row.get('category') or '')
        old_conf = (row.get('confidence') or '')
        old_sev = (row.get('severity') or '')

        if old_cat != category or old_conf != confidence or old_sev != severity:
            cursor.execute(
                'UPDATE threat_indicators SET category = ?, confidence = ?, severity = ? WHERE id = ?',
                (category, confidence, severity, row.get('id'))
            )
            updated += 1

    conn.commit()
    conn.close()

    print(f'Total rows: {total}. Updated rows: {updated}.')


if __name__ == '__main__':
    main()
