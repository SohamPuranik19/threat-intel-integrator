#!/usr/bin/env python3
"""Backfill script to normalize the `category` column in the threat_intel.db database.

This script reads all rows from the `threat_indicators` table, maps free-form
category values to a canonical set, and updates the DB in-place.

Usage:
  .venv/bin/python scripts/backfill_categories.py

It is safe to re-run; only rows whose normalized category differs from the
existing value will be updated.
"""
import sqlite3
import argparse
from typing import List

# Canonical categories (should mirror the dashboard choices)
CATEGORY_CHOICES = [
    'Phishing', 'Malware', 'Ransomware', 'CredentialLeak', 'CommandAndControl', 'Botnet',
    'Spam', 'Fraud', 'C2', 'DataExfiltration', 'Reconnaissance', 'UnauthorizedAccess',
    'PolicyViolation', 'Suspicious', 'Benign'
]


def normalize_category(value: str) -> str:
    if not value:
        return 'Suspicious'
    v = str(value).strip()
    lv = v.lower()
    # Map common placeholder tokens to Suspicious
    if lv in ('', 'unknown', 'none', 'n/a', 'na'):
        return 'Suspicious'
    for c in CATEGORY_CHOICES:
        if lv == c.lower():
            return c
    if 'phish' in lv:
        return 'Phishing'
    if 'ransom' in lv:
        return 'Ransomware'
    if 'malware' in lv or 'trojan' in lv or 'virus' in lv:
        return 'Malware'
    if 'credential' in lv or 'leak' in lv or 'password' in lv:
        return 'CredentialLeak'
    if 'c2' in lv or 'command' in lv or 'control' in lv:
        return 'CommandAndControl'
    if 'bot' in lv:
        return 'Botnet'
    if 'spam' in lv:
        return 'Spam'
    if 'fraud' in lv:
        return 'Fraud'
    if 'exfil' in lv or 'data' in lv:
        return 'DataExfiltration'
    if 'recon' in lv or 'scan' in lv or 'reconnaissance' in lv:
        return 'Reconnaissance'
    if 'unauthor' in lv or 'unauth' in lv or 'unauthorized' in lv:
        return 'UnauthorizedAccess'
    if 'policy' in lv:
        return 'PolicyViolation'
    if 'suspicious' in lv:
        return 'Suspicious'
    if 'benign' in lv or 'false' in lv:
        return 'Benign'
    return v


def backfill(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute('SELECT id, category FROM threat_indicators')
    rows = cur.fetchall()
    updated = 0
    total = len(rows)
    for rid, cat in rows:
        new_cat = normalize_category(cat)
        # Only update when different
        if (cat or '').strip() != (new_cat or '').strip():
            cur.execute('UPDATE threat_indicators SET category = ? WHERE id = ?', (new_cat, rid))
            updated += 1

    conn.commit()
    conn.close()

    print(f'Backfill complete: {updated} rows updated out of {total} total')


def main(argv: List[str] = None):
    p = argparse.ArgumentParser(description='Backfill threat categories to canonical set')
    p.add_argument('--db', default='threat_intel.db', help='Path to SQLite DB file')
    args = p.parse_args(argv)
    backfill(args.db)


if __name__ == '__main__':
    main()
