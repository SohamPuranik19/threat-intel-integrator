#!/usr/bin/env python3
"""Bulk-import email indicators of compromise into the local SQLite database.

Usage examples:
    # Import emails listed one-per-line in emails.txt
    .venv/bin/python scripts/import_email_iocs.py --input emails.txt

    # Import from a CSV column named "email"
    .venv/bin/python scripts/import_email_iocs.py --input emails.csv --column email

The script skips duplicates (case-insensitive) and will report how many
indicators were inserted versus ignored. Defaults are tuned for phishing
indicators but can be overridden via CLI flags.
"""
import argparse
import csv
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Set

# Ensure repository root is on sys.path so the infosecwriteups package resolves even when
# the script is executed directly via `python scripts/import_email_iocs.py`.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from infosecwriteups.database import ThreatDatabase


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bulk import email IOCs into threat_intel.db")
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to text file or CSV containing email addresses (one per line or in a column)",
    )
    parser.add_argument(
        "--column",
        type=str,
        default=None,
        help="If provided, interpret input as CSV and read this column for email addresses",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("threat_intel.db"),
        help="Path to the SQLite database file (default: threat_intel.db)",
    )
    parser.add_argument(
        "--score",
        type=float,
        default=70.0,
        help="Threat score to assign to imported indicators (default: 70.0)",
    )
    parser.add_argument(
        "--classification",
        type=str,
        default="Malicious",
        help="Classification label for imported indicators (default: Malicious)",
    )
    parser.add_argument(
        "--category",
        type=str,
        default="phishing",
        help="Canonical category for imported indicators (default: phishing)",
    )
    parser.add_argument(
        "--source",
        type=str,
        default="BulkImport",
        help="Source label stored in the database (default: BulkImport)",
    )
    parser.add_argument(
        "--tags",
        type=str,
        default="email,phishing",
        help="Comma-separated extra tags to store alongside each indicator",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be inserted without modifying the database",
    )
    return parser.parse_args()


def read_emails_from_text(path: Path) -> List[str]:
    emails: List[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            candidate = line.strip()
            if not candidate or candidate.startswith("#"):
                continue
            emails.append(candidate)
    return emails


def read_emails_from_csv(path: Path, column: str) -> List[str]:
    emails: List[str] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if column not in reader.fieldnames:
            raise ValueError(f"Column '{column}' not found in CSV headers: {reader.fieldnames}")
        for row in reader:
            candidate = (row.get(column) or "").strip()
            if candidate:
                emails.append(candidate)
    return emails


def derive_confidence(score: float) -> str:
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def derive_severity(score: float) -> str:
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def load_existing_indicators(db: ThreatDatabase) -> Set[str]:
    existing = set()
    for row in db.get_all_threats():
        indicator = (row.get("indicator") or "").lower()
        if indicator:
            existing.add(indicator)
    return existing


def filter_valid_emails(candidates: Iterable[str]) -> List[str]:
    valid: List[str] = []
    for candidate in candidates:
        trimmed = candidate.strip()
        if "@" not in trimmed or " " in trimmed:
            continue
        valid.append(trimmed)
    return valid


def main() -> None:
    args = parse_args()

    if not args.input.exists():
        raise SystemExit(f"Input file '{args.input}' does not exist")

    if args.column:
        raw_emails = read_emails_from_csv(args.input, args.column)
    else:
        raw_emails = read_emails_from_text(args.input)

    emails = filter_valid_emails(raw_emails)
    if not emails:
        raise SystemExit("No valid email indicators found in the input")

    db = ThreatDatabase(db_name=str(args.db))
    existing = load_existing_indicators(db)

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    tags = [t.strip() for t in args.tags.split(",") if t.strip()]

    inserted = 0
    skipped = 0
    skipped_items: List[str] = []

    for email in emails:
        lower = email.lower()
        if lower in existing:
            skipped += 1
            skipped_items.append(email)
            continue

        record = {
            "indicator": email,
            "timestamp": timestamp,
            "threat_score": args.score,
            "classification": args.classification,
            "category": args.category,
            "confidence": derive_confidence(args.score),
            "severity": derive_severity(args.score),
            "source": args.source,
            "tags": ",".join(sorted(set(tags + ["email"]))),
            "threat_actor": "",
            "malware_family": "",
            "country": "Unknown",
            "isp": "Unknown",
            "usage_type": "Unknown",
            "sources": [],
        }

        if args.dry_run:
            print(f"DRY-RUN: would insert {email}")
        else:
            db.insert_threat(record)
            existing.add(lower)
            inserted += 1

    print(f"Processed {len(emails)} indicators: inserted {inserted}, skipped {skipped} duplicates.")
    if skipped_items:
        print("Skipped duplicates:")
        for item in skipped_items:
            print(f"  - {item}")


if __name__ == "__main__":
    main()
