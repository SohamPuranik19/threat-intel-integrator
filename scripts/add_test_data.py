#!/usr/bin/env python3
"""
Add sample IP and domain test data to the threat database.
Useful for demonstrating the dashboard functionality.
"""

import sys
import pathlib
from datetime import datetime

repo_root = pathlib.Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from infosecwriteups.database import ThreatDatabase

# Sample test data: IPs and domains with realistic threat scores
TEST_DATA = [
    {
        'indicator': '192.168.1.100',
        'timestamp': datetime.utcnow().isoformat(),
        'threat_score': 5.0,
        'classification': 'Benign',
        'category': 'Internal Network',
        'confidence': 95,
        'severity': 'Low',
        'source': 'test_data',
        'country': 'Internal',
        'isp': 'Private Network',
        'abuseipdb_score': 0,
        'virustotal_score': 0,
        'otx_score': 0,
    },
    {
        'indicator': '10.0.0.1',
        'timestamp': datetime.utcnow().isoformat(),
        'threat_score': 2.0,
        'classification': 'Benign',
        'category': 'Internal Network',
        'confidence': 98,
        'severity': 'Low',
        'source': 'test_data',
        'country': 'Internal',
        'isp': 'Private Network',
        'abuseipdb_score': 0,
        'virustotal_score': 0,
        'otx_score': 0,
    },
    {
        'indicator': 'google.com',
        'timestamp': datetime.utcnow().isoformat(),
        'threat_score': 1.0,
        'classification': 'Benign',
        'category': 'Benign',
        'confidence': 100,
        'severity': 'Low',
        'source': 'test_data',
        'country': 'US',
        'abuseipdb_score': 0,
        'virustotal_score': 0,
        'otx_score': 0,
    },
    {
        'indicator': 'github.com',
        'timestamp': datetime.utcnow().isoformat(),
        'threat_score': 0.0,
        'classification': 'Benign',
        'category': 'Benign',
        'confidence': 100,
        'severity': 'Low',
        'source': 'test_data',
        'country': 'US',
        'abuseipdb_score': 0,
        'virustotal_score': 0,
        'otx_score': 0,
    },
    {
        'indicator': '1.1.1.1',
        'timestamp': datetime.utcnow().isoformat(),
        'threat_score': 3.0,
        'classification': 'Benign',
        'category': 'DNS',
        'confidence': 98,
        'severity': 'Low',
        'source': 'test_data',
        'country': 'AU',
        'isp': 'Cloudflare',
        'abuseipdb_score': 0,
        'virustotal_score': 0,
        'otx_score': 0,
    },
    {
        'indicator': '8.8.4.4',
        'timestamp': datetime.utcnow().isoformat(),
        'threat_score': 2.0,
        'classification': 'Benign',
        'category': 'DNS',
        'confidence': 99,
        'severity': 'Low',
        'source': 'test_data',
        'country': 'US',
        'isp': 'Google',
        'abuseipdb_score': 0,
        'virustotal_score': 0,
        'otx_score': 0,
    },
    {
        'indicator': 'malware-example.com',
        'timestamp': datetime.utcnow().isoformat(),
        'threat_score': 85.0,
        'classification': 'Malicious',
        'category': 'Malware',
        'confidence': 85,
        'severity': 'Critical',
        'source': 'test_data',
        'country': 'RU',
        'abuseipdb_score': 75,
        'virustotal_score': 82,
        'otx_score': 80,
    },
    {
        'indicator': 'phishing-site.net',
        'timestamp': datetime.utcnow().isoformat(),
        'threat_score': 78.0,
        'classification': 'Malicious',
        'category': 'Phishing',
        'confidence': 80,
        'severity': 'High',
        'source': 'test_data',
        'country': 'CN',
        'abuseipdb_score': 65,
        'virustotal_score': 70,
        'otx_score': 75,
    },
    {
        'indicator': 'c2-command.evil.com',
        'timestamp': datetime.utcnow().isoformat(),
        'threat_score': 95.0,
        'classification': 'Malicious',
        'category': 'CommandAndControl',
        'confidence': 92,
        'severity': 'Critical',
        'source': 'test_data',
        'country': 'KP',
        'abuseipdb_score': 90,
        'virustotal_score': 95,
        'otx_score': 92,
    },
    {
        'indicator': '203.0.113.45',
        'timestamp': datetime.utcnow().isoformat(),
        'threat_score': 72.0,
        'classification': 'Suspicious',
        'category': 'Botnet',
        'confidence': 70,
        'severity': 'High',
        'source': 'test_data',
        'country': 'VN',
        'isp': 'Unknown ISP',
        'abuseipdb_score': 60,
        'virustotal_score': 65,
        'otx_score': 70,
    },
    {
        'indicator': 'spam-server.suspicious.org',
        'timestamp': datetime.utcnow().isoformat(),
        'threat_score': 55.0,
        'classification': 'Suspicious',
        'category': 'Spam',
        'confidence': 60,
        'severity': 'Medium',
        'source': 'test_data',
        'country': 'IN',
        'abuseipdb_score': 45,
        'virustotal_score': 50,
        'otx_score': 55,
    },
    {
        'indicator': '198.51.100.89',
        'timestamp': datetime.utcnow().isoformat(),
        'threat_score': 42.0,
        'classification': 'Suspicious',
        'category': 'Fraud',
        'confidence': 55,
        'severity': 'Medium',
        'source': 'test_data',
        'country': 'BR',
        'isp': 'Test ISP',
        'abuseipdb_score': 35,
        'virustotal_score': 40,
        'otx_score': 42,
    },
]


def main():
    db = ThreatDatabase()
    inserted = 0
    skipped = 0

    for data in TEST_DATA:
        try:
            db.insert_threat(data)
            inserted += 1
            print(f"✓ Added: {data['indicator']:40} | {data['classification']:15} | Score: {data['threat_score']}")
        except Exception as e:
            skipped += 1
            print(f"✗ Skipped: {data['indicator']} — {e}")

    print(f"\n✓ Successfully added {inserted} test records")
    if skipped > 0:
        print(f"⚠ Skipped {skipped} records (may already exist)")


if __name__ == '__main__':
    main()
