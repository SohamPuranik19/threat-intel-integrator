import os
from dotenv import load_dotenv
from typing import List
from .api_integrations import ThreatIntelAPI
from .processor import ThreatProcessor
from .database import ThreatDatabase

load_dotenv()

def analyze_indicators(indicators: List[str]):
    """Main analysis function"""
    api = ThreatIntelAPI(
        abuse_key=os.getenv('ABUSEIPDB_KEY'),
        vt_key=os.getenv('VIRUSTOTAL_KEY'),
        otx_key=os.getenv('OTX_KEY')
    )
    
    processor = ThreatProcessor()
    db = ThreatDatabase()
    
    for indicator in indicators:
        print(f"Analyzing {indicator}...")
        results = api.fetch_all_sources(indicator)
        analysis = processor.calculate_consensus(results)
        enriched = processor.enrich_data(indicator, analysis)
        db.insert_threat(enriched)
        print(f"  Classification: {enriched['classification']}")
        print(f"  Threat Score: {enriched['threat_score']}")

if __name__ == "__main__":
    test_ips = ["8.8.8.8", "1.2.3.4"]  # Add test IPs
    analyze_indicators(test_ips)
