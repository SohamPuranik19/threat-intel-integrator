from typing import Dict, List
import time

class ThreatProcessor:
    def __init__(self):
        self.thresholds = {
            'benign': 20,
            'suspicious': 50,
            'malicious': 70
        }
    
    def classify_threat(self, score: float) -> str:
        """Classify threat based on score"""
        if score >= self.thresholds['malicious']:
            return 'Malicious'
        elif score >= self.thresholds['suspicious']:
            return 'Suspicious'
        else:
            return 'Benign'
    
    def calculate_consensus(self, results: List[Dict]) -> Dict:
        """Calculate consensus verdict from multiple sources"""
        scores = [r['score'] for r in results if 'error' not in r]
        avg_score = sum(scores) / len(scores) if scores else 0
        
        verdicts = [self.classify_threat(s) for s in scores]
        consensus = max(set(verdicts), key=verdicts.count)
        
        return {
            'average_score': round(avg_score, 2),
            'consensus': consensus,
            'individual_results': results
        }
    
    def enrich_data(self, indicator: str, analysis: Dict) -> Dict:
        """Add metadata and enrichment"""
        return {
            'indicator': indicator,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'threat_score': analysis['average_score'],
            'classification': analysis['consensus'],
            'sources': analysis['individual_results']
        }
