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
        score = analysis.get('average_score', 0)
        sources = analysis.get('individual_results', [])

        # derive confidence and severity from score
        if score >= 90:
            severity = 'Critical'
        elif score >= 70:
            severity = 'High'
        elif score >= 40:
            severity = 'Medium'
        else:
            severity = 'Low'

        if score >= 70:
            confidence = 'High'
        elif score >= 40:
            confidence = 'Medium'
        else:
            confidence = 'Low'

        # source list and tags
        src_names = [s.get('source', 'Unknown') for s in sources]
        source_field = ','.join([n for n in src_names if n])

        usage_type = ''
        country = 'Unknown'
        isp = 'Unknown'
        # Pull common enrichment fields from AbuseIPDB result when present
        for s in sources:
            if s.get('source') == 'AbuseIPDB':
                usage_type = s.get('usage_type', '')
                country = s.get('country', country)
                isp = s.get('isp', isp)

        # classification taxonomy (canonical values):
        # phishing, credential_harvest, typosquatting, scam, spam,
        # malware, ransomware, c2, botnet, exploit, privacy_leak, suspicious, unknown
        category = 'unknown'

        # Helper checks across sources
        def any_source_has(key, terms):
            for s in sources:
                v = s.get(key, '')
                if not v:
                    continue
                txt = str(v).lower()
                for t in terms:
                    if t in txt:
                        return True
            return False

        # Email indicators -> phishing is likely
        if '@' in indicator:
            category = 'phishing'
        else:
            # HTML/form based heuristics for credential harvesting
            # look for evidence of password inputs or common form strings in sources
            if any_source_has('html', ['input type="password"', 'name="password"', 'passwd', 'pwd']):
                category = 'credential_harvest'

            # Typosquatting heuristics: unicode or non-ascii chars or digit substitutions
            if category == 'unknown':
                try:
                    # if indicator contains non-ascii characters, treat as possible homoglyph
                    if any(ord(ch) > 127 for ch in indicator):
                        category = 'typosquatting'
                except Exception:
                    pass
                # quick digit-substitution heuristic: mix of letters and digits in a short domain
                alpha = any(c.isalpha() for c in indicator)
                digit = any(c.isdigit() for c in indicator)
                if category == 'unknown' and alpha and digit:
                    category = 'typosquatting'

            # Source/vendor signals
            if category == 'unknown':
                # high VT detections or named malware families
                if any_source_has('malware_family', ['ransom', 'trojan', 'c2', 'botnet', 'exploit']) or any_source_has('tags', ['ransom', 'malware', 'trojan', 'botnet', 'c2']):
                    # refine to ransomware if keyword present
                    if any_source_has('malware_family', ['ransom']) or any_source_has('tags', ['ransom']):
                        category = 'ransomware'
                    elif any_source_has('malware_family', ['botnet']) or any_source_has('tags', ['botnet']):
                        category = 'botnet'
                    elif any_source_has('malware_family', ['c2']) or any_source_has('tags', ['c2']):
                        category = 'c2'
                    else:
                        category = 'malware'

            # Spam/scam/privacy leak based on descriptive tags
            if category == 'unknown':
                if any_source_has('tags', ['scam', 'fraud', 'advance-fee']):
                    category = 'scam'
                elif any_source_has('usage_type', ['spam']) or any_source_has('tags', ['spam']):
                    category = 'spam'
                elif any_source_has('tags', ['data leak', 'exposed', 'credentials']) or any_source_has('summary', ['data leak', 'credentials exposed']):
                    category = 'privacy_leak'

            # If high score but no clear family, mark suspicious/malware
            if category == 'unknown':
                if score >= 70:
                    category = 'malware'
                elif score >= 40:
                    category = 'suspicious'
                else:
                    category = 'unknown'

        tags = []
        if usage_type:
            tags.append(usage_type)
        tags.extend([n for n in src_names if n])

        return {
            'indicator': indicator,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'threat_score': score,
            'classification': analysis.get('consensus', 'Unknown'),
            'sources': sources,
            'category': category,
            'confidence': confidence,
            'severity': severity,
            'source': source_field,
            'tags': ','.join(tags),
            'threat_actor': analysis.get('threat_actor', ''),
            'malware_family': analysis.get('malware_family', ''),
            'country': country,
            'isp': isp,
            'usage_type': usage_type
        }
