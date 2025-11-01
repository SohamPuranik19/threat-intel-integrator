import requests
import time
from typing import Dict, List

class ThreatIntelAPI:
    def __init__(self, abuse_key: str, vt_key: str, otx_key: str):
        self.abuse_key = abuse_key
        self.vt_key = vt_key
        self.otx_key = otx_key
        
    def check_abuseipdb(self, ip: str) -> Dict:
        """Query AbuseIPDB for IP reputation"""
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {'Key': self.abuse_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'source': 'AbuseIPDB',
                    'score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'country': data.get('countryCode', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'usage_type': data.get('usageType', 'Unknown')
                }
        except Exception as e:
            print(f"AbuseIPDB error: {e}")
        return {'source': 'AbuseIPDB', 'score': 0, 'error': True}
    
    def check_virustotal(self, ip: str) -> Dict:
        """Query VirusTotal for IP analysis"""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {'x-apikey': self.vt_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                score = ((malicious + suspicious) / total * 100) if total > 0 else 0
                return {
                    'source': 'VirusTotal',
                    'score': score,
                    'malicious_count': malicious,
                    'suspicious_count': suspicious
                }
        except Exception as e:
            print(f"VirusTotal error: {e}")
        return {'source': 'VirusTotal', 'score': 0, 'error': True}
    
    def check_alienvault_otx(self, ip: str) -> Dict:
        """Query AlienVault OTX for threat pulses"""
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {'X-OTX-API-KEY': self.otx_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                score = min(pulse_count * 10, 100)  # Scale to 0-100
                return {
                    'source': 'AlienVault OTX',
                    'score': score,
                    'pulse_count': pulse_count
                }
        except Exception as e:
            print(f"AlienVault OTX error: {e}")
        return {'source': 'AlienVault OTX', 'score': 0, 'error': True}
    
    def fetch_all_sources(self, indicator: str) -> List[Dict]:
        """Fetch data from all threat intelligence sources"""
        results = []
        results.append(self.check_abuseipdb(indicator))
        time.sleep(1)  # Rate limiting
        results.append(self.check_virustotal(indicator))
        time.sleep(1)
        results.append(self.check_alienvault_otx(indicator))
        return results
