import requests
import time
import json
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime

class ThreatIntelAPI:
    def __init__(self, abuse_key: str = "", vt_key: str = "", otx_key: str = "", 
                 shodan_key: str = "", urlscan_key: str = "", hybrid_key: str = ""):
        self.abuse_key = abuse_key
        self.vt_key = vt_key
        self.otx_key = otx_key
        self.shodan_key = shodan_key
        self.urlscan_key = urlscan_key
        self.hybrid_key = hybrid_key
        
        # MITRE ATT&CK mapping for threat classification
        self.mitre_mapping = {
            'phishing': {
                'tactic': 'Initial Access',
                'technique': 'T1566 - Phishing',
                'sub_techniques': ['T1566.001 - Spearphishing Attachment', 'T1566.002 - Spearphishing Link']
            },
            'c2': {
                'tactic': 'Command and Control',
                'technique': 'T1071 - Application Layer Protocol',
                'sub_techniques': ['T1071.001 - Web Protocols', 'T1071.004 - DNS']
            },
            'malware': {
                'tactic': 'Execution',
                'technique': 'T1204 - User Execution',
                'sub_techniques': ['T1204.001 - Malicious Link', 'T1204.002 - Malicious File']
            },
            'ransomware': {
                'tactic': 'Impact',
                'technique': 'T1486 - Data Encrypted for Impact',
                'sub_techniques': []
            },
            'data_exfiltration': {
                'tactic': 'Exfiltration',
                'technique': 'T1041 - Exfiltration Over C2 Channel',
                'sub_techniques': []
            },
            'trojan': {
                'tactic': 'Persistence',
                'technique': 'T1547 - Boot or Logon Autostart Execution',
                'sub_techniques': []
            },
            'scanner': {
                'tactic': 'Discovery',
                'technique': 'T1046 - Network Service Discovery',
                'sub_techniques': []
            },
            'exploit': {
                'tactic': 'Execution',
                'technique': 'T1203 - Exploitation for Client Execution',
                'sub_techniques': []
            }
        }
        
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
    
    def check_shodan(self, ip: str) -> Dict:
        """Query Shodan for host information and vulnerabilities"""
        if not self.shodan_key:
            return {'source': 'Shodan', 'score': 0, 'error': True, 'message': 'No API key'}
        
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {'key': self.shodan_key}
        
        try:
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulns = data.get('vulns', [])
                ports = data.get('ports', [])
                tags = data.get('tags', [])
                
                # Score based on vulnerabilities and suspicious tags
                vuln_score = min(len(vulns) * 15, 60)
                tag_score = 20 if any(tag in ['malware', 'tor', 'proxy', 'vpn'] for tag in tags) else 0
                port_score = 20 if any(port in [22, 23, 3389, 445] for port in ports) else 0
                
                total_score = min(vuln_score + tag_score + port_score, 100)
                
                return {
                    'source': 'Shodan',
                    'score': total_score,
                    'vulnerabilities': len(vulns),
                    'open_ports': len(ports),
                    'tags': tags,
                    'organization': data.get('org', 'Unknown'),
                    'services': [s.get('product', 'Unknown') for s in data.get('data', [])[:5]]
                }
        except Exception as e:
            print(f"Shodan error: {e}")
        return {'source': 'Shodan', 'score': 0, 'error': True}
    
    def check_urlscan(self, url: str) -> Dict:
        """Submit URL to URLScan.io and retrieve scan results"""
        if not self.urlscan_key:
            return {'source': 'URLScan', 'score': 0, 'error': True, 'message': 'No API key'}
        
        # Submit URL for scanning
        submit_url = "https://urlscan.io/api/v1/scan/"
        headers = {'API-Key': self.urlscan_key, 'Content-Type': 'application/json'}
        data = {'url': url, 'visibility': 'unlisted'}
        
        try:
            response = requests.post(submit_url, headers=headers, json=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                uuid = result.get('uuid')
                
                # Wait for scan to complete
                time.sleep(5)
                
                # Retrieve results
                result_url = f"https://urlscan.io/api/v1/result/{uuid}/"
                result_response = requests.get(result_url, timeout=10)
                
                if result_response.status_code == 200:
                    scan_data = result_response.json()
                    verdicts = scan_data.get('verdicts', {})
                    
                    malicious = verdicts.get('overall', {}).get('malicious', False)
                    score = verdicts.get('overall', {}).get('score', 0) * 100
                    categories = verdicts.get('overall', {}).get('categories', [])
                    
                    return {
                        'source': 'URLScan',
                        'score': score if malicious else min(score, 50),
                        'malicious': malicious,
                        'categories': categories,
                        'scan_url': f"https://urlscan.io/result/{uuid}/"
                    }
        except Exception as e:
            print(f"URLScan error: {e}")
        return {'source': 'URLScan', 'score': 0, 'error': True}
    
    def check_hybrid_analysis(self, file_hash: str) -> Dict:
        """Query Hybrid Analysis for file/hash reputation"""
        if not self.hybrid_key:
            return {'source': 'Hybrid Analysis', 'score': 0, 'error': True, 'message': 'No API key'}
        
        url = f"https://www.hybrid-analysis.com/api/v2/search/hash"
        headers = {
            'api-key': self.hybrid_key,
            'User-Agent': 'Falcon Sandbox',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {'hash': file_hash}
        
        try:
            response = requests.post(url, headers=headers, data=data, timeout=15)
            if response.status_code == 200:
                results = response.json()
                if results:
                    result = results[0]
                    threat_score = result.get('threat_score', 0)
                    verdict = result.get('verdict', 'unknown')
                    av_detect = result.get('av_detect', 0)
                    
                    # Map verdict to score
                    verdict_scores = {
                        'malicious': 100,
                        'suspicious': 70,
                        'no specific threat': 30,
                        'whitelisted': 0
                    }
                    
                    score = verdict_scores.get(verdict.lower(), threat_score)
                    
                    return {
                        'source': 'Hybrid Analysis',
                        'score': score,
                        'verdict': verdict,
                        'av_detect': av_detect,
                        'threat_score': threat_score,
                        'malware_family': result.get('malware_family', 'Unknown')
                    }
        except Exception as e:
            print(f"Hybrid Analysis error: {e}")
        return {'source': 'Hybrid Analysis', 'score': 0, 'error': True}
    
    def check_urlhaus(self, indicator: str) -> Dict:
        """Query URLhaus for malicious URLs and malware distribution"""
        url = "https://urlhaus-api.abuse.ch/v1/url/"
        data = {'url': indicator}
        
        try:
            response = requests.post(url, data=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                query_status = result.get('query_status')
                
                if query_status == 'ok':
                    threat = result.get('threat', 'Unknown')
                    tags = result.get('tags', [])
                    malware_family = result.get('payloads', [{}])[0].get('signature', 'Unknown')
                    
                    # Score based on threat type
                    threat_scores = {
                        'malware_download': 100,
                        'phishing': 90,
                        'c2': 95
                    }
                    
                    score = threat_scores.get(threat.lower(), 80)
                    
                    return {
                        'source': 'URLhaus',
                        'score': score,
                        'threat': threat,
                        'tags': tags,
                        'malware_family': malware_family,
                        'online': result.get('url_status') == 'online'
                    }
                else:
                    # Not in database = likely clean
                    return {
                        'source': 'URLhaus',
                        'score': 0,
                        'status': 'not_found'
                    }
        except Exception as e:
            print(f"URLhaus error: {e}")
        return {'source': 'URLhaus', 'score': 0, 'error': True}
    
    def check_abusech_threatfox(self, ioc: str) -> Dict:
        """Query abuse.ch ThreatFox for IOC information"""
        url = "https://threatfox-api.abuse.ch/api/v1/"
        data = {
            'query': 'search_ioc',
            'search_term': ioc
        }
        
        try:
            response = requests.post(url, json=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                query_status = result.get('query_status')
                
                if query_status == 'ok':
                    entries = result.get('data', [])
                    if entries:
                        entry = entries[0]
                        malware = entry.get('malware', 'Unknown')
                        confidence = entry.get('confidence_level', 50)
                        tags = entry.get('tags', [])
                        
                        return {
                            'source': 'ThreatFox',
                            'score': confidence,
                            'malware_family': malware,
                            'tags': tags,
                            'threat_type': entry.get('threat_type', 'Unknown')
                        }
                else:
                    return {
                        'source': 'ThreatFox',
                        'score': 0,
                        'status': 'not_found'
                    }
        except Exception as e:
            print(f"ThreatFox error: {e}")
        return {'source': 'ThreatFox', 'score': 0, 'error': True}
    
    def check_whois(self, domain: str) -> Dict:
        """Query WHOIS information for domain reputation"""
        try:
            import whois
            w = whois.whois(domain)
            
            # Analyze WHOIS data for suspicious indicators
            score = 0
            indicators = []
            
            # Check domain age
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                age_days = (datetime.now() - creation_date).days
                if age_days < 30:
                    score += 40
                    indicators.append('Domain less than 30 days old')
                elif age_days < 90:
                    score += 20
                    indicators.append('Domain less than 90 days old')
            
            # Check registrar
            if w.registrar and any(term in str(w.registrar).lower() for term in ['privacy', 'guard', 'protect']):
                score += 15
                indicators.append('Privacy protection enabled')
            
            # Check for missing information
            if not w.emails:
                score += 10
                indicators.append('No contact email')
            
            return {
                'source': 'WHOIS',
                'score': min(score, 100),
                'creation_date': str(w.creation_date) if w.creation_date else 'Unknown',
                'registrar': w.registrar or 'Unknown',
                'country': w.country or 'Unknown',
                'indicators': indicators
            }
        except Exception as e:
            # If whois module not available or query fails, return basic info
            return {
                'source': 'WHOIS',
                'score': 0,
                'error': True,
                'message': 'WHOIS lookup failed or python-whois not installed'
            }
    
    def fetch_all_sources(self, indicator: str, indicator_type: str = 'ip') -> List[Dict]:
        """Fetch data from all threat intelligence sources based on indicator type"""
        results = []
        
        if indicator_type == 'ip':
            # IP-specific sources
            if self.abuse_key:
                results.append(self.check_abuseipdb(indicator))
                time.sleep(1)
            if self.vt_key:
                results.append(self.check_virustotal(indicator))
                time.sleep(1)
            if self.otx_key:
                results.append(self.check_alienvault_otx(indicator))
                time.sleep(1)
            if self.shodan_key:
                results.append(self.check_shodan(indicator))
                time.sleep(1)
        
        elif indicator_type == 'url' or indicator_type == 'domain':
            # URL/Domain-specific sources
            if self.vt_key:
                results.append(self.check_virustotal(indicator))
                time.sleep(1)
            if self.urlscan_key:
                results.append(self.check_urlscan(indicator))
                time.sleep(2)
            results.append(self.check_urlhaus(indicator))
            time.sleep(1)
            results.append(self.check_abusech_threatfox(indicator))
            time.sleep(1)
            if indicator_type == 'domain':
                results.append(self.check_whois(indicator))
                time.sleep(1)
        
        elif indicator_type == 'hash':
            # File hash-specific sources
            if self.vt_key:
                results.append(self.check_virustotal(indicator))
                time.sleep(1)
            if self.hybrid_key:
                results.append(self.check_hybrid_analysis(indicator))
                time.sleep(1)
            results.append(self.check_abusech_threatfox(indicator))
            time.sleep(1)
        
        return results
    
    def calculate_composite_score(self, source_results: List[Dict]) -> Dict:
        """
        Calculate weighted composite score from multiple sources
        Returns comprehensive scorecard
        """
        # Source weights (based on reliability and coverage)
        weights = {
            'VirusTotal': 0.20,
            'AbuseIPDB': 0.15,
            'AlienVault OTX': 0.15,
            'Shodan': 0.10,
            'URLScan': 0.15,
            'Hybrid Analysis': 0.10,
            'URLhaus': 0.10,
            'ThreatFox': 0.05,
            'WHOIS': 0.05
        }
        
        total_weight = 0
        weighted_score = 0
        source_scores = {}
        
        for result in source_results:
            source = result.get('source')
            score = result.get('score', 0)
            error = result.get('error', False)
            
            if not error and source in weights:
                weight = weights[source]
                weighted_score += score * weight
                total_weight += weight
                source_scores[source] = score
        
        # Normalize score
        final_score = (weighted_score / total_weight) if total_weight > 0 else 0
        
        # Determine classification
        if final_score >= 70:
            classification = 'Malicious'
            severity = 'Critical' if final_score >= 85 else 'High'
        elif final_score >= 40:
            classification = 'Suspicious'
            severity = 'Medium'
        else:
            classification = 'Benign'
            severity = 'Low'
        
        return {
            'composite_score': round(final_score, 2),
            'classification': classification,
            'severity': severity,
            'source_scores': source_scores,
            'sources_checked': len(source_scores),
            'total_sources': len([r for r in source_results if not r.get('error')])
        }
    
    def classify_ioc_type(self, source_results: List[Dict], indicator: str) -> Dict:
        """
        Classify IOC type (phishing, C2, malware, etc.) based on multi-source analysis
        and map to MITRE ATT&CK framework
        """
        # Collect all indicators from sources
        tags = []
        threats = []
        malware_families = []
        categories = []
        
        for result in source_results:
            tags.extend(result.get('tags', []))
            if 'threat' in result:
                threats.append(result['threat'])
            if 'malware_family' in result:
                malware_families.append(result['malware_family'])
            if 'categories' in result:
                categories.extend(result['categories'])
            if 'threat_type' in result:
                threats.append(result['threat_type'])
        
        # Classify based on keywords
        all_indicators = ' '.join(tags + threats + categories).lower()
        
        ioc_type = 'unknown'
        confidence = 0
        
        # Classification rules
        if any(term in all_indicators for term in ['phish', 'spoof', 'fake']):
            ioc_type = 'phishing'
            confidence = 85
        elif any(term in all_indicators for term in ['c2', 'command', 'control', 'botnet']):
            ioc_type = 'c2'
            confidence = 90
        elif any(term in all_indicators for term in ['ransomware', 'ransom', 'encrypt']):
            ioc_type = 'ransomware'
            confidence = 95
        elif any(term in all_indicators for term in ['trojan', 'backdoor', 'rat']):
            ioc_type = 'trojan'
            confidence = 85
        elif any(term in all_indicators for term in ['malware', 'virus', 'worm']):
            ioc_type = 'malware'
            confidence = 80
        elif any(term in all_indicators for term in ['scan', 'probe', 'recon']):
            ioc_type = 'scanner'
            confidence = 75
        elif any(term in all_indicators for term in ['exploit', 'cve']):
            ioc_type = 'exploit'
            confidence = 85
        elif any(term in all_indicators for term in ['exfil', 'data theft', 'stealing']):
            ioc_type = 'data_exfiltration'
            confidence = 80
        
        # Get MITRE mapping
        mitre_info = self.mitre_mapping.get(ioc_type, {
            'tactic': 'Unknown',
            'technique': 'Unknown',
            'sub_techniques': []
        })
        
        return {
            'ioc_type': ioc_type,
            'confidence': confidence,
            'mitre_tactic': mitre_info['tactic'],
            'mitre_technique': mitre_info['technique'],
            'mitre_sub_techniques': mitre_info['sub_techniques'],
            'related_malware': list(set([m for m in malware_families if m and m != 'Unknown'])),
            'tags': list(set(tags))
        }
    
    def extract_related_iocs(self, source_results: List[Dict], original_indicator: str) -> Dict:
        """
        Extract related IOCs to build connection graph
        Returns related IPs, domains, URLs, hashes, and campaigns
        """
        related = {
            'domains': set(),
            'ips': set(),
            'urls': set(),
            'hashes': set(),
            'emails': set(),
            'campaigns': set(),
            'malware_families': set()
        }
        
        for result in source_results:
            # Extract domains
            if 'domain' in result:
                related['domains'].add(result['domain'])
            
            # Extract IPs
            if 'domain_ip' in result:
                related['ips'].add(result['domain_ip'])
            
            # Extract URLs
            if 'scan_url' in result:
                related['urls'].add(result['scan_url'])
            
            # Extract malware families
            if 'malware_family' in result and result['malware_family'] != 'Unknown':
                related['malware_families'].add(result['malware_family'])
            
            # Extract campaigns from tags
            if 'tags' in result:
                for tag in result['tags']:
                    if 'campaign' in tag.lower() or 'apt' in tag.lower():
                        related['campaigns'].add(tag)
        
        # Convert sets to lists
        return {
            'domains': list(related['domains']),
            'ips': list(related['ips']),
            'urls': list(related['urls']),
            'hashes': list(related['hashes']),
            'emails': list(related['emails']),
            'campaigns': list(related['campaigns']),
            'malware_families': list(related['malware_families'])
        }
    
    def build_connection_graph(self, indicator: str, source_results: List[Dict], 
                              classification: Dict, related_iocs: Dict) -> Dict:
        """
        Build a connection graph showing relationships between IOCs
        Returns graph structure with nodes and edges
        """
        nodes = []
        edges = []
        node_id = 0
        
        # Add central node (the queried indicator)
        central_node = {
            'id': node_id,
            'label': indicator,
            'type': 'primary',
            'ioc_type': classification.get('ioc_type', 'unknown'),
            'threat_level': classification.get('confidence', 0)
        }
        nodes.append(central_node)
        central_id = node_id
        node_id += 1
        
        # Add related domains
        for domain in related_iocs.get('domains', []):
            nodes.append({
                'id': node_id,
                'label': domain,
                'type': 'domain',
                'category': 'infrastructure'
            })
            edges.append({
                'from': central_id,
                'to': node_id,
                'relationship': 'resolves_to'
            })
            node_id += 1
        
        # Add related IPs
        for ip in related_iocs.get('ips', []):
            nodes.append({
                'id': node_id,
                'label': ip,
                'type': 'ip',
                'category': 'infrastructure'
            })
            edges.append({
                'from': central_id,
                'to': node_id,
                'relationship': 'connected_to'
            })
            node_id += 1
        
        # Add malware families
        for malware in related_iocs.get('malware_families', []):
            nodes.append({
                'id': node_id,
                'label': malware,
                'type': 'malware',
                'category': 'threat_actor'
            })
            edges.append({
                'from': central_id,
                'to': node_id,
                'relationship': 'associated_with'
            })
            node_id += 1
        
        # Add campaigns
        for campaign in related_iocs.get('campaigns', []):
            nodes.append({
                'id': node_id,
                'label': campaign,
                'type': 'campaign',
                'category': 'threat_actor'
            })
            edges.append({
                'from': central_id,
                'to': node_id,
                'relationship': 'part_of'
            })
            node_id += 1
        
        return {
            'nodes': nodes,
            'edges': edges,
            'total_nodes': len(nodes),
            'total_edges': len(edges)
        }
    
    def comprehensive_analysis(self, indicator: str, indicator_type: str = 'ip') -> Dict:
        """
        Perform comprehensive threat intelligence analysis
        Combines all features: multi-source scoring, classification, MITRE mapping, and graph
        """
        print(f"\n{'='*60}")
        print(f"COMPREHENSIVE THREAT ANALYSIS")
        print(f"{'='*60}")
        print(f"Indicator: {indicator}")
        print(f"Type: {indicator_type}")
        print(f"{'='*60}\n")
        
        # Step 1: Fetch from all sources
        print("📡 Querying threat intelligence sources...")
        source_results = self.fetch_all_sources(indicator, indicator_type)
        
        # Step 2: Calculate composite score
        print("📊 Calculating composite threat score...")
        scorecard = self.calculate_composite_score(source_results)
        
        # Step 3: Classify IOC type and map to MITRE
        print("🎯 Classifying threat type and mapping to MITRE ATT&CK...")
        classification = self.classify_ioc_type(source_results, indicator)
        
        # Step 4: Extract related IOCs
        print("🔗 Extracting related indicators...")
        related_iocs = self.extract_related_iocs(source_results, indicator)
        
        # Step 5: Build connection graph
        print("🕸️  Building connection graph...")
        connection_graph = self.build_connection_graph(
            indicator, source_results, classification, related_iocs
        )
        
        print(f"\n✅ Analysis complete!")
        print(f"{'='*60}\n")
        
        return {
            'indicator': indicator,
            'indicator_type': indicator_type,
            'timestamp': datetime.now().isoformat(),
            'source_results': source_results,
            'scorecard': scorecard,
            'classification': classification,
            'related_iocs': related_iocs,
            'connection_graph': connection_graph
        }
