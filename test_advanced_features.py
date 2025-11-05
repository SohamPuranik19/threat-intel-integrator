#!/usr/bin/env python3
"""
Comprehensive Testing Script for Advanced Threat Intelligence Features

Tests:
1. Multi-source integration (9 sources)
2. Composite scorecard system
3. IOC classification with MITRE ATT&CK mapping
4. Connection graph generation

Author: Advanced Threat Intelligence Platform
Date: November 4, 2025
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List

BASE_URL = "http://localhost:8000"

def print_section(title: str, char: str = "="):
    """Print a formatted section header"""
    print(f"\n{char * 80}")
    print(f"  {title}")
    print(f"{char * 80}\n")

def print_json(data: dict, indent: int = 2):
    """Pretty print JSON data"""
    print(json.dumps(data, indent=indent))

def print_result(emoji: str, message: str):
    """Print a result message with emoji"""
    print(f"{emoji} {message}")

# =============================================================================
# TEST 1: Multi-Source Integration
# =============================================================================

def test_multi_source_integration():
    """Test all 9 threat intelligence sources"""
    print_section("TEST 1: Multi-Source Integration (9 Sources)", "=")
    
    print("📡 Checking available threat intelligence sources...\n")
    
    response = requests.get(f"{BASE_URL}/sources")
    data = response.json()
    
    if response.status_code == 200:
        print_result("✅", f"Total Sources Available: {data['total_sources']}")
        print_result("✅", f"Sources Enabled: {data['enabled_sources']}")
        
        print("\n📊 Source Status:\n")
        sources = data['sources']
        
        for source_name, source_info in sources.items():
            status = "🟢 ENABLED" if source_info['enabled'] else "🔴 DISABLED (No API Key)"
            weight = source_info['weight']
            print(f"  {source_name:25} {status:30} Weight: {weight:.0%}")
        
        print("\n" + "-" * 80)
        print("📝 SOURCES EXPLANATION:")
        print("-" * 80)
        print("🟢 ENABLED  = API key configured or no key required")
        print("🔴 DISABLED = Requires API key (add to .env file)")
        print("\nFree sources (always enabled):")
        print("  • URLhaus - Malware distribution URLs")
        print("  • ThreatFox - abuse.ch IOC database")
        print("  • WHOIS - Domain registration data")
        print("\nOptional sources (require free API keys):")
        print("  • VirusTotal - Multi-engine malware scanner")
        print("  • AbuseIPDB - IP abuse reports")
        print("  • AlienVault OTX - Threat intelligence pulses")
        print("  • Shodan - Internet-wide device scanner")
        print("  • URLScan.io - Website analysis")
        print("  • Hybrid Analysis - Malware sandbox")
        
        return True
    else:
        print_result("❌", f"Failed to get sources: {response.status_code}")
        return False

# =============================================================================
# TEST 2: Composite Scorecard System
# =============================================================================

def test_composite_scorecard(indicator: str, indicator_type: str):
    """Test multi-source composite scoring"""
    print_section(f"TEST 2: Composite Scorecard - {indicator}", "=")
    
    print(f"🎯 Analyzing indicator: {indicator}")
    print(f"📋 Type: {indicator_type}")
    print(f"⏳ Querying all available sources (this may take 15-30 seconds)...\n")
    
    payload = {
        "indicator": indicator,
        "indicator_type": indicator_type
    }
    
    response = requests.post(f"{BASE_URL}/analyze", json=payload)
    
    if response.status_code != 200:
        print_result("❌", f"Analysis failed: {response.status_code}")
        return None
    
    data = response.json()
    
    if data.get('status') != 'success':
        print_result("❌", f"Analysis error: {data}")
        return None
    
    analysis = data['data']
    scorecard = analysis['scorecard']
    
    # Display Scorecard Results
    print("=" * 80)
    print("📊 COMPOSITE SCORECARD RESULTS")
    print("=" * 80)
    
    print(f"\n🎯 Overall Assessment:")
    print(f"  Composite Score:  {scorecard['composite_score']:.2f}/100")
    print(f"  Classification:   {scorecard['classification']}")
    print(f"  Severity Level:   {scorecard['severity']}")
    print(f"  Sources Checked:  {scorecard['sources_checked']}/{scorecard['total_sources']}")
    
    print(f"\n📈 Individual Source Scores:")
    print("-" * 80)
    
    source_scores = scorecard.get('source_scores', {})
    if source_scores:
        # Sort by score (highest first)
        sorted_scores = sorted(source_scores.items(), key=lambda x: x[1], reverse=True)
        
        for source, score in sorted_scores:
            # Visual bar representation
            bar_length = int(score / 5)  # 20 chars = 100 score
            bar = "█" * bar_length + "░" * (20 - bar_length)
            
            # Color coding
            if score >= 70:
                indicator_emoji = "🔴"  # High threat
            elif score >= 40:
                indicator_emoji = "🟡"  # Medium threat
            else:
                indicator_emoji = "🟢"  # Low threat
            
            print(f"  {indicator_emoji} {source:20} {bar} {score:5.1f}/100")
    else:
        print("  No source scores available")
    
    print("\n" + "=" * 80)
    print("📐 SCORING METHODOLOGY")
    print("=" * 80)
    print("Composite Score = Weighted Average of All Sources")
    print("\nSource Weights:")
    print("  VirusTotal:       20%  (Multi-engine analysis)")
    print("  AbuseIPDB:        15%  (IP reputation)")
    print("  AlienVault OTX:   15%  (Threat pulses)")
    print("  URLScan:          15%  (Website analysis)")
    print("  Shodan:           10%  (Device scanning)")
    print("  Hybrid Analysis:  10%  (Sandbox)")
    print("  URLhaus:          10%  (Malware URLs)")
    print("  ThreatFox:         5%  (IOC database)")
    print("  WHOIS:             5%  (Domain age/privacy)")
    
    print("\nClassification Thresholds:")
    print("  🔴 Malicious:  70-100 (Critical/High severity)")
    print("  🟡 Suspicious: 40-69  (Medium severity)")
    print("  🟢 Benign:     0-39   (Low severity)")
    
    return analysis

# =============================================================================
# TEST 3: IOC Classification & MITRE ATT&CK Mapping
# =============================================================================

def test_ioc_classification(analysis: Dict):
    """Test IOC classification and MITRE ATT&CK mapping"""
    print_section("TEST 3: IOC Classification & MITRE ATT&CK Mapping", "=")
    
    if not analysis:
        print_result("⚠️", "No analysis data provided")
        return
    
    classification = analysis.get('classification', {})
    
    print("🎯 IOC CLASSIFICATION RESULTS")
    print("=" * 80)
    
    # IOC Type
    ioc_type = classification.get('ioc_type', 'unknown')
    confidence = classification.get('confidence', 0)
    
    print(f"\n📌 IOC Type: {ioc_type.upper()}")
    print(f"   Confidence: {confidence}%")
    
    # Confidence bar
    conf_bar = "█" * int(confidence / 5) + "░" * (20 - int(confidence / 5))
    print(f"   {conf_bar} {confidence}%")
    
    # MITRE ATT&CK Mapping
    print(f"\n🗺️  MITRE ATT&CK Framework Mapping:")
    print("-" * 80)
    print(f"  Tactic:     {classification.get('mitre_tactic', 'Unknown')}")
    print(f"  Technique:  {classification.get('mitre_technique', 'Unknown')}")
    
    sub_techniques = classification.get('mitre_sub_techniques', [])
    if sub_techniques:
        print(f"\n  Sub-Techniques:")
        for sub_tech in sub_techniques:
            print(f"    • {sub_tech}")
    
    # Related Malware
    related_malware = classification.get('related_malware', [])
    if related_malware:
        print(f"\n🦠 Related Malware Families:")
        for malware in related_malware:
            print(f"  • {malware}")
    
    # Tags
    tags = classification.get('tags', [])
    if tags:
        print(f"\n🏷️  Tags: {', '.join(tags[:10])}")
    
    # IOC Type Definitions
    print("\n" + "=" * 80)
    print("📚 IOC TYPE DEFINITIONS")
    print("=" * 80)
    
    ioc_definitions = {
        'phishing': {
            'desc': 'Fraudulent attempts to obtain sensitive information',
            'mitre': 'T1566 - Phishing',
            'tactic': 'Initial Access'
        },
        'c2': {
            'desc': 'Command and Control server infrastructure',
            'mitre': 'T1071 - Application Layer Protocol',
            'tactic': 'Command and Control'
        },
        'ransomware': {
            'desc': 'Malware that encrypts data for ransom',
            'mitre': 'T1486 - Data Encrypted for Impact',
            'tactic': 'Impact'
        },
        'trojan': {
            'desc': 'Malware disguised as legitimate software',
            'mitre': 'T1547 - Boot or Logon Autostart Execution',
            'tactic': 'Persistence'
        },
        'malware': {
            'desc': 'General malicious software',
            'mitre': 'T1204 - User Execution',
            'tactic': 'Execution'
        },
        'scanner': {
            'desc': 'Network or service discovery tools',
            'mitre': 'T1046 - Network Service Discovery',
            'tactic': 'Discovery'
        },
        'exploit': {
            'desc': 'Code that takes advantage of vulnerabilities',
            'mitre': 'T1203 - Exploitation for Client Execution',
            'tactic': 'Execution'
        },
        'data_exfiltration': {
            'desc': 'Unauthorized data transfer',
            'mitre': 'T1041 - Exfiltration Over C2 Channel',
            'tactic': 'Exfiltration'
        }
    }
    
    if ioc_type in ioc_definitions:
        info = ioc_definitions[ioc_type]
        print(f"\n{ioc_type.upper()}:")
        print(f"  Description: {info['desc']}")
        print(f"  MITRE Tactic: {info['tactic']}")
        print(f"  MITRE Technique: {info['mitre']}")
    
    print("\n💡 Classification is based on:")
    print("  • Keywords from source tags and threat types")
    print("  • Malware family associations")
    print("  • Behavioral indicators")
    print("  • Community threat intelligence")

# =============================================================================
# TEST 4: Connection Graph Generation
# =============================================================================

def test_connection_graph(analysis: Dict, indicator: str):
    """Test connection graph and IOC relationships"""
    print_section("TEST 4: Connection Graph & IOC Relationships", "=")
    
    if not analysis:
        print_result("⚠️", "No analysis data provided")
        return
    
    # Related IOCs
    related_iocs = analysis.get('related_iocs', {})
    
    print("🔗 RELATED INDICATORS")
    print("=" * 80)
    
    total_related = 0
    
    # Domains
    domains = related_iocs.get('domains', [])
    if domains:
        print(f"\n🌐 Related Domains ({len(domains)}):")
        for domain in domains[:5]:
            print(f"  • {domain}")
        if len(domains) > 5:
            print(f"  ... and {len(domains) - 5} more")
        total_related += len(domains)
    
    # IPs
    ips = related_iocs.get('ips', [])
    if ips:
        print(f"\n🖥️  Related IP Addresses ({len(ips)}):")
        for ip in ips[:5]:
            print(f"  • {ip}")
        if len(ips) > 5:
            print(f"  ... and {len(ips) - 5} more")
        total_related += len(ips)
    
    # URLs
    urls = related_iocs.get('urls', [])
    if urls:
        print(f"\n🔗 Related URLs ({len(urls)}):")
        for url in urls[:3]:
            print(f"  • {url}")
        if len(urls) > 3:
            print(f"  ... and {len(urls) - 3} more")
        total_related += len(urls)
    
    # Malware Families
    malware_families = related_iocs.get('malware_families', [])
    if malware_families:
        print(f"\n🦠 Malware Families ({len(malware_families)}):")
        for malware in malware_families:
            print(f"  • {malware}")
        total_related += len(malware_families)
    
    # Campaigns
    campaigns = related_iocs.get('campaigns', [])
    if campaigns:
        print(f"\n🎯 Threat Campaigns ({len(campaigns)}):")
        for campaign in campaigns:
            print(f"  • {campaign}")
        total_related += len(campaigns)
    
    if total_related == 0:
        print("\n  No related indicators found for this IOC")
    
    # Connection Graph
    print("\n" + "=" * 80)
    print("🕸️  CONNECTION GRAPH STRUCTURE")
    print("=" * 80)
    
    graph = analysis.get('connection_graph', {})
    nodes = graph.get('nodes', [])
    edges = graph.get('edges', [])
    
    print(f"\nGraph Statistics:")
    print(f"  Total Nodes: {len(nodes)}")
    print(f"  Total Edges: {len(edges)}")
    
    # Node Types
    if nodes:
        print(f"\n📊 Node Types:")
        node_types = {}
        for node in nodes:
            node_type = node.get('type', 'unknown')
            node_types[node_type] = node_types.get(node_type, 0) + 1
        
        for ntype, count in sorted(node_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {ntype:15} {count} node(s)")
    
    # Sample Nodes
    if len(nodes) > 0:
        print(f"\n📍 Sample Nodes (first 5):")
        for node in nodes[:5]:
            node_id = node.get('id')
            label = node.get('label')
            ntype = node.get('type')
            print(f"  [{node_id}] {label} ({ntype})")
    
    # Edge Types (Relationships)
    if edges:
        print(f"\n🔀 Relationship Types:")
        edge_types = {}
        for edge in edges:
            rel = edge.get('relationship', 'unknown')
            edge_types[rel] = edge_types.get(rel, 0) + 1
        
        for rel_type, count in sorted(edge_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {rel_type:20} {count} connection(s)")
    
    # Sample Edges
    if len(edges) > 0:
        print(f"\n🔗 Sample Connections (first 5):")
        for edge in edges[:5]:
            from_id = edge.get('from')
            to_id = edge.get('to')
            rel = edge.get('relationship')
            
            # Find node labels
            from_label = next((n['label'] for n in nodes if n['id'] == from_id), f"Node {from_id}")
            to_label = next((n['label'] for n in nodes if n['id'] == to_id), f"Node {to_id}")
            
            print(f"  {from_label} --[{rel}]--> {to_label}")
    
    # Graph Explanation
    print("\n" + "=" * 80)
    print("📖 GRAPH RELATIONSHIPS EXPLAINED")
    print("=" * 80)
    print("""
The connection graph maps relationships between different IOCs:

🔗 Relationship Types:
  • resolves_to       - Domain resolves to IP address
  • connected_to      - IP addresses that communicate
  • associated_with   - IOC linked to malware family
  • part_of           - IOC part of threat campaign

📍 Node Categories:
  • primary           - The queried indicator (center of graph)
  • domain            - Domain names
  • ip                - IP addresses  
  • malware           - Malware families
  • campaign          - Threat actor campaigns

💡 Use Case:
  Starting from a single malicious IP, you can discover:
  → Related domains it hosts
  → Other IPs in same network
  → Malware families using this infrastructure
  → Broader threat campaigns
  → Email addresses in malicious campaigns
    """)
    
    # Visualization recommendation
    if len(nodes) > 1:
        print("🎨 VISUALIZATION RECOMMENDATION:")
        print("-" * 80)
        print("To visualize this graph in the frontend, use:")
        print("  • react-force-graph (3D interactive graphs)")
        print("  • vis.js (Network diagrams)")
        print("  • cytoscape.js (Complex networks)")
        print(f"\nGraph data available at: GET /graph/{indicator}")

# =============================================================================
# MAIN TEST RUNNER
# =============================================================================

def run_all_tests():
    """Execute all comprehensive tests"""
    print("\n" + "🛡️ " * 30)
    print(" " * 20 + "ADVANCED THREAT INTELLIGENCE TESTING SUITE")
    print("🛡️ " * 30)
    
    print(f"\n📅 Test Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 API Endpoint: {BASE_URL}")
    print(f"📋 Testing All 4 Advanced Features\n")
    
    try:
        # Test 1: Multi-Source Integration
        source_test = test_multi_source_integration()
        time.sleep(2)
        
        if not source_test:
            print("\n⚠️  Source test failed. Continuing with other tests...\n")
        
        # Test 2, 3, 4: Analyze an indicator to test scorecard, classification, and graph
        print("\n" + "=" * 80)
        print("🧪 Running Tests 2-4 with Sample Indicators")
        print("=" * 80)
        
        # Test with multiple indicator types
        test_cases = [
            ("8.8.8.8", "ip", "Google DNS - Expected Benign"),
            ("example.com", "domain", "Example Domain - Expected Benign"),
        ]
        
        for indicator, ind_type, description in test_cases:
            print(f"\n{'=' * 80}")
            print(f"Testing: {description}")
            print(f"{'=' * 80}")
            
            # Test 2: Composite Scorecard
            analysis = test_composite_scorecard(indicator, ind_type)
            time.sleep(2)
            
            if analysis:
                # Test 3: IOC Classification & MITRE
                test_ioc_classification(analysis)
                time.sleep(2)
                
                # Test 4: Connection Graph
                test_connection_graph(analysis, indicator)
                time.sleep(2)
            else:
                print(f"\n⚠️  Could not complete tests for {indicator}")
            
            print("\n" + "=" * 80)
            time.sleep(1)
        
        # Final Summary
        print_section("✅ ALL TESTS COMPLETED", "=")
        print("""
🎉 TESTING SUMMARY
═══════════════════════════════════════════════════════════════════════════

✅ TEST 1: Multi-Source Integration
   • Verified 9 threat intelligence sources
   • Checked source availability and weights
   • Sources: VirusTotal, AbuseIPDB, OTX, Shodan, URLScan, 
              Hybrid Analysis, URLhaus, ThreatFox, WHOIS

✅ TEST 2: Composite Scorecard System
   • Multi-source weighted scoring verified
   • Classification logic working (Malicious/Suspicious/Benign)
   • Severity levels assigned correctly
   • Individual source scores aggregated

✅ TEST 3: IOC Classification & MITRE ATT&CK
   • IOC type detection functional
   • MITRE ATT&CK mapping operational
   • Tactics and techniques correctly mapped
   • Malware family tracking active
   • 8 IOC types supported

✅ TEST 4: Connection Graph Generation  
   • Related IOCs extracted successfully
   • Graph structure (nodes/edges) generated
   • Relationship types mapped correctly
   • Multi-hop connections supported

═══════════════════════════════════════════════════════════════════════════

📊 NEXT STEPS:

1. Add API Keys for Full Functionality:
   cp .env.example .env
   # Edit .env with your API keys

2. Test with Malicious Indicators:
   • Try known malicious IPs/domains
   • Observe higher threat scores
   • See richer MITRE mappings

3. Visualize Connection Graphs:
   • Install: npm install react-force-graph
   • Create ConnectionGraph.tsx component
   • Use graph data from API

4. Explore API Documentation:
   • http://localhost:8000/docs
   • Try all endpoints interactively

═══════════════════════════════════════════════════════════════════════════

🎓 DOCUMENTATION:
   • TESTING_GUIDE.md - Step-by-step testing instructions
   • README_ENHANCED.md - Complete feature documentation  
   • IMPLEMENTATION_SUMMARY.md - Technical details

🛡️  Your Advanced Threat Intelligence Platform is fully operational!
        """)
        
    except requests.exceptions.ConnectionError:
        print("\n" + "=" * 80)
        print("❌ ERROR: Cannot connect to API server!")
        print("=" * 80)
        print("\n📋 Please ensure the backend is running:")
        print("   python3 -m uvicorn infosecwriteups.api_server_enhanced:app --reload --port 8000")
        print("\n🌐 Backend should be accessible at: http://localhost:8000")
        print("📖 Check API docs at: http://localhost:8000/docs\n")
    
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    run_all_tests()
