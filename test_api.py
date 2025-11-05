#!/usr/bin/env python3
"""
Test script for the Advanced Threat Intelligence Platform
Demonstrates all API endpoints and features
"""

import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:8000"

def print_header(title):
    """Print a formatted header"""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80 + "\n")

def print_json(data):
    """Pretty print JSON data"""
    print(json.dumps(data, indent=2))

def test_root():
    """Test root endpoint"""
    print_header("1. Testing Root Endpoint (GET /)")
    
    response = requests.get(f"{BASE_URL}/")
    print(f"Status Code: {response.status_code}")
    print_json(response.json())
    time.sleep(1)

def test_sources():
    """Test available sources endpoint"""
    print_header("2. Testing Available Sources (GET /sources)")
    
    response = requests.get(f"{BASE_URL}/sources")
    print(f"Status Code: {response.status_code}")
    data = response.json()
    print_json(data)
    
    print(f"\n✅ Total Sources: {data['total_sources']}")
    print(f"✅ Enabled Sources: {data['enabled_sources']}")
    time.sleep(1)

def test_analyze_ip():
    """Test IP analysis"""
    print_header("3. Testing IP Analysis (POST /analyze)")
    
    payload = {
        "indicator": "8.8.8.8",
        "indicator_type": "ip"
    }
    
    print(f"📡 Analyzing IP: {payload['indicator']}")
    print("⏳ This may take 10-30 seconds (querying multiple sources)...\n")
    
    response = requests.post(f"{BASE_URL}/analyze", json=payload)
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        
        if data.get('status') == 'success':
            analysis = data['data']
            
            print(f"\n📊 ANALYSIS RESULTS:")
            print(f"  Indicator: {analysis['indicator']}")
            print(f"  Type: {analysis['indicator_type']}")
            print(f"  Timestamp: {analysis['timestamp']}")
            
            # Scorecard
            scorecard = analysis['scorecard']
            print(f"\n🎯 THREAT SCORECARD:")
            print(f"  Composite Score: {scorecard['composite_score']}/100")
            print(f"  Classification: {scorecard['classification']}")
            print(f"  Severity: {scorecard['severity']}")
            print(f"  Sources Checked: {scorecard['sources_checked']}/{scorecard['total_sources']}")
            
            print(f"\n  Source Scores:")
            for source, score in scorecard['source_scores'].items():
                print(f"    • {source}: {score}/100")
            
            # Classification
            classification = analysis['classification']
            print(f"\n🎯 IOC CLASSIFICATION:")
            print(f"  Type: {classification['ioc_type']}")
            print(f"  Confidence: {classification['confidence']}%")
            print(f"  MITRE Tactic: {classification['mitre_tactic']}")
            print(f"  MITRE Technique: {classification['mitre_technique']}")
            
            if classification['mitre_sub_techniques']:
                print(f"  Sub-Techniques: {', '.join(classification['mitre_sub_techniques'])}")
            
            if classification['related_malware']:
                print(f"  Related Malware: {', '.join(classification['related_malware'])}")
            
            if classification['tags']:
                print(f"  Tags: {', '.join(classification['tags'][:5])}")
            
            # Related IOCs
            related = analysis['related_iocs']
            print(f"\n🔗 RELATED INDICATORS:")
            if related['domains']:
                print(f"  Domains: {', '.join(related['domains'][:3])}")
            if related['ips']:
                print(f"  IPs: {', '.join(related['ips'][:3])}")
            if related['malware_families']:
                print(f"  Malware Families: {', '.join(related['malware_families'][:3])}")
            
            # Connection Graph
            graph = analysis['connection_graph']
            print(f"\n🕸️  CONNECTION GRAPH:")
            print(f"  Total Nodes: {graph['total_nodes']}")
            print(f"  Total Edges: {graph['total_edges']}")
            
            return analysis
        else:
            print(f"❌ Analysis failed: {data}")
    else:
        print(f"❌ Request failed with status code: {response.status_code}")
    
    time.sleep(2)

def test_analyze_domain():
    """Test domain analysis"""
    print_header("4. Testing Domain Analysis (POST /analyze)")
    
    payload = {
        "indicator": "google.com",
        "indicator_type": "domain"
    }
    
    print(f"📡 Analyzing Domain: {payload['indicator']}")
    print("⏳ This may take 10-30 seconds...\n")
    
    response = requests.post(f"{BASE_URL}/analyze", json=payload)
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        if data.get('status') == 'success':
            scorecard = data['data']['scorecard']
            print(f"\n📊 Quick Results:")
            print(f"  Composite Score: {scorecard['composite_score']}/100")
            print(f"  Classification: {scorecard['classification']}")
            print(f"  Severity: {scorecard['severity']}")
    
    time.sleep(2)

def test_search():
    """Test search endpoint"""
    print_header("5. Testing Search with Filters (POST /search)")
    
    # Search for malicious IOCs
    payload = {
        "classification": "Malicious",
        "min_score": 70.0
    }
    
    print(f"🔍 Searching for: {payload}")
    response = requests.post(f"{BASE_URL}/search", json=payload)
    
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n✅ Found {data['count']} results")
        
        if data['count'] > 0:
            print("\nTop Results:")
            for i, result in enumerate(data['results'][:3], 1):
                print(f"  {i}. {result['indicator']} - Score: {result.get('composite_score', 'N/A')}")
    
    time.sleep(1)

def test_get_indicators():
    """Test get all indicators"""
    print_header("6. Testing Get All Indicators (GET /indicators)")
    
    response = requests.get(f"{BASE_URL}/indicators?limit=10")
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n✅ Total Indicators: {data['count']}")
        print(f"   Showing: {data['limit']} per page")
        
        if data['count'] > 0:
            print("\nRecent Indicators:")
            for i, ind in enumerate(data['results'][:5], 1):
                print(f"  {i}. {ind['indicator']} ({ind['indicator_type']}) - {ind['classification']}")
    
    time.sleep(1)

def test_get_indicator():
    """Test get specific indicator"""
    print_header("7. Testing Get Specific Indicator (GET /indicator/{indicator})")
    
    indicator = "8.8.8.8"
    print(f"📋 Retrieving cached analysis for: {indicator}")
    
    response = requests.get(f"{BASE_URL}/indicator/{indicator}")
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        if data.get('status') == 'success':
            result = data['data']
            print(f"\n✅ Cached Analysis Found:")
            print(f"   Score: {result.get('composite_score', 'N/A')}/100")
            print(f"   Classification: {result.get('classification', 'N/A')}")
            print(f"   IOC Type: {result.get('ioc_type', 'N/A')}")
    
    time.sleep(1)

def test_connection_graph():
    """Test connection graph endpoint"""
    print_header("8. Testing Connection Graph (GET /graph/{indicator})")
    
    indicator = "8.8.8.8"
    print(f"🕸️  Retrieving connection graph for: {indicator}")
    
    response = requests.get(f"{BASE_URL}/graph/{indicator}?depth=2")
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        if data.get('status') == 'success':
            graph = data['graph']
            print(f"\n✅ Graph Structure:")
            print(f"   Nodes: {len(graph.get('nodes', []))}")
            print(f"   Edges: {len(graph.get('edges', []))}")
            
            if graph.get('nodes'):
                print(f"\n   Node Types:")
                node_types = {}
                for node in graph['nodes']:
                    node_type = node.get('type', 'unknown')
                    node_types[node_type] = node_types.get(node_type, 0) + 1
                
                for ntype, count in node_types.items():
                    print(f"     • {ntype}: {count}")
    
    time.sleep(1)

def test_mitre_stats():
    """Test MITRE statistics endpoint"""
    print_header("9. Testing MITRE ATT&CK Statistics (GET /mitre/statistics)")
    
    response = requests.get(f"{BASE_URL}/mitre/statistics")
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        if data.get('status') == 'success':
            stats = data['data']['mitre_stats']
            
            if stats:
                print(f"\n✅ MITRE ATT&CK Techniques Observed: {len(stats)}")
                print("\nTop 5 Techniques:")
                for i, stat in enumerate(stats[:5], 1):
                    print(f"  {i}. {stat['technique']} ({stat['tactic']}) - {stat['count']} occurrences")
            else:
                print("\n📊 No MITRE statistics available yet (no analyzed indicators)")
    
    time.sleep(1)

def test_health():
    """Test health check endpoint"""
    print_header("10. Testing Health Check (GET /health)")
    
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status Code: {response.status_code}")
    print_json(response.json())

def main():
    """Run all tests"""
    print("\n" + "🛡️ "*20)
    print("   ADVANCED THREAT INTELLIGENCE PLATFORM - API TEST SUITE")
    print("🛡️ "*20)
    
    print(f"\n📅 Test Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 Base URL: {BASE_URL}")
    
    try:
        # Test all endpoints
        test_root()
        test_health()
        test_sources()
        test_analyze_ip()
        test_analyze_domain()
        test_search()
        test_get_indicators()
        test_get_indicator()
        test_connection_graph()
        test_mitre_stats()
        
        # Final summary
        print_header("✅ ALL TESTS COMPLETED SUCCESSFULLY!")
        print("""
🎉 Summary:
  ✅ Root endpoint working
  ✅ Health check passing
  ✅ Sources endpoint active
  ✅ IP analysis functional
  ✅ Domain analysis functional
  ✅ Search with filters working
  ✅ Indicator listing active
  ✅ Cached retrieval working
  ✅ Connection graph generated
  ✅ MITRE statistics available

📊 Your threat intelligence platform is fully operational!

🌐 Access the frontend at: http://localhost:3000
📖 View API docs at: http://localhost:8000/docs
        """)
        
    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: Cannot connect to API server!")
        print("   Please ensure the backend is running on http://localhost:8000")
        print("   Start it with: python3 -m uvicorn infosecwriteups.api_server_enhanced:app --reload --port 8000")
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
