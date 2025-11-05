# 🛡️ Advanced Threat Intelligence Platform

A comprehensive threat intelligence aggregation and analysis platform with multi-source integration, MITRE ATT&CK mapping, and connection graph visualization.

## 🚀 Features

### 1. **Multi-Source Threat Intelligence** 📡
Integrates with 9+ threat intelligence sources:
- ✅ **VirusTotal** - File, URL, IP, and domain analysis
- ✅ **AbuseIPDB** - IP reputation and abuse reports
- ✅ **AlienVault OTX** - Open Threat Exchange pulses
- ✅ **Shodan** - Internet-wide device scanning and vulnerability detection
- ✅ **URLScan.io** - URL and website analysis
- ✅ **Hybrid Analysis** - Malware sandbox analysis
- ✅ **URLhaus** - Malware distribution URL tracking
- ✅ **ThreatFox** - IOC database from abuse.ch
- ✅ **WHOIS** - Domain registration and ownership data

### 2. **Intelligent Scoring System** 📊
- **Weighted Composite Scoring**: Aggregates scores from all sources with configurable weights
- **Multi-Dimensional Analysis**: Considers reputation, malware detections, vulnerabilities, and threat indicators
- **Classification Levels**:
  - 🔴 **Malicious** (70-100): Critical/High severity threats
  - 🟠 **Suspicious** (40-69): Medium severity, requires investigation
  - 🟢 **Benign** (0-39): Low severity or clean

### 3. **IOC Classification & MITRE ATT&CK Mapping** 🎯
Automatically classifies indicators and maps to MITRE ATT&CK framework:

| IOC Type | MITRE Tactic | Example Techniques |
|----------|--------------|-------------------|
| **Phishing** | Initial Access | T1566 - Phishing |
| **C2 (Command & Control)** | Command and Control | T1071 - Application Layer Protocol |
| **Malware** | Execution | T1204 - User Execution |
| **Ransomware** | Impact | T1486 - Data Encrypted for Impact |
| **Data Exfiltration** | Exfiltration | T1041 - Exfiltration Over C2 Channel |
| **Trojan** | Persistence | T1547 - Boot or Logon Autostart Execution |
| **Scanner** | Discovery | T1046 - Network Service Discovery |
| **Exploit** | Execution | T1203 - Exploitation for Client Execution |

### 4. **Connection Graph Visualization** 🕸️
Maps relationships between IOCs:
- **Infrastructure Connections**: IPs ↔ Domains ↔ URLs
- **Malware Associations**: Links to malware families and variants
- **Campaign Tracking**: Identifies related threat campaigns
- **Multi-Hop Analysis**: Discovers indirect relationships up to N levels deep

### 5. **Comprehensive Database** 💾
Enhanced schema supporting:
- Multi-source threat data storage
- IOC relationship mapping
- Malware family tracking
- Campaign attribution
- MITRE ATT&CK technique statistics
- Historical analysis retention

## 📦 Installation

### Prerequisites
- Python 3.8+
- Node.js 18+
- npm or yarn

### Backend Setup

1. **Clone the repository**
```bash
git clone <repository-url>
cd threat-intel-integrator-main
```

2. **Install Python dependencies**
```bash
pip3 install -r requirements.txt
```

3. **Set up API keys**
```bash
cp .env.example .env
# Edit .env and add your API keys
```

4. **Start the backend**
```bash
# Standard API server
python3 -m uvicorn infosecwriteups.api_server:app --reload --port 8000

# OR Enhanced API server with all new features
python3 -m uvicorn infosecwriteups.api_server_enhanced:app --reload --port 8000
```

### Frontend Setup

1. **Navigate to frontend directory**
```bash
cd frontend
```

2. **Install dependencies**
```bash
npm install
```

3. **Start the development server**
```bash
npm run dev
```

4. **Access the application**
- Frontend: http://localhost:3000
- Backend API Docs: http://localhost:8000/docs

## 🔑 API Keys Setup

### Required API Keys

1. **VirusTotal** (Free tier: 4 requests/min)
   - Sign up: https://www.virustotal.com/gui/join-us
   - Get API key: https://www.virustotal.com/gui/my-apikey

2. **AbuseIPDB** (Free tier: 1000 requests/day)
   - Sign up: https://www.abuseipdb.com/register
   - Get API key: https://www.abuseipdb.com/account/api

3. **AlienVault OTX** (Free, no limits)
   - Sign up: https://otx.alienvault.com/accounts/signup
   - Get API key: https://otx.alienvault.com/api

### Optional API Keys (Enhanced Features)

4. **Shodan** (Free tier: 100 results/month)
   - Sign up: https://account.shodan.io/register
   - Get API key: https://account.shodan.io/

5. **URLScan.io** (Free tier: 500 scans/day)
   - Sign up: https://urlscan.io/user/signup
   - Get API key: https://urlscan.io/user/profile/

6. **Hybrid Analysis** (Free tier: 50 submissions/day)
   - Sign up: https://www.hybrid-analysis.com/signup
   - Get API key: https://www.hybrid-analysis.com/apikeys/info

### Free Services (No API Key Required)
- URLhaus
- ThreatFox (abuse.ch)
- WHOIS

## 📚 API Documentation

### Enhanced API Endpoints

#### 1. Comprehensive Analysis
```bash
POST /analyze
Content-Type: application/json

{
  "indicator": "8.8.8.8",
  "indicator_type": "ip"  # Optional: ip, url, domain, hash
}
```

**Response includes:**
- Multi-source scorecard
- IOC classification
- MITRE ATT&CK mapping
- Related IOCs
- Connection graph

#### 2. Search Indicators
```bash
POST /search
Content-Type: application/json

{
  "query": "malware",
  "classification": "Malicious",
  "ioc_type": "c2",
  "min_score": 70.0
}
```

#### 3. Get Indicator Details
```bash
GET /indicator/{indicator}
```

#### 4. Get Connection Graph
```bash
GET /graph/{indicator}?depth=2
```

#### 5. MITRE ATT&CK Statistics
```bash
GET /mitre/statistics
```

#### 6. List All Indicators
```bash
GET /indicators?limit=100&offset=0
```

#### 7. Check Available Sources
```bash
GET /sources
```

## 🎨 Frontend Features

- **Professional Black/Orange Theme**: Modern, hacker-aesthetic design
- **Matrix-Style Animations**: Dynamic background with falling code
- **Real-time Analysis**: Instant threat lookups with loading states
- **Interactive Dashboards**: Charts, tables, and graphs
- **Quick Verdict**: At-a-glance threat classification
- **Responsive Design**: Works on desktop and mobile

## 🧪 Example Usage

### Python Example
```python
from infosecwriteups.api_integrations import ThreatIntelAPI
from infosecwriteups.database_enhanced import EnhancedThreatDatabase

# Initialize with API keys
api = ThreatIntelAPI(
    abuse_key="your_key",
    vt_key="your_key",
    otx_key="your_key"
)

# Perform comprehensive analysis
analysis = api.comprehensive_analysis("8.8.8.8", "ip")

# Store in database
db = EnhancedThreatDatabase()
db.insert_comprehensive_analysis(analysis)

# Access results
print(f"Composite Score: {analysis['scorecard']['composite_score']}")
print(f"Classification: {analysis['scorecard']['classification']}")
print(f"IOC Type: {analysis['classification']['ioc_type']}")
print(f"MITRE Technique: {analysis['classification']['mitre_technique']}")
```

### cURL Example
```bash
# Analyze an IP address
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "indicator": "1.2.3.4",
    "indicator_type": "ip"
  }'

# Search for malicious IOCs
curl -X POST "http://localhost:8000/search" \
  -H "Content-Type: application/json" \
  -d '{
    "classification": "Malicious",
    "min_score": 80
  }'
```

## 🔬 Database Schema

### Main Tables

1. **threat_indicators**: Core IOC data with composite scoring
2. **source_scores**: Individual scores from each threat intel source
3. **ioc_relationships**: Connections between different IOCs
4. **malware_families**: Tracked malware families and variants
5. **campaigns**: Threat actor campaigns
6. **campaign_iocs**: Mapping between campaigns and IOCs

## 📊 Scoring Algorithm

The composite score uses weighted averaging from all available sources:

```
Composite Score = Σ (Source Score × Source Weight) / Σ Source Weights

Weights:
- VirusTotal: 20%
- AbuseIPDB: 15%
- AlienVault OTX: 15%
- URLScan: 15%
- Shodan: 10%
- Hybrid Analysis: 10%
- URLhaus: 10%
- ThreatFox: 5%
- WHOIS: 5%
```

## 🛠️ Development

### Project Structure
```
threat-intel-integrator-main/
├── infosecwriteups/
│   ├── api_integrations.py      # Multi-source API integrations
│   ├── api_server.py             # Basic FastAPI server
│   ├── api_server_enhanced.py    # Enhanced API with new features
│   ├── database.py               # Basic database
│   ├── database_enhanced.py      # Enhanced schema with graphs
│   ├── processor.py              # Data processing logic
│   └── config.py                 # Configuration
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx          # Main dashboard
│   │   │   └── login/page.tsx    # Login page
│   │   └── components/
│   │       ├── QuickVerdict.tsx  # Threat verdict display
│   │       ├── Charts.tsx        # Data visualization
│   │       ├── SearchBar.tsx     # Search interface
│   │       ├── DataTable.tsx     # Results table
│   │       └── Sidebar.tsx       # Filter controls
│   └── package.json
├── requirements.txt
├── .env.example
└── README.md
```

### Running Tests
```bash
# Backend tests
pytest tests/

# Frontend tests
cd frontend && npm test
```

## 🚀 Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed deployment instructions for:
- Vercel (Frontend)
- Railway/Render (Backend)
- Docker containers
- Cloud platforms (AWS, GCP, Azure)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- MITRE ATT&CK Framework
- All threat intelligence providers
- Open source security community

## 📧 Contact

For questions or support, please open an issue on GitHub.

---

**⚠️ Disclaimer**: This tool is for security research and defensive purposes only. Always ensure you have permission before analyzing systems or infrastructure you don't own.
