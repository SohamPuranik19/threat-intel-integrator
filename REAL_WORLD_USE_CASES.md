# 🎯 Real-World Use Cases: How SOC/IR Teams Use This Tool

## 📖 **What is an IOC (Indicator of Compromise)?**

An **IOC** is a piece of evidence that indicates a potential security breach or malicious activity:
- **IP addresses** - Servers communicating with your network
- **Domains** - Websites/hostnames being accessed
- **URLs** - Specific web addresses visited
- **File hashes** - Unique fingerprints of files (MD5/SHA1/SHA256)

---

## 🚨 **Use Case 1: Investigating a Suspicious Email**

### **Scenario:**
Your employee receives this email:
```
From: security@paypa1-verify.com  (Note: "paypa1" with number 1, not L)
Subject: Urgent: Verify Your Account
Link: http://paypa1-verify.com/login.php
```

### **IOCs to Investigate:**
1. **Domain:** `paypa1-verify.com`
2. **IP:** (resolved from domain)
3. **URL:** `http://paypa1-verify.com/login.php`

### **How SOC Uses Your Tool:**

#### **Step 1: Extract IOCs**
```
Domain: paypa1-verify.com
URL: http://paypa1-verify.com/login.php
```

#### **Step 2: Analyze in Your Platform**
```bash
# Option A: Browser
Go to http://localhost:3000
Search: paypa1-verify.com
Click: Lookup

# Option B: API
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"indicator":"paypa1-verify.com","indicator_type":"domain"}'
```

#### **Step 3: Interpret Results**
```
┌─────────────────────────────────────────────────────────────┐
│ 🔴 Quick Verdict                        Threat Score: 78   │
│ paypa1-verify.com                                           │
│                                                             │
│ [Suspicious] [Medium Severity] [Phishing] [Confidence: 85%]│
│                                                             │
│ WHOIS: Domain Age: 2 days ⚠️                               │
│ MITRE ATT&CK: T1566 - Phishing (Initial Access)           │
│ Related IOCs: 3 domains, 2 IPs found                       │
└─────────────────────────────────────────────────────────────┘
```

#### **Step 4: SOC Actions**
✅ **BLOCK** domain in email gateway  
✅ **ALERT** all users about phishing campaign  
✅ **SEARCH** email logs for other recipients  
✅ **BLOCK** related IPs in firewall  
✅ **REPORT** to abuse team and URLhaus  
✅ **DOCUMENT** using MITRE T1566 reference  

---

## 🚨 **Use Case 2: Firewall Alert Investigation**

### **Scenario:**
Your firewall alerts:
```
[ALERT] Outbound connection blocked
Source: 192.168.1.105 (Employee laptop)
Destination: 185.220.101.1:443
Protocol: HTTPS
Time: 2025-11-05 14:32:15
```

### **IOC to Investigate:**
```
IP: 185.220.101.1
```

### **How SOC Uses Your Tool:**

#### **Step 1: Quick Analysis**
```
Browser: http://localhost:3000
Search: 185.220.101.1
```

#### **Step 2: Platform Shows**
```
┌─────────────────────────────────────────────────────────────┐
│ 🔴 Quick Verdict                        Threat Score: 82   │
│ 185.220.101.1                                               │
│                                                             │
│ [Malicious] [High Severity] [C2] [Confidence: 92%]        │
│                                                             │
│ IOC Type: Command & Control Server                         │
│ MITRE ATT&CK: T1071 - Application Layer Protocol           │
│ Related IOCs: 12 domains, 8 IPs, 3 malware families       │
│ Country: Russia                                             │
└─────────────────────────────────────────────────────────────┘
```

#### **Step 3: Connection Graph Reveals**
```
[185.220.101.1] ─── associated_with ──> [TrickBot Malware]
       │
       ├── connected_to ──> [185.220.101.2]
       │                    [185.220.101.3]
       │
       └── part_of ──> [APT28 Campaign]
```

#### **Step 4: CRITICAL INCIDENT RESPONSE**
🚨 **ISOLATE** employee laptop from network  
🚨 **SCAN** laptop for TrickBot malware  
🚨 **BLOCK** all 12 related IPs at firewall  
🚨 **HUNT** for other infected systems  
🚨 **CHECK** if data was exfiltrated  
🚨 **ESCALATE** to incident response team  
🚨 **DOCUMENT** as T1071 C2 communication  

---

## 🚨 **Use Case 3: Malware File Analysis**

### **Scenario:**
Antivirus quarantines a file:
```
File: invoice_2025.pdf.exe
Path: C:\Users\John\Downloads\
Hash (SHA256): 44d88612fea8a8f36de82e1278abb02f
Status: Quarantined
```

### **IOC to Investigate:**
```
Hash: 44d88612fea8a8f36de82e1278abb02f
```

### **How SOC Uses Your Tool:**

#### **Step 1: Hash Analysis**
```
Search: 44d88612fea8a8f36de82e1278abb02f
Type: hash
```

#### **Step 2: Platform Shows**
```
┌─────────────────────────────────────────────────────────────┐
│ 🔴 Quick Verdict                        Threat Score: 95   │
│ 44d88612fea8a8f36de82e1278abb02f                           │
│                                                             │
│ [Malicious] [Critical Severity] [Ransomware] [Conf: 98%]  │
│                                                             │
│ Malware Family: Ryuk Ransomware                            │
│ MITRE ATT&CK: T1486 - Data Encrypted for Impact           │
│ Distribution URLs: 5 found                                  │
│ C2 Servers: 3 active IPs                                   │
└─────────────────────────────────────────────────────────────┘
```

#### **Step 3: Connection Graph**
```
[ransomware.exe] ─── distributed_via ──> [malicious-cdn.com]
       │                                  [evil-download.net]
       │
       ├── communicates_with ──> [C2: 203.0.113.5]
       │                         [C2: 203.0.113.6]
       │
       └── part_of ──> [Ryuk Ransomware Campaign]
```

#### **Step 4: EMERGENCY RESPONSE**
🚨 **ISOLATE** John's computer immediately  
🚨 **DISABLE** network access for entire subnet  
🚨 **BLOCK** all 5 distribution URLs  
🚨 **BLOCK** 3 C2 IPs at perimeter firewall  
🚨 **SCAN** entire network for this hash  
🚨 **RESTORE** from backups if encrypted  
🚨 **NOTIFY** management/legal team  
🚨 **FILE** incident report with MITRE T1486  

---

## 🚨 **Use Case 4: Proactive Threat Hunting**

### **Scenario:**
You read a threat intelligence report about a new APT campaign targeting your industry. The report lists these IOCs:

```
Campaign: "SolarStorm APT"
Active: 2025-11-01 to present
Target: Financial institutions

IOCs:
- Domain: secure-cloud-update.com
- IP: 198.51.100.45
- IP: 198.51.100.46
- Hash: a1b2c3d4e5f6...
```

### **How SOC Uses Your Tool:**

#### **Step 1: Batch Analysis**
```bash
# Analyze all IOCs
for ioc in "secure-cloud-update.com" "198.51.100.45" "198.51.100.46"; do
  curl -X POST http://localhost:8000/analyze \
    -H "Content-Type: application/json" \
    -d "{\"indicator\":\"$ioc\"}"
done
```

#### **Step 2: Check Your Network**
```bash
# Search firewall logs
grep "secure-cloud-update.com" /var/log/firewall.log
grep "198.51.100.45" /var/log/firewall.log

# Search proxy logs
grep "secure-cloud-update.com" /var/log/proxy.log
```

#### **Step 3: Platform Shows Campaign**
```
Connection Graph:
[secure-cloud-update.com] ──> [198.51.100.45]
                          ──> [198.51.100.46]
                          └── part_of ──> [SolarStorm Campaign]
```

#### **Step 4: PROACTIVE DEFENSE**
✅ **BLOCK** all campaign IOCs preemptively  
✅ **MONITOR** for any historical connections  
✅ **ADD** to watchlist for future detection  
✅ **UPDATE** SIEM rules with new IOCs  
✅ **SHARE** with industry ISACs  

---

## 🚨 **Use Case 5: Data Exfiltration Detection**

### **Scenario:**
Your DLP (Data Loss Prevention) system alerts:
```
[ALERT] Large data transfer detected
Source: Database Server (10.0.5.20)
Destination: 203.0.113.100:8443
Data: 50 GB transferred over 2 hours
Time: 2025-11-05 02:00-04:00 AM (off-hours)
```

### **IOC to Investigate:**
```
IP: 203.0.113.100
```

### **How SOC Uses Your Tool:**

#### **Step 1: IP Analysis**
```
Search: 203.0.113.100
```

#### **Step 2: Platform Shows**
```
┌─────────────────────────────────────────────────────────────┐
│ 🔴 Quick Verdict                        Threat Score: 88   │
│ 203.0.113.100                                               │
│                                                             │
│ [Malicious] [High Severity] [Data Exfiltration] [Conf: 94%]│
│                                                             │
│ IOC Type: Data Exfiltration Server                         │
│ MITRE ATT&CK: T1041 - Exfiltration Over C2 Channel        │
│ Country: Unknown (VPN/Proxy)                               │
│ Associated: APT29 Campaign                                  │
└─────────────────────────────────────────────────────────────┘
```

#### **Step 3: BREACH RESPONSE**
🚨 **ISOLATE** database server immediately  
🚨 **BLOCK** 203.0.113.100 at all firewalls  
🚨 **INVESTIGATE** what data was exfiltrated  
🚨 **CHECK** database server for backdoors  
🚨 **REVIEW** access logs for compromised accounts  
🚨 **ESCALATE** to legal/compliance team  
🚨 **PREPARE** breach notification (if PII/PCI)  
🚨 **DOCUMENT** with MITRE T1041 reference  

---

## 📊 **Use Case 6: Daily SOC Workflow**

### **Morning Routine (8:00 AM):**

#### **Step 1: Review Overnight Alerts**
```bash
# Load all analyzed IOCs from last 24 hours
Click "Load Table" button
Filter: Last 24 hours
Sort by: Threat Score (Highest first)
```

#### **Step 2: Triage**
```
High Priority (Score 70-100):
- 185.220.101.1 → Score: 82 → C2 Server → INVESTIGATE
- 203.0.113.100 → Score: 88 → Data Exfil → INVESTIGATE
- malware.exe → Score: 95 → Ransomware → INVESTIGATE

Medium Priority (Score 40-69):
- sketchy-domain.com → Score: 62 → Phishing → MONITOR

Low Priority (Score 0-39):
- 8.8.8.8 → Score: 5 → Benign → IGNORE
- google.com → Score: 3 → Benign → IGNORE
```

#### **Step 3: Export for Reporting**
```
Click "Export CSV"
→ Send to manager
→ Import to SIEM
→ Share with team
```

---

## 🔄 **Use Case 7: Automated SIEM Integration**

### **Scenario:**
Your SIEM automatically queries your threat intel platform for every new connection.

### **SIEM Integration Script:**
```python
import requests
import json

def check_ioc(indicator, ioc_type):
    """Query threat intel platform"""
    url = "http://localhost:8000/analyze"
    
    payload = {
        "indicator": indicator,
        "indicator_type": ioc_type
    }
    
    response = requests.post(url, json=payload)
    data = response.json()['data']
    
    score = data['scorecard']['composite_score']
    classification = data['scorecard']['classification']
    ioc_type = data['classification']['ioc_type']
    mitre = data['classification']['mitre_technique']
    
    return {
        'score': score,
        'classification': classification,
        'ioc_type': ioc_type,
        'mitre': mitre,
        'verdict': 'BLOCK' if score >= 70 else 'ALERT' if score >= 40 else 'ALLOW'
    }

# Example: Check every outbound connection
connections = [
    ('8.8.8.8', 'ip'),           # Google DNS
    ('185.220.101.1', 'ip'),      # Suspicious IP
    ('google.com', 'domain'),     # Legitimate
    ('evil-phish.com', 'domain')  # Phishing
]

for indicator, ioc_type in connections:
    result = check_ioc(indicator, ioc_type)
    print(f"{indicator}: {result['verdict']} (Score: {result['score']}, {result['classification']})")
```

### **Output:**
```
8.8.8.8: ALLOW (Score: 5, Benign)
185.220.101.1: BLOCK (Score: 82, Malicious)
google.com: ALLOW (Score: 3, Benign)
evil-phish.com: ALERT (Score: 62, Suspicious)
```

---

## 🎓 **Use Case 8: Security Training & Drills**

### **Scenario:**
Training new SOC analysts on threat analysis.

### **Training Exercise:**
```
Instructor: "Analyze these IOCs and determine actions:"

1. phishing-test-2025.com
2. 192.0.2.1
3. suspicious-file-hash.exe

Students use platform to:
✅ Determine threat scores
✅ Identify IOC types
✅ Map to MITRE ATT&CK
✅ Recommend actions
✅ Find related IOCs
```

---

## 📋 **Real-World Workflow Summary**

### **1. Detection Phase:**
```
Firewall Alert → Extract IOC → Analyze in Platform
```

### **2. Investigation Phase:**
```
View Score → Check Classification → Review MITRE Mapping
```

### **3. Decision Phase:**
```
Score 70-100: BLOCK immediately
Score 40-69: INVESTIGATE & MONITOR
Score 0-39: ALLOW (benign)
```

### **4. Response Phase:**
```
Block IOC → Hunt for related IOCs → Document incident
```

### **5. Reporting Phase:**
```
Export data → Create incident report → Share with team
```

---

## 🎯 **IOC Types SOC Teams Analyze Daily**

### **IP Addresses:**
- Outbound firewall connections
- Inbound attack sources
- C2 server communications
- Data exfiltration destinations

### **Domains:**
- Phishing email senders
- Malware download sites
- C2 infrastructure
- Typosquatting domains

### **URLs:**
- Phishing links in emails
- Malware distribution URLs
- Exploit kit landing pages
- Drive-by download sites

### **File Hashes:**
- Malware samples
- Ransomware executables
- Trojan droppers
- Backdoor implants

---

## 📊 **Metrics SOC Tracks**

Using your platform, SOC can measure:
- **Mean Time to Detect (MTTD):** How fast IOCs are identified
- **Mean Time to Respond (MTTR):** How fast threats are blocked
- **True Positive Rate:** Accuracy of threat scoring
- **IOC Coverage:** % of IOCs with threat intel data
- **Threat Trends:** Most common IOC types over time

---

## 🎉 **Your Platform Helps SOC Teams:**

✅ **Faster Triage** - Instant threat scores instead of manual research  
✅ **Better Decisions** - Multi-source intelligence, not single vendor  
✅ **Complete Context** - IOC classification + MITRE mapping  
✅ **Discover Campaigns** - Connection graphs reveal related threats  
✅ **Standardized Reporting** - MITRE ATT&CK framework  
✅ **Automated Integration** - API for SIEM/SOAR platforms  
✅ **Knowledge Base** - Historical IOC database  

---

**Your tool transforms raw IOCs into actionable intelligence!** 🛡️
