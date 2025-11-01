import sqlite3
from typing import Dict, List

class ThreatDatabase:
    def __init__(self, db_name: str = 'threat_intel.db'):
        self.db_name = db_name
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                threat_score REAL,
                classification TEXT,
                country TEXT,
                isp TEXT,
                usage_type TEXT,
                abuseipdb_score REAL,
                virustotal_score REAL,
                otx_score REAL
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_indicator 
            ON threat_indicators(indicator)
        ''')
        
        conn.commit()
        conn.close()
    
    def insert_threat(self, data: Dict):
        """Insert threat intelligence data"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO threat_indicators 
            (indicator, timestamp, threat_score, classification, 
             country, isp, usage_type, abuseipdb_score, 
             virustotal_score, otx_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['indicator'],
            data['timestamp'],
            data['threat_score'],
            data['classification'],
            data.get('country', 'Unknown'),
            data.get('isp', 'Unknown'),
            data.get('usage_type', 'Unknown'),
            data['sources'][0].get('score', 0),
            data['sources'][1].get('score', 0),
            data['sources'][2].get('score', 0)
        ))
        
        conn.commit()
        conn.close()
    
    def get_all_threats(self) -> List[Dict]:
        """Retrieve all threat data"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM threat_indicators ORDER BY timestamp DESC')
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(zip([col[0] for col in cursor.description], row)) for row in rows]
