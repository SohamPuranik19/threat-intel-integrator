import sqlite3
import json
from typing import Dict, List, Optional
from datetime import datetime
from passlib.hash import pbkdf2_sha256 as pwd_hasher

class EnhancedThreatDatabase:
    """
    Enhanced database schema supporting:
    - Multi-source threat intelligence
    - MITRE ATT&CK mappings
    - IOC relationships and connection graphs
    - Comprehensive scoring from multiple sources
    """
    
    def __init__(self, db_name: str = 'threat_intel_enhanced.db'):
        self.db_name = db_name
        self.init_database()
    
    def init_database(self):
        """Initialize enhanced database schema"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Main threat indicators table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL UNIQUE,
                indicator_type TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                
                -- Composite scoring
                composite_score REAL,
                classification TEXT,
                severity TEXT,
                confidence INTEGER,
                
                -- IOC Classification
                ioc_type TEXT,
                ioc_confidence INTEGER,
                
                -- MITRE ATT&CK mapping
                mitre_tactic TEXT,
                mitre_technique TEXT,
                mitre_sub_techniques TEXT,
                
                -- Metadata
                tags TEXT,
                related_malware TEXT,
                country TEXT,
                isp TEXT,
                organization TEXT,
                
                -- Source data (JSON)
                source_results TEXT,
                related_iocs TEXT,
                connection_graph TEXT,
                
                -- Timestamps
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            )
        ''')
        
        # Source-specific scores table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS source_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_id INTEGER NOT NULL,
                source_name TEXT NOT NULL,
                score REAL,
                raw_data TEXT,
                checked_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (indicator_id) REFERENCES threat_indicators(id),
                UNIQUE(indicator_id, source_name)
            )
        ''')
        
        # IOC relationships table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc_relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_indicator_id INTEGER NOT NULL,
                target_indicator TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                confidence INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                FOREIGN KEY (source_indicator_id) REFERENCES threat_indicators(id)
            )
        ''')
        
        # Malware families table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malware_families (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                aliases TEXT,
                description TEXT,
                mitre_techniques TEXT,
                first_seen TEXT,
                last_seen TEXT
            )
        ''')
        
        # Campaign tracking table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                threat_actor TEXT,
                start_date TEXT,
                end_date TEXT,
                mitre_tactics TEXT,
                related_malware TEXT
            )
        ''')
        
        # Campaign-IOC mapping
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaign_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                indicator_id INTEGER NOT NULL,
                role TEXT,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
                FOREIGN KEY (indicator_id) REFERENCES threat_indicators(id),
                UNIQUE(campaign_id, indicator_id)
            )
        ''')
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_indicator ON threat_indicators(indicator)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_indicator_type ON threat_indicators(indicator_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_classification ON threat_indicators(classification)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_type ON threat_indicators(ioc_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_composite_score ON threat_indicators(composite_score)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_scores_indicator ON source_scores(indicator_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_relationships_source ON ioc_relationships(source_indicator_id)')
        
        conn.commit()
        conn.close()
    
    def insert_comprehensive_analysis(self, analysis: Dict) -> int:
        """
        Insert comprehensive analysis result into database
        Returns the indicator_id
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        indicator = analysis['indicator']
        indicator_type = analysis['indicator_type']
        scorecard = analysis['scorecard']
        classification = analysis['classification']
        related_iocs = analysis['related_iocs']
        connection_graph = analysis['connection_graph']
        source_results = analysis['source_results']
        
        # Insert or update main indicator
        cursor.execute('''
            INSERT OR REPLACE INTO threat_indicators 
            (indicator, indicator_type, first_seen, last_seen,
             composite_score, classification, severity, confidence,
             ioc_type, ioc_confidence,
             mitre_tactic, mitre_technique, mitre_sub_techniques,
             tags, related_malware,
             source_results, related_iocs, connection_graph,
             updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            indicator,
            indicator_type,
            analysis['timestamp'],
            analysis['timestamp'],
            scorecard['composite_score'],
            scorecard['classification'],
            scorecard['severity'],
            classification['confidence'],
            classification['ioc_type'],
            classification['confidence'],
            classification['mitre_tactic'],
            classification['mitre_technique'],
            json.dumps(classification['mitre_sub_techniques']),
            json.dumps(classification['tags']),
            json.dumps(classification['related_malware']),
            json.dumps(source_results),
            json.dumps(related_iocs),
            json.dumps(connection_graph),
            datetime.now().isoformat()
        ))
        
        indicator_id = cursor.lastrowid
        
        # Insert source scores
        for source_name, score in scorecard['source_scores'].items():
            cursor.execute('''
                INSERT OR REPLACE INTO source_scores
                (indicator_id, source_name, score, checked_at)
                VALUES (?, ?, ?, ?)
            ''', (indicator_id, source_name, score, datetime.now().isoformat()))
        
        # Insert IOC relationships
        for domain in related_iocs.get('domains', []):
            cursor.execute('''
                INSERT OR IGNORE INTO ioc_relationships
                (source_indicator_id, target_indicator, relationship_type, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
            ''', (indicator_id, domain, 'resolves_to', analysis['timestamp'], analysis['timestamp']))
        
        for ip in related_iocs.get('ips', []):
            cursor.execute('''
                INSERT OR IGNORE INTO ioc_relationships
                (source_indicator_id, target_indicator, relationship_type, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
            ''', (indicator_id, ip, 'connected_to', analysis['timestamp'], analysis['timestamp']))
        
        # Insert malware families
        for malware in related_iocs.get('malware_families', []):
            cursor.execute('''
                INSERT OR IGNORE INTO malware_families
                (name, first_seen, last_seen)
                VALUES (?, ?, ?)
            ''', (malware, analysis['timestamp'], analysis['timestamp']))
        
        conn.commit()
        conn.close()
        
        return indicator_id
    
    def get_indicator_analysis(self, indicator: str) -> Optional[Dict]:
        """Retrieve complete analysis for an indicator"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM threat_indicators WHERE indicator = ?', (indicator,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return None
        
        col_names = [col[0] for col in cursor.description]
        result = dict(zip(col_names, row))
        
        # Parse JSON fields
        result['mitre_sub_techniques'] = json.loads(result.get('mitre_sub_techniques', '[]'))
        result['tags'] = json.loads(result.get('tags', '[]'))
        result['related_malware'] = json.loads(result.get('related_malware', '[]'))
        result['source_results'] = json.loads(result.get('source_results', '[]'))
        result['related_iocs'] = json.loads(result.get('related_iocs', '{}'))
        result['connection_graph'] = json.loads(result.get('connection_graph', '{}'))
        
        # Get source scores
        cursor.execute('SELECT source_name, score FROM source_scores WHERE indicator_id = ?', (result['id'],))
        result['source_scores'] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Get relationships
        cursor.execute('''
            SELECT target_indicator, relationship_type, confidence 
            FROM ioc_relationships 
            WHERE source_indicator_id = ?
        ''', (result['id'],))
        result['relationships'] = [
            {'target': row[0], 'type': row[1], 'confidence': row[2]}
            for row in cursor.fetchall()
        ]
        
        conn.close()
        return result
    
    def get_all_indicators(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Get all indicators with summary information"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, indicator, indicator_type, composite_score, classification,
                   severity, ioc_type, mitre_technique, last_seen, updated_at
            FROM threat_indicators
            ORDER BY updated_at DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        
        rows = cursor.fetchall()
        col_names = [col[0] for col in cursor.description]
        conn.close()
        
        return [dict(zip(col_names, row)) for row in rows]
    
    def search_indicators(self, query: str = "", classification: str = None, 
                         ioc_type: str = None, min_score: float = None) -> List[Dict]:
        """Search indicators with filters"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        where_clauses = []
        params = []
        
        if query:
            where_clauses.append('(indicator LIKE ? OR tags LIKE ?)')
            params.extend([f'%{query}%', f'%{query}%'])
        
        if classification:
            where_clauses.append('classification = ?')
            params.append(classification)
        
        if ioc_type:
            where_clauses.append('ioc_type = ?')
            params.append(ioc_type)
        
        if min_score is not None:
            where_clauses.append('composite_score >= ?')
            params.append(min_score)
        
        where_sql = 'WHERE ' + ' AND '.join(where_clauses) if where_clauses else ''
        
        cursor.execute(f'''
            SELECT id, indicator, indicator_type, composite_score, classification,
                   severity, ioc_type, mitre_technique, last_seen
            FROM threat_indicators
            {where_sql}
            ORDER BY composite_score DESC
            LIMIT 100
        ''', params)
        
        rows = cursor.fetchall()
        col_names = [col[0] for col in cursor.description]
        conn.close()
        
        return [dict(zip(col_names, row)) for row in rows]
    
    def get_connection_graph(self, indicator: str, depth: int = 2) -> Dict:
        """
        Get connection graph for an indicator with specified depth
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Get the main indicator
        cursor.execute('SELECT id, connection_graph FROM threat_indicators WHERE indicator = ?', (indicator,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return {'nodes': [], 'edges': []}
        
        graph = json.loads(row[1]) if row[1] else {'nodes': [], 'edges': []}
        
        conn.close()
        return graph
    
    def get_mitre_statistics(self) -> Dict:
        """Get statistics on MITRE ATT&CK techniques observed"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT mitre_tactic, mitre_technique, COUNT(*) as count
            FROM threat_indicators
            WHERE mitre_technique IS NOT NULL AND mitre_technique != 'Unknown'
            GROUP BY mitre_tactic, mitre_technique
            ORDER BY count DESC
        ''')
        
        stats = []
        for row in cursor.fetchall():
            stats.append({
                'tactic': row[0],
                'technique': row[1],
                'count': row[2]
            })
        
        conn.close()
        return {'mitre_stats': stats}
    
    # User management methods (same as before)
    def create_user(self, email: str, password: str) -> Dict:
        """Create a new user"""
        pw_hash = pwd_hasher.hash(password)
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', (email, pw_hash))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            raise ValueError('Email already registered')
        
        cursor.execute('SELECT id, email, created_at FROM users WHERE email = ?', (email,))
        row = cursor.fetchone()
        conn.close()
        
        return {'id': row[0], 'email': row[1], 'created_at': row[2]} if row else {}
    
    def verify_user(self, email: str, password: str) -> bool:
        """Verify user credentials"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('SELECT password_hash FROM users WHERE email = ?', (email,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return False
        
        try:
            return pwd_hasher.verify(password, row[0])
        except Exception:
            return False
