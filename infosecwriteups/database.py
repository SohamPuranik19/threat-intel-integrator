import sqlite3
from typing import Dict, List
from passlib.hash import pbkdf2_sha256 as pwd_hasher

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
                category TEXT,
                confidence TEXT,
                severity TEXT,
                source TEXT,
                tags TEXT,
                threat_actor TEXT,
                malware_family TEXT,
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

        # Users table for simple email/password auth
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            )
        ''')
        
        conn.commit()
        conn.close()

        # Ensure any missing columns are added for existing DBs
        # This is a safe migration for local SQLite files created before
        # these fields were introduced.
        self._migrate_add_columns()

    def _migrate_add_columns(self):
        """Add missing columns to threat_indicators table if they don't exist."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(threat_indicators)")
        existing = {row[1] for row in cursor.fetchall()}  # column names

        additions = {
            'category': 'TEXT',
            'confidence': 'TEXT',
            'severity': 'TEXT',
            'source': 'TEXT',
            'tags': 'TEXT',
            'threat_actor': 'TEXT',
            'malware_family': 'TEXT'
        }

        for col, col_type in additions.items():
            if col not in existing:
                try:
                    cursor.execute(f'ALTER TABLE threat_indicators ADD COLUMN {col} {col_type}')
                except Exception:
                    # non-fatal; leave DB as-is if we cannot alter
                    pass

        conn.commit()
        conn.close()
    
    def insert_threat(self, data: Dict):
        """Insert threat intelligence data"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO threat_indicators 
            (indicator, timestamp, threat_score, classification, 
             category, confidence, severity, source, tags, threat_actor, malware_family,
             country, isp, usage_type, abuseipdb_score, 
             virustotal_score, otx_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['indicator'],
            data['timestamp'],
            data['threat_score'],
            data.get('classification'),
            data.get('category'),
            data.get('confidence'),
            data.get('severity'),
            data.get('source'),
            data.get('tags'),
            data.get('threat_actor'),
            data.get('malware_family'),
            data.get('country', 'Unknown'),
            data.get('isp', 'Unknown'),
            data.get('usage_type', 'Unknown'),
            # scores from sources list if present
            (data.get('sources') or [])[0].get('score', 0) if data.get('sources') else 0,
            (data.get('sources') or [None, None])[1].get('score', 0) if len(data.get('sources', [])) > 1 and data.get('sources')[1] else 0,
            (data.get('sources') or [None, None, None])[2].get('score', 0) if len(data.get('sources', [])) > 2 and data.get('sources')[2] else 0
        ))
        
        conn.commit()
        conn.close()
    
    def get_all_threats(self) -> List[Dict]:
        """Retrieve all threat data"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM threat_indicators ORDER BY timestamp DESC')
        rows = cursor.fetchall()
        # capture column names before closing connection
        col_names = [col[0] for col in cursor.description]
        conn.close()

        return [dict(zip(col_names, row)) for row in rows]

    # -------------------- User methods --------------------
    def create_user(self, email: str, password: str) -> Dict:
        """Create a new user with hashed password. Raises sqlite3.IntegrityError if email exists."""
        pw_hash = pwd_hasher.hash(password)
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        try:
            cursor.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', (email, pw_hash))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            # Provide a clearer error to the caller/UI
            raise ValueError('Email already registered')

        cursor.execute('SELECT id, email, created_at FROM users WHERE email = ?', (email,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return {'id': row[0], 'email': row[1], 'created_at': row[2]}
        return {}

    def get_user_by_email(self, email: str) -> Dict:
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('SELECT id, email, password_hash, created_at FROM users WHERE email = ?', (email,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return {}
        return {'id': row[0], 'email': row[1], 'password_hash': row[2], 'created_at': row[3]}

    def verify_user(self, email: str, password: str) -> bool:
        """Verify email/password. Returns True if credentials match."""
        user = self.get_user_by_email(email)
        if not user:
            return False
        try:
            return pwd_hasher.verify(password, user['password_hash'])
        except Exception:
            return False

    def query_threats(self,
                      indicator: str = None,
                      indicator_like: str = None,
                      category: str = None,
                      confidence: str = None,
                      severity: str = None,
                      source: str = None,
                      tags: str = None,
                      threat_actor: str = None,
                      malware_family: str = None,
                      min_score: float = None,
                      max_score: float = None,
                      classification: str = None,
                      start_ts: str = None,
                      end_ts: str = None,
                      country: str = None,
                      isp: str = None,
                      usage_type: str = None,
                      limit: int = 100,
                      offset: int = 0) -> List[Dict]:
        """Query threats with optional filters.

        All timestamp arguments should be strings comparable in the DB's timestamp format
        (this project uses the timestamp format produced by the processor).

        Returns a list of dicts matching the selected fields.
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        where_clauses = []
        params = []

        if indicator:
            # exact (case-sensitive as stored) indicator match
            where_clauses.append('indicator = ?')
            params.append(indicator)
        if indicator_like:
            # case-insensitive partial match on indicator
            where_clauses.append('LOWER(indicator) LIKE ?')
            params.append(f"%{indicator_like.lower()}%")
        if category:
            where_clauses.append('category = ?')
            params.append(category)
        if confidence:
            where_clauses.append('confidence = ?')
            params.append(confidence)
        if severity:
            where_clauses.append('severity = ?')
            params.append(severity)
        if source:
            where_clauses.append('source = ?')
            params.append(source)
        if tags:
            # partial tag match
            where_clauses.append('LOWER(tags) LIKE ?')
            params.append(f"%{tags.lower()}%")
        if threat_actor:
            where_clauses.append('LOWER(threat_actor) LIKE ?')
            params.append(f"%{threat_actor.lower()}%")
        if malware_family:
            where_clauses.append('LOWER(malware_family) LIKE ?')
            params.append(f"%{malware_family.lower()}%")
        if min_score is not None:
            where_clauses.append('threat_score >= ?')
            params.append(min_score)
        if max_score is not None:
            where_clauses.append('threat_score <= ?')
            params.append(max_score)
        if classification:
            where_clauses.append('classification = ?')
            params.append(classification)
        if start_ts:
            where_clauses.append('timestamp >= ?')
            params.append(start_ts)
        if end_ts:
            where_clauses.append('timestamp <= ?')
            params.append(end_ts)
        if country:
            where_clauses.append('country = ?')
            params.append(country)
        if isp:
            where_clauses.append('isp = ?')
            params.append(isp)
        if usage_type:
            where_clauses.append('usage_type = ?')
            params.append(usage_type)

        where_sql = ''
        if where_clauses:
            where_sql = 'WHERE ' + ' AND '.join(where_clauses)

        sql = f'SELECT * FROM threat_indicators {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])

        cursor.execute(sql, tuple(params))
        rows = cursor.fetchall()
        col_names = [col[0] for col in cursor.description]
        conn.close()

        return [dict(zip(col_names, row)) for row in rows]
