import sys
import pathlib

# Ensure repo root is on sys.path
repo_root = pathlib.Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from infosecwriteups.database import ThreatDatabase

if __name__ == '__main__':
    db = ThreatDatabase()
    email = 'longpass@example.local'
    long_pw = 'p' * 300  # 300 chars > bcrypt 72-byte limit

    # Try to remove existing user if any
    try:
        # naive cleanup
        import sqlite3
        conn = sqlite3.connect(db.db_name)
        cur = conn.cursor()
        cur.execute('DELETE FROM users WHERE email = ?', (email,))
        conn.commit()
        conn.close()
    except Exception:
        pass

    try:
        user = db.create_user(email, long_pw)
        print('User created:', user)
    except Exception as e:
        print('Create user error:', e)

    ok = db.verify_user(email, long_pw)
    print('Verify returned:', ok)
