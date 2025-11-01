import sys
import pathlib
repo_root = pathlib.Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from infosecwriteups.database import ThreatDatabase

if __name__ == '__main__':
    db = ThreatDatabase()
    email = 'dup@example.local'
    pw = 'password123'

    # cleanup
    import sqlite3
    conn = sqlite3.connect(db.db_name)
    cur = conn.cursor()
    cur.execute('DELETE FROM users WHERE email = ?', (email,))
    conn.commit()
    conn.close()

    try:
        print('Creating first user...')
        print(db.create_user(email, pw))
        print('Creating duplicate user...')
        print(db.create_user(email, pw))
    except Exception as e:
        print('Error caught:', type(e), e)
