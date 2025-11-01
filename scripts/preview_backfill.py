#!/usr/bin/env python3
"""Preview backfill mappings for the first N rows without modifying the DB.
Run from repo root using the project's venv:
.venv/bin/python scripts/preview_backfill.py
"""
import sqlite3
import runpy

# Import the mapping function by running the backfill script as a module
mod = runpy.run_path('scripts/backfill_mappings.py')
map_from_row = mod['map_from_row']

DB = 'threat_intel.db'
N = 10

conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row
cur = conn.cursor()
cur.execute('SELECT * FROM threat_indicators LIMIT ?', (N,))
rows = cur.fetchall()
if not rows:
    print('No rows found in threat_indicators')
    raise SystemExit(0)

print(f'Previewing up to {N} rows (no DB changes)')
print('-' * 80)
for r in rows:
    row = dict(r)
    old_cat = (row.get('category') or 'NULL')
    old_conf = (row.get('confidence') or 'NULL')
    old_sev = (row.get('severity') or 'NULL')
    new_cat, new_conf, new_sev = map_from_row(row)
    print(f"id={row.get('id')} indicator={row.get('indicator')}")
    print(f"  old: category={old_cat} confidence={old_conf} severity={old_sev}")
    print(f"  new: category={new_cat} confidence={new_conf} severity={new_sev}")
    print('-' * 80)

conn.close()
