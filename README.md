# Threat Intel Integrator

This repository contains a small threat intelligence integrator with a Streamlit dashboard at `infosecwriteups/dashboard.py`.

You said you don't want Docker — below are instructions to run locally and to deploy on Streamlit Cloud (hosted Streamlit service).

---

## Run locally (recommended for development)

1. Create and activate a Python virtual environment (optional but recommended):

```bash
python -m venv .venv
source .venv/bin/activate  # macOS / Linux (zsh)
```
 

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the Streamlit dashboard:

```bash
streamlit run infosecwriteups/dashboard.py --server.port 8501 --server.address 127.0.0.1
```

4. Open http://localhost:8501 in your browser.

Notes:
- The app uses the local SQLite DB file `threat_intel.db`. Make sure it exists or run the analysis (`python -m infosecwriteups.main`) to populate sample data.
- The app now uses an absolute import to reliably locate the `ThreatDatabase` class when run in different environments.

### Bulk import email indicators

- Prepare a newline-delimited text file (or CSV) of the email addresses you want to add, for example `email_iocs.txt`.
- Run the helper script to insert them into `threat_intel.db`:

```bash
.venv/bin/python scripts/import_email_iocs.py --input email_iocs.txt
```

- For CSV sources, provide the column name that holds the email address:

```bash
.venv/bin/python scripts/import_email_iocs.py --input phishing.csv --column email_address
```

The script skips duplicates (case-insensitive), assigns sensible phishing defaults (score 70, classification Malicious, category phishing), and exposes flags like `--score`, `--tags`, `--dry-run`, or `--db` if you need to tune the insertion.

---

## Deploy to Streamlit Cloud (hosted)

1. Push this repository to GitHub.
2. Go to https://share.streamlit.io and sign in with your GitHub account.
3. Click "New app" and select the repository and branch.
4. For the "File in the repo to run", enter `infosecwriteups/dashboard.py`.
5. Click "Deploy".

Caveats for Streamlit Cloud:
- Streamlit Cloud runs apps from your repository and does not provide persistent local files. If you need persistent storage for `threat_intel.db`, move to an external DB (Postgres, etc.) or use object storage and import on start.
- Ensure required secrets/API keys are provided through Streamlit Cloud's Secrets manager (for example, `ABUSEIPDB_KEY`, `VIRUSTOTAL_KEY`, `OTX_KEY`) if you want analysis features to call external APIs.

---

## If you want, I can:
- Add a small script to export/import DB contents to a CSV for backup/restore on Streamlit Cloud.
- Add a lightweight `requirements.txt` pinning and `runtime.txt` if Streamlit Cloud needs a specific Python version.
- Add GitHub Actions to run tests and optionally deploy.

Tell me which of the above you want me to do next.

---

## Authentication notes

- The app now supports simple email/password authentication backed by the local SQLite DB (`threat_intel.db`).
- Passwords are hashed using PBKDF2-SHA256 (via passlib) which does not have the 72-byte limit that bcrypt has — you can use arbitrarily long passwords.
- To reset users, delete the database file `threat_intel.db` or remove rows from the `users` table. Example:

```bash
sqlite3 threat_intel.db "DELETE FROM users WHERE email = 'user@example.com';"
```

Or remove the DB entirely (will also remove threat data):

```bash
rm threat_intel.db
```

If you'd like stronger password hashing (e.g., Argon2) or persistent sessions, I can add that next.

---

## Why use this project

- Targets SOC analysts, incident responders, threat researchers and small security teams who need a fast, local way to triage indicators of compromise.
- Consolidates multiple reputation sources into a single, interactive dashboard for easier decision-making.
- Local-first: stores results in a local SQLite DB so you retain full control and auditability of your data.
- Lightweight and extensible: built with Streamlit for fast iteration and easy customization.

If you'd like, I can expand this README with usage examples, screenshots, or add a quick-start checklist for non-developers.
