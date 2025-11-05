# How to run the Threat Intel Integrator locally

This document covers quick steps to run the backend and frontend locally for development and testing.

Prerequisites

- Python 3.9+ (venv recommended)
- Node.js 18+ and npm
- SQLite (bundled with Python)

Backend

1. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install Python dependencies

```bash
pip install -r requirements.txt
```

3. Create a `.env` file from `.env.example` and add any API keys you want to use (VirusTotal, AbuseIPDB, etc.). Optionally set `API_KEY` to enable API key enforcement for local testing.

4. Run the backend

```bash
uvicorn infosecwriteups.api_server_enhanced:app --reload --port 8000
```

5. Quick checks

```bash
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/analyze -H "Content-Type: application/json" -d '{"indicator":"8.8.8.8","indicator_type":"ip"}'
```

Frontend

1. Install frontend dependencies and run dev server

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
```

2. By default, `frontend` uses `NEXT_PUBLIC_API_URL` environment variable to point at the backend. When running locally, set it to `http://127.0.0.1:8000`.

CI / Tests

Run the Python test suite from the repository root:

```bash
python3 test_api.py
python3 test_advanced_features.py
```

Notes

- If you enable `API_KEY` in `.env`, include the same header `x-api-key: <API_KEY>` in frontend requests (or disable for local dev).
- Rate-limiting is implemented as a simple in-memory limiter and is not suitable for multi-process production. For production, use a distributed rate-limiter (Redis) or a gateway.
