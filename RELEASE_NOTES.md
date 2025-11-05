# Release v1.0.0

Release date: 2025-11-05

Highlights
- Production-ready threat intelligence platform with multi-source integrations, composite scorecard, IOC classification with MITRE mapping, and connection graph generation.
- Deployment configuration and scripts for Render (backend) and Vercel (frontend) included.
- Added startup scripts and environment handling for robust cloud deployment.

Recent commits (summary)

```
dca752b 2025-11-05 feat: Add Vercel configuration for proper deployment
542f3cb 2025-11-05 fix: Add Vercel domains to CORS
d390f56 2025-11-05 feat: Update frontend with production backend URL
30246d4 2025-11-05 fix: Add Python startup script for Render
8687c30 2025-11-05 fix: Enhanced startup script with debugging
759cd0a 2025-11-05 fix: Explicitly set PYTHONPATH in start command
803b909 2025-11-05 fix: Use startup script for Render deployment
ebc5d74 2025-11-05 fix: Add PYTHONPATH to Render configuration
3aa3a69 2025-11-05 fix: Update Render start command to use python -m uvicorn
15a7a67 2025-11-05 feat: Production-ready threat intelligence platform with deployment configuration
4ab0fae 2025-11-03 Merge pull request #1 from SohamPuranik19/feat/quick-verdict
31fa5fa 2025-11-03 feat: Add frontend components and backend scripts for Threat Intel Integrator
```

Notes & Next Steps
- The test suite reported some missing fields in `/analyze` responses (e.g., `timestamp`, `scorecard`) during verification; please review `infosecwriteups/api_integrations.py` and `infosecwriteups/database_enhanced.py` to ensure the analysis payload includes the expected keys for the frontend and tests. These are likely due to optional sources being disabled and code paths not populating defaults.
- API key enforcement and a simple in-memory rate-limiter were added to the backend; configure `API_KEY`, `RATE_LIMIT_REQUESTS`, and `RATE_LIMIT_WINDOW_SECONDS` in environment for production hardening. Consider replacing the in-memory limiter with a Redis-based solution for multi-instance deployments.
- The repository includes a CI workflow that runs tests and builds the frontend; add secrets and deployment steps as needed.
