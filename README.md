# Threat Intel Integrator

A comprehensive threat intelligence platform with multiple interfaces for analyzing IPs, domains, and other indicators of compromise (IOCs).

## Features

- 🔍 **Multi-source Intelligence**: Integrates with VirusTotal, AbuseIPDB, and AlienVault OTX
- 📊 **Multiple Interfaces**: 
  - Modern React/Next.js frontend
  - Streamlit dashboard for quick analysis
  - FastAPI backend for programmatic access
- 💾 **Local Database**: SQLite-based storage for all threat data
- 🎨 **Beautiful UI**: Modern, responsive design with dark theme
- 🧪 **Tested**: Automated smoke tests included
- 🔐 **Authentication**: Simple email/password auth with PBKDF2-SHA256 hashing

---

## Prerequisites

- Python 3.9+
- Node.js 16+ and npm
- Git

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/SohamPuranik19/threat-intel-integrator.git
cd threat-intel-integrator
```

### 2. Backend Setup (Python)

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Frontend Setup (Node.js)

```bash
# Navigate to frontend directory
cd frontend

# Install Node.js dependencies
npm install

# Return to project root
cd ..
```

### 4. Environment Configuration (Optional)

Create a `.env` file in the project root for API keys:

```bash
# Optional: Add your API keys for enhanced threat intelligence
VIRUSTOTAL_KEY=your_vt_key_here
ABUSEIPDB_KEY=your_abuseipdb_key_here
OTX_KEY=your_otx_key_here
```

*Note: The tool works without API keys using heuristic analysis.*

---

## Running the Application

You have three ways to run the application:

### Option 1: Modern React Frontend (Recommended)

#### Terminal 1 - Start Backend API:
```bash
source .venv/bin/activate
uvicorn infosecwriteups.api_server:app --host 127.0.0.1 --port 8000 --reload
```

#### Terminal 2 - Start Frontend:
```bash
cd frontend
npm run dev
```

Then open: **http://localhost:3000**

---

### Option 2: Streamlit Dashboard

```bash
source .venv/bin/activate
streamlit run infosecwriteups/dashboard.py --server.port 8502
```

Then open: **http://localhost:8502**

---

### Option 3: API Only

```bash
source .venv/bin/activate
uvicorn infosecwriteups.api_server:app --host 127.0.0.1 --port 8000
```

API documentation: **http://127.0.0.1:8000/docs**

---

## Testing

Run automated smoke tests to verify everything is working:

```bash
./tests/smoke_test.sh
```

This tests:
- ✅ Frontend loads correctly
- ✅ Backend API endpoints respond
- ✅ Search functionality works
- ✅ Lookup functionality works
- ✅ CORS is configured properly

---

## Usage Examples

### Using the Web Interface

1. **Search for an indicator**:
   - Enter an IP (e.g., `8.8.8.8`) or domain (e.g., `google.com`)
   - Click "Lookup" to analyze
   - View the quick verdict with threat score and classification

2. **Load all data**:
   - Click "Load Table" to see all stored indicators
   - Browse through the interactive table
   - View charts and statistics

### Using the API

#### Search for indicators:
```bash
curl "http://127.0.0.1:8000/search?q=8.8.8.8&limit=10"
```

#### Lookup a specific indicator:
```bash
curl -X POST "http://127.0.0.1:8000/lookup" \
  -H "Content-Type: application/json" \
  -d '{"indicator":"google.com","analyze":true}'
```

---

## Project Structure

```
threat-intel-integrator/
├── infosecwriteups/
│   ├── api_server.py          # FastAPI backend
│   ├── dashboard.py           # Streamlit UI
│   ├── database.py            # SQLite database handler
│   ├── api_integrations.py   # External API integrations
│   ├── processor.py           # Data processing logic
│   └── config.py              # Configuration
├── frontend/                  # Next.js React frontend
│   ├── src/
│   │   ├── app/              # Next.js app directory
│   │   └── components/       # React components
│   └── package.json
├── tests/
│   └── smoke_test.sh         # Automated tests
├── scripts/
│   └── add_test_data.py      # Add sample data
├── requirements.txt          # Python dependencies
└── threat_intel.db          # SQLite database
```

---

## Development

### Adding Sample Data

```bash
source .venv/bin/activate
python scripts/add_test_data.py
```

### Running in Development Mode

Both the backend (`--reload`) and frontend (`npm run dev`) support hot-reloading for development.

---

## Troubleshooting

### Port Already in Use

If you get port conflicts:

```bash
# Kill process on port 8000 (backend)
lsof -ti:8000 | xargs kill -9

# Kill process on port 3000 (frontend)
lsof -ti:3000 | xargs kill -9
```

### CORS Errors

Make sure the backend is running with CORS middleware enabled (already configured in `api_server.py`).

### Database Issues

If you need to reset the database:

```bash
rm threat_intel.db
python scripts/add_test_data.py  # Add sample data
```

---

---

## API Endpoints

- `GET /search?q={query}&limit={limit}` - Search indicators (query optional)
- `POST /lookup` - Analyze a specific indicator
- `GET /docs` - Interactive API documentation (Swagger UI)

---

## Authentication & User Management

- The Streamlit dashboard supports email/password authentication
- Passwords are hashed using PBKDF2-SHA256 (via passlib)
- To reset users, manage the `users` table in SQLite:

```bash
sqlite3 threat_intel.db "DELETE FROM users WHERE email = 'user@example.com';"
```

---

## Deploy to Streamlit Cloud (hosted)

1. Push this repository to GitHub
2. Go to https://share.streamlit.io and sign in
3. Click "New app" and select the repository
4. Set the main file to `infosecwriteups/dashboard.py`
5. Add API keys through Streamlit Cloud's Secrets manager if needed
6. Click "Deploy"

**Note**: Streamlit Cloud doesn't provide persistent storage for SQLite. For production, consider using PostgreSQL or external object storage.

---

## Why Use This Project

- **For SOC Analysts**: Fast, local triage of indicators of compromise
- **For Incident Responders**: Consolidate multiple reputation sources in one dashboard
- **For Threat Researchers**: Local-first approach with full data control
- **For Small Security Teams**: Lightweight, extensible, and easy to customize

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Run tests: `./tests/smoke_test.sh`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

---

## License

MIT License - see LICENSE file for details

---

## Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**Happy Threat Hunting! 🔍🛡️**

````

---

## Why use this project

- Targets SOC analysts, incident responders, threat researchers and small security teams who need a fast, local way to triage indicators of compromise.
- Consolidates multiple reputation sources into a single, interactive dashboard for easier decision-making.
- Local-first: stores results in a local SQLite DB so you retain full control and auditability of your data.
- Lightweight and extensible: built with Streamlit for fast iteration and easy customization.

If you'd like, I can expand this README with usage examples, screenshots, or add a quick-start checklist for non-developers.
