# 🚀 Production Deployment Guide

## 📋 **Deployment Overview**

Your platform has 2 components:
1. **Frontend** - Next.js (React) application
2. **Backend** - FastAPI (Python) application

**Recommended Stack:**
- **Frontend:** Vercel (Free tier, optimized for Next.js)
- **Backend:** Render or Railway (Free tier with persistent storage)

---

## 🎯 **Option 1: Vercel (Frontend) + Render (Backend) [RECOMMENDED]**

### **Total Cost:** FREE for both!

### **Why This Stack?**
- ✅ Free tier includes everything you need
- ✅ Automatic HTTPS/SSL certificates
- ✅ Global CDN for fast loading
- ✅ Automatic deployments from GitHub
- ✅ Easy environment variable management
- ✅ Persistent disk for SQLite database

---

## 📦 **Step 1: Prepare Your Code for Deployment**

### **1.1 Update Frontend API URL**

Create a new file for environment-based configuration:

```bash
cd /Users/sohampuranik/Documents/projects/threat-intel-integrator-main/frontend
```

Create `src/config/api.ts`:
```typescript
// API configuration based on environment
export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 
  (process.env.NODE_ENV === 'production' 
    ? 'https://your-backend-url.onrender.com'  // Will update after backend deployment
    : 'http://127.0.0.1:8000');

export const API_ENDPOINTS = {
  analyze: `${API_BASE_URL}/analyze`,
  sources: `${API_BASE_URL}/sources`,
  indicators: `${API_BASE_URL}/indicators`,
  search: `${API_BASE_URL}/search`,
  graph: `${API_BASE_URL}/graph`,
  mitre: `${API_BASE_URL}/mitre/statistics`,
  health: `${API_BASE_URL}/health`,
};
```

### **1.2 Create Production Requirements**

Create `requirements-prod.txt`:
```
fastapi==0.104.1
uvicorn[standard]==0.24.0
requests==2.31.0
python-whois==0.8.0
passlib[bcrypt]==1.7.4
python-jose[cryptography]==3.3.0
python-multipart==0.0.6
pydantic==2.5.0
```

### **1.3 Create Backend Dockerfile (Optional)**

Create `Dockerfile` in root:
```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY infosecwriteups/ ./infosecwriteups/
COPY .env.example .env

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "infosecwriteups.api_server_enhanced:app", "--host", "0.0.0.0", "--port", "8000"]
```

### **1.4 Create .gitignore**

Create `.gitignore`:
```
# Environment files
.env
*.db
*.db-journal

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
ENV/

# Next.js
frontend/.next/
frontend/node_modules/
frontend/out/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
```

---

## 🚀 **Step 2: Deploy Backend to Render**

### **2.1 Push Code to GitHub**

```bash
cd /Users/sohampuranik/Documents/projects/threat-intel-integrator-main

# Initialize git (if not already done)
git init
git add .
git commit -m "feat: Production-ready threat intelligence platform"

# Create GitHub repository and push
# (Do this on GitHub.com first, then:)
git remote add origin https://github.com/YOUR_USERNAME/threat-intel-integrator.git
git branch -M main
git push -u origin main
```

### **2.2 Deploy on Render**

1. **Go to:** https://render.com
2. **Sign up** with GitHub
3. **Click:** "New +" → "Web Service"
4. **Connect:** Your GitHub repository
5. **Configure:**

```yaml
Name: threat-intel-api
Environment: Python 3
Region: Oregon (or closest to you)
Branch: main
Root Directory: (leave blank)

Build Command:
pip install -r requirements.txt

Start Command:
uvicorn infosecwriteups.api_server_enhanced:app --host 0.0.0.0 --port $PORT

Instance Type: Free
```

6. **Environment Variables** (Click "Advanced"):

```
ABUSEIPDB_KEY=your_key_here
VIRUSTOTAL_KEY=your_key_here
OTX_KEY=your_key_here
SHODAN_KEY=your_key_here
URLSCAN_KEY=your_key_here
HYBRID_ANALYSIS_KEY=your_key_here
```

7. **Add Persistent Disk** (for SQLite database):
   - Click "Disks"
   - Add disk: `/opt/render/project/src`
   - Size: 1GB (free tier)

8. **Click:** "Create Web Service"

9. **Wait** for deployment (5-10 minutes)

10. **Copy** your backend URL: `https://threat-intel-api-XXXX.onrender.com`

### **2.3 Test Backend**

```bash
# Test health endpoint
curl https://threat-intel-api-XXXX.onrender.com/health

# Should return:
{"status":"healthy","service":"Advanced Threat Intelligence API"}
```

---

## 🎨 **Step 3: Deploy Frontend to Vercel**

### **3.1 Update API Configuration**

In `frontend/src/components/SearchBar.tsx`, replace hardcoded URLs:

```typescript
// OLD:
const res = await axios.post('http://127.0.0.1:8000/analyze', ...)

// NEW:
import { API_ENDPOINTS } from '../config/api';
const res = await axios.post(API_ENDPOINTS.analyze, ...)
```

Do this for all components (SearchBar, QuickVerdict, DataTable).

### **3.2 Deploy on Vercel**

1. **Go to:** https://vercel.com
2. **Sign up** with GitHub
3. **Click:** "New Project"
4. **Import:** Your GitHub repository
5. **Configure:**

```yaml
Framework Preset: Next.js
Root Directory: frontend
Build Command: npm run build
Output Directory: (leave default)
Install Command: npm install
```

6. **Environment Variables:**

```
NEXT_PUBLIC_API_URL=https://threat-intel-api-XXXX.onrender.com
```

7. **Click:** "Deploy"

8. **Wait** for deployment (2-3 minutes)

9. **Your site is live!** `https://threat-intel-integrator.vercel.app`

### **3.3 Update Backend CORS**

Update `infosecwriteups/api_server_enhanced.py`:

```python
# OLD:
origins = ["http://localhost:3000", "http://127.0.0.1:3000"]

# NEW:
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://threat-intel-integrator.vercel.app",  # Your Vercel URL
    "https://*.vercel.app",  # Allow all Vercel preview URLs
]
```

Commit and push this change - Render will auto-deploy.

---

## 🔒 **Step 4: Security Hardening**

### **4.1 Add Real Authentication**

Update `frontend/src/app/login/page.tsx`:

```typescript
// Replace localStorage demo with real API authentication
async function handleLogin(e: React.FormEvent) {
  e.preventDefault();
  
  try {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    if (response.ok) {
      const data = await response.json();
      localStorage.setItem('token', data.token);
      router.push('/');
    } else {
      setError('Invalid credentials');
    }
  } catch (error) {
    setError('Login failed');
  }
}
```

### **4.2 Add Rate Limiting**

Install in backend:
```bash
pip install slowapi
```

Update `api_server_enhanced.py`:
```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/analyze")
@limiter.limit("10/minute")  # Max 10 requests per minute
async def analyze_indicator(request: Request, ...):
    ...
```

### **4.3 Add API Key Authentication**

Create `.env` variable:
```
API_KEY=your-secret-api-key-here
```

Add middleware:
```python
from fastapi import Header, HTTPException

async def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != os.getenv("API_KEY"):
        raise HTTPException(status_code=403, detail="Invalid API key")
    return x_api_key

# Apply to endpoints
@app.post("/analyze", dependencies=[Depends(verify_api_key)])
```

---

## 📊 **Step 5: Monitoring & Logging**

### **5.1 Set Up Health Checks**

Both Render and Vercel support health checks:

**Render:**
- Health Check Path: `/health`
- Interval: 60 seconds

**Vercel:**
- Automatic monitoring included

### **5.2 Add Application Logging**

Update backend with better logging:

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

@app.post("/analyze")
async def analyze_indicator(...):
    logger.info(f"Analyzing indicator: {indicator_request.indicator}")
    # ... rest of code
```

### **5.3 Set Up Sentry (Optional)**

Free error tracking:

```bash
pip install sentry-sdk
```

```python
import sentry_sdk

sentry_sdk.init(
    dsn="your-sentry-dsn",
    traces_sample_rate=1.0,
)
```

---

## 🌐 **Step 6: Custom Domain (Optional)**

### **6.1 Buy Domain**
- Namecheap, GoDaddy, or Google Domains
- Example: `threatintel.yourdomain.com`

### **6.2 Configure Vercel**
1. Project Settings → Domains
2. Add domain: `threatintel.yourdomain.com`
3. Add DNS records as instructed

### **6.3 Configure Render**
1. Settings → Custom Domains
2. Add: `api.threatintel.yourdomain.com`
3. Update DNS records

---

## ✅ **Step 7: Post-Deployment Checklist**

- [ ] Backend deployed and accessible
- [ ] Frontend deployed and accessible
- [ ] CORS configured correctly
- [ ] Environment variables set
- [ ] API keys added (if available)
- [ ] Health checks working
- [ ] Database persisting data
- [ ] HTTPS enabled (automatic)
- [ ] Error logging configured
- [ ] Rate limiting enabled
- [ ] Authentication working

---

## 🧪 **Step 8: Test Production Deployment**

### **8.1 Test Backend API**

```bash
# Health check
curl https://your-backend.onrender.com/health

# List sources
curl https://your-backend.onrender.com/sources

# Analyze indicator
curl -X POST https://your-backend.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -d '{"indicator":"8.8.8.8","indicator_type":"ip"}'
```

### **8.2 Test Frontend**

1. Visit: `https://your-app.vercel.app`
2. Login with credentials
3. Search: `8.8.8.8`
4. Verify Quick Verdict appears
5. Click "Load Table"
6. Test export CSV

---

## 💰 **Pricing & Limits**

### **Render Free Tier:**
- ✅ 750 hours/month (enough for 1 app 24/7)
- ✅ 512 MB RAM
- ✅ Automatic HTTPS
- ✅ Persistent disk (1GB)
- ⚠️ Spins down after 15 min inactivity (30-60s startup)

### **Vercel Free Tier:**
- ✅ Unlimited deployments
- ✅ 100 GB bandwidth/month
- ✅ Automatic HTTPS
- ✅ Global CDN
- ✅ Preview deployments

### **If You Need More:**
- **Render:** $7/month for always-on
- **Vercel:** $20/month for team features
- **Alternative:** Railway ($5/month credits)

---

## 🚀 **Quick Deploy Commands**

### **One-Time Setup:**

```bash
# 1. Commit code
git add .
git commit -m "Production ready"
git push origin main

# 2. Deploy backend on Render.com
# (Use web UI - 5 minutes)

# 3. Deploy frontend on Vercel.com  
# (Use web UI - 2 minutes)

# 4. Update CORS in backend
# (Git commit + push - auto deploys)
```

### **Future Updates:**

```bash
# Make changes
git add .
git commit -m "Feature: XYZ"
git push origin main

# Both platforms auto-deploy! 🎉
```

---

## 📱 **Alternative Deployment Options**

### **Option 2: Railway (Both Frontend + Backend)**

**Pros:**
- Single platform for both
- PostgreSQL included (upgrade from SQLite)
- $5/month free credits

**Deploy:**
1. Go to: https://railway.app
2. "New Project" → "Deploy from GitHub"
3. Add both services from same repo

### **Option 3: AWS (Advanced)**

**For enterprise production:**
- Frontend: AWS Amplify or S3 + CloudFront
- Backend: ECS/Fargate or Lambda
- Database: RDS PostgreSQL
- Cost: ~$50-200/month

### **Option 4: Docker + DigitalOcean**

**For self-hosted:**
- Docker Compose for both services
- DigitalOcean Droplet ($6/month)
- Requires more setup and maintenance

---

## 🎓 **Post-Deployment Best Practices**

### **1. Get Free API Keys**

Add these to Render environment variables:
- VirusTotal: https://www.virustotal.com/gui/my-apikey
- AbuseIPDB: https://www.abuseipdb.com/api
- AlienVault OTX: https://otx.alienvault.com/api
- Shodan: https://account.shodan.io/
- URLScan: https://urlscan.io/user/profile/
- Hybrid Analysis: https://www.hybrid-analysis.com/apikeys/info

This unlocks all 9 threat intelligence sources!

### **2. Monitor Usage**

- Check Render dashboard for errors
- Monitor Vercel analytics
- Set up alerts for downtime

### **3. Regular Updates**

```bash
# Update dependencies monthly
cd frontend && npm update
cd .. && pip install --upgrade -r requirements.txt

# Commit and push
git commit -am "chore: Update dependencies"
git push
```

### **4. Backup Database**

Download SQLite database from Render disk weekly:
- Render Dashboard → Disk → Download

---

## 🎉 **You're Live!**

After deployment, share:
- **Frontend URL:** `https://threat-intel-integrator.vercel.app`
- **API Docs:** `https://your-backend.onrender.com/docs`
- **GitHub Repo:** `https://github.com/YOUR_USERNAME/threat-intel-integrator`

---

## 📞 **Need Help?**

Common issues:
- **CORS errors:** Update origins in api_server_enhanced.py
- **502 Bad Gateway:** Backend is spinning up (wait 60s)
- **404 errors:** Check API_BASE_URL in frontend
- **Slow first load:** Free tier spins down (upgrade to $7/month)

---

**Ready to deploy? Let's start with Step 1!** 🚀
